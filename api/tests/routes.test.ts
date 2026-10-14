import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import type { Readable } from "node:stream";

import { buildServer, type ServerDeps } from "../src/server.js";
import { ApiConfig } from "../src/config.js";
import { Db } from "../src/db.js";
import { OrchestratorClient } from "../src/orchestrator-client.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { CSRF_COOKIE, SESSION_COOKIE } from "../src/csrf.js";
import { deriveCsrfToken, generateCsrfKey, hashSecret } from "../src/session.js";
import { RunnerCallError } from "../src/runner-adapter-http.js";
import type { RunnerAdapter } from "../src/runner-adapter.js";
import { PoolBinder, syncPool } from "../src/sweep.js";
import { MAX_CREDENTIAL_BYTES } from "../src/credential.js";
import { FakeOrchestrator } from "../mock/fake-orchestrator.js";
import { derive, parseSetCookies } from "./helpers.js";

/**
 * What `capStream` handed back, and whether the route destroyed it.
 *
 * §4.7 makes "capStream created even on the refusal path" load-bearing, and the
 * `.destroy()` is the half that actually stops a transfer — a refusal returns
 * without reading a byte, so nothing else would.
 *
 * `app.inject` cannot observe it: it destroys whatever payload it was handed once
 * the response is written, so `request.body.destroyed` is true whether the route
 * destroyed it or never looked at it, and an assertion on it passes for the wrong
 * reason either way. Wrapping `capStream` records the call the *route* makes, which
 * is the thing under test. `importOriginal` keeps every other export real, and the
 * wrapper returns the unmodified stream, so nothing else in this file sees a
 * difference.
 */
const capRecords: { limit: number; destroyed: boolean }[] = [];

vi.mock("../src/credential.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/credential.js")>();
  return {
    ...actual,
    capStream: (source: Readable, limit?: number) => {
      const stream = actual.capStream(source, limit);
      const record = { limit: limit ?? actual.MAX_CREDENTIAL_BYTES, destroyed: false };
      capRecords.push(record);
      const destroy = stream.destroy.bind(stream);
      stream.destroy = (...args: Parameters<typeof destroy>) => {
        record.destroyed = true;
        return destroy(...args);
      };
      return stream;
    },
  };
});

/**
 * The route surface, exercised over HTTP. Three groups of concern:
 *
 *   - the contract mac renders against (snapshot shape, state unions, cookie
 *     attributes, status codes)
 *   - the authorisation properties: ownership, 409 on a second export, no
 *     enumeration
 *   - that the two half-wired routes refuse rather than pretend
 */

const ALLOWED = "https://app.example.com";
const FOREIGN = "https://evil.test";
const SECRET = "A".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const OTHER_GUID = "00000000-0000-0000-0000-000000000000";
const TTL = 43_200_000;

const config: ApiConfig = {
  allowedOrigins: new Set([ALLOWED]),
  csrfKey: "C".repeat(43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  publicOrigin: "https://one-backend.example.com",
  orchestratorUrl: "http://orchestrator:9100",
  orchestratorSecret: "B".repeat(43),
  orchestratorReplayWindowSeconds: 60,
  logLevel: "info",
  listen: "127.0.0.1:0",
  databasePath: ":memory:",
  sseBufferEvents: 500,
  sseKeepaliveMs: 15_000,
};

let db: Db;
let sse: SseHub;
let limiter: RateLimiter;
let csrfKey: string;

function deps(): ServerDeps {
  return {
    db,
    sse,
    limiter,
    orchestrator: new OrchestratorClient({
      baseUrl: "http://127.0.0.1:1",
      secret: config.orchestratorSecret,
    }),
  };
}

async function newApp(): Promise<FastifyInstance> {
  const app = buildServer(config, deps());
  await app.ready();
  return app;
}

function seed(guid = GUID, opts: { state?: string; runnerId?: string | null; auth?: string } = {}) {
  csrfKey = generateCsrfKey();
  db.createSession({
    guid,
    secretHash: hashSecret(SECRET),
    csrfKey,
    now: Date.now(),
    expiresAt: Date.now() + TTL,
  });
  const runnerId = opts.runnerId === undefined ? "slot-1" : opts.runnerId;
  db.run(
    `UPDATE sessions SET state = ?, runner_id = ?, auth_state = ? WHERE guid = ?`,
    opts.state ?? "authenticated",
    runnerId,
    opts.auth ?? "valid",
    guid,
  );
  // **The pool row is seeded with the session row, not after it (F3).**
  //
  // `sessions.runner_id` is only half a binding; `runners.session_guid` is the
  // other half, and everything downstream reads both. Seeding one without the
  // other produced a state the process cannot be in — a session naming a slot that
  // names nobody — which made #93's release a no-op in every fixture that wanted to
  // test it, and would have left `releaseStaleRunner`'s guarded `releaseRunner`
  // matching nothing while the test still read as a pass.
  //
  // `syncPool` (the harness's own call) registers the row as `idle` with a NULL
  // guid, so this overwrites rather than skips.
  if (runnerId !== null) {
    db.registerRunner(runnerId, `ctr-${runnerId}`, "claimed");
    db.run(`UPDATE runners SET session_guid = ? WHERE id = ?`, guid, runnerId);
  }
}

function cookieHeader(guid = GUID, secret = SECRET): string {
  return `${SESSION_COOKIE}=${guid}:${secret}`;
}

beforeEach(() => {
  db = new Db(":memory:");
  sse = new SseHub();
  limiter = new RateLimiter({ logSalt: "test" });
});

// ---- POST /api/session ----------------------------------------------------

/** A Microsoft account: an email or a username, never a secret, never logged. */
const ACCOUNT = "someone@example.com";

describe("POST /api/session", () => {
  const create = (payload: unknown, headers: Record<string, string> = {}) =>
    newApp().then((app) =>
      app
        .inject({
          method: "POST",
          url: "/api/session",
          headers: { "content-type": "application/json", origin: ALLOWED, ...headers },
          payload: typeof payload === "string" ? payload : JSON.stringify(payload),
        })
        .finally(() => app.close()),
    );

  it("creates a session and returns 201 with the protocol version", async () => {
    const response = await create({ guid: GUID, secret: SECRET });
    expect(response.statusCode).toBe(201);
    expect(response.json().protocol).toBe(3);
    expect(db.getSession(GUID)).toBeDefined();
  });

  // T-C5, asserted on what the server actually sends.
  it("sets the session cookie with the §3.3 attribute set", async () => {
    const response = await create({ guid: GUID, secret: SECRET });
    const cookies = parseSetCookies(response);

    // Exactly one cookie. mac's blocking finding: the CSRF token used to travel in
    // a second, non-HttpOnly cookie — which is invisible to `document.cookie` on
    // the frontend's different host, so every mutating route 403'd on a token no
    // page could read. It is in the response body now.
    expect(cookies).toHaveLength(1);

    const session = cookies[0]!;
    expect(session).toContain("HttpOnly");
    expect(session).toContain("Secure");
    expect(session).toContain("SameSite=None");
    expect(session).toContain("Path=/");
    // The __Host- prefix forbids Domain; its absence is the requirement.
    expect(session).not.toMatch(/domain/i);
    expect(session).toContain("Max-Age=43200");
  });

  it("returns the CSRF token in the body, where the frontend can reach it", async () => {
    const response = await create({ guid: GUID, secret: SECRET });
    const token = response.json().csrfToken;

    expect(typeof token).toBe("string");
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // The key is generated by the server, so the test reads it back from the
    // stored row. What is asserted is that the body carries the *derived* token —
    // not the key itself, which would hand the derivation input to the browser.
    const storedKey = db.getSession(GUID)?.csrf_key;
    expect(token).toBe(derive(storedKey!, GUID));
    expect(token).not.toBe(storedKey);
  });

  it("issues a CSRF token that validates against the session", async () => {
    // The round trip the whole scheme exists for: body out, header in, accepted.
    // Both halves on my side, which is what the blocker proved was necessary —
    // asserting each half in isolation is what let it through review.
    const created = await create({ guid: GUID, secret: SECRET });
    const token = created.json().csrfToken;

    const app = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/notebooks",
        headers: {
          "content-type": "application/json",
          cookie: `${SESSION_COOKIE}=${GUID}:${SECRET}`,
          origin: ALLOWED,
          "x-csrf-token": token,
        },
      });
      // Not 403: the token the server issued is the token it accepts.
      expect(response.statusCode).not.toBe(403);
    } finally {
      await app.close();
    }
  });

  // The secret is stored hashed, so the plaintext in the cookie is the only copy
  // and the server cannot leak it from its own state.
  it("stores only a hash of the secret", async () => {
    await create({ guid: GUID, secret: SECRET });
    const row = db.getSession(GUID);
    expect(row?.secret_hash).toBe(hashSecret(SECRET));
    expect(JSON.stringify(row)).not.toContain(SECRET);
  });

  it("validates the secret length rather than trusting the client", async () => {
    // T9: under the split the secret is generated by Component A, and a
    // compromised frontend could generate a weak one.
    for (const secret of ["", "short", "A".repeat(42), "A".repeat(44)]) {
      const response = await create({ guid: GUID, secret });
      expect(response.statusCode).toBe(400);
    }
  });

  it("validates the guid shape", async () => {
    for (const guid of ["", "nope", GUID.toUpperCase(), `${GUID}/x`]) {
      const response = await create({ guid, secret: SECRET });
      expect(response.statusCode).toBe(400);
    }
  });

  it("rejects an unknown field rather than ignoring it", async () => {
    // A caller sending `runnerId` and getting a 201 would conclude it was set.
    const response = await create({ guid: GUID, secret: SECRET, runnerId: "slot-1" });
    expect(response.statusCode).toBe(400);
  });

  it("rejects a body that is not an object", async () => {
    for (const payload of ["[]", '"str"', "null", "42"]) {
      const response = await create(payload);
      expect(response.statusCode).toBe(400);
    }
  });

  it("rejects a foreign origin with no ACAO", async () => {
    const response = await create({ guid: GUID, secret: SECRET }, { origin: FOREIGN });
    expect(response.statusCode).toBe(403);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  // mac flagged that this route read `request.headers.origin` directly while the
  // hook reads through `header()`. A repeated Origin arrives as `string[]`, so
  // `has(array)` is false — which fails closed, but disagrees with the deliberate
  // repeated-header handling in server.ts. Now routed through the same helper.
  it("refuses a repeated Origin header", async () => {
    const app = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session",
        headers: {
          "content-type": "application/json",
          // No browser sends two, so this is not a browser request — and one of
          // them is foreign, which must not be laundered by picking one.
          origin: [ALLOWED, FOREIGN] as never,
        },
        payload: JSON.stringify({ guid: GUID, secret: SECRET }),
      });
      expect(response.statusCode).toBe(403);
      expect(db.getSession(GUID)).toBeUndefined();
    } finally {
      await app.close();
    }
  });

  it("rate limits to three sessions an hour per address", async () => {
    const app = await newApp();
    try {
      for (let i = 0; i < 3; i++) {
        const guid = `3f2504e0-4f89-11d3-9a0c-00000000000${i}`;
        const response = await app.inject({
          method: "POST",
          url: "/api/session",
          headers: { "content-type": "application/json", origin: ALLOWED },
          payload: JSON.stringify({ guid, secret: SECRET }),
        });
        expect(response.statusCode).toBe(201);
      }
      const fourth = await app.inject({
        method: "POST",
        url: "/api/session",
        headers: { "content-type": "application/json", origin: ALLOWED },
        payload: JSON.stringify({ guid: "3f2504e0-4f89-11d3-9a0c-000000000009", secret: SECRET }),
      });
      expect(fourth.statusCode).toBe(429);
      expect(fourth.headers["retry-after"]).toBeDefined();
    } finally {
      await app.close();
    }
  });

  // A reload into the same session must not destroy a live auth.json.
  it("re-issues cookies for an existing session rather than recreating it", async () => {
    seed();
    const app = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session",
        headers: { "content-type": "application/json", origin: ALLOWED },
        payload: JSON.stringify({ guid: GUID, secret: SECRET }),
      });
      expect(response.statusCode).toBe(200);
      expect(parseSetCookies(response)).toHaveLength(1);
      expect(db.getSession(GUID)?.runner_id).toBe("slot-1");
    } finally {
      await app.close();
    }
  });

  // Otherwise this becomes a session-takeover path by GUID enumeration.
  it("refuses to re-issue cookies when the presented secret does not match", async () => {
    seed();
    const app = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session",
        headers: { "content-type": "application/json", origin: ALLOWED },
        payload: JSON.stringify({ guid: GUID, secret: "B".repeat(43) }),
      });
      expect(response.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });
});

// ---- GET /api/session/status ----------------------------------------------

describe("GET /api/session/status", () => {
  it("returns the full snapshot for a valid session", async () => {
    seed();
    const app = await newApp();
    try {
      const response = await app.inject({
        method: "GET",
        url: "/api/session/status",
        headers: { cookie: cookieHeader(), origin: ALLOWED },
      });
      expect(response.statusCode).toBe(200);

      const body = response.json();
      // Every top-level key present, always. The client never branches on a
      // missing key.
      for (const key of ["protocol", "serverTime", "session", "auth", "notebooks", "export", "artifact"]) {
        expect(body).toHaveProperty(key);
      }
      expect(body.protocol).toBe(3);
      expect(body.serverTime).toMatch(/\.\d{3}Z$/);
    } finally {
      await app.close();
    }
  });

  // The refresh-restore path for the CSRF token. §7.5's flow calls status on
  // mount, so this is where a reloaded tab re-arms its header — the in-memory copy
  // from session creation is gone by then.
  it("returns a fresh CSRF token on every status call", async () => {
    seed();
    const app = await newApp();
    try {
      const first = await app.inject({
        method: "GET",
        url: "/api/session/status",
        headers: { cookie: cookieHeader() },
      });
      const second = await app.inject({
        method: "GET",
        url: "/api/session/status",
        headers: { cookie: cookieHeader() },
      });

      // Derived, so it is stable for a session rather than rotating per call —
      // a rotating token would race a tab that read it a moment earlier.
      expect(first.json().csrfToken).toBe(second.json().csrfToken);
      expect(first.json().csrfToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
      // And the snapshot is still intact alongside it.
      expect(first.json().session.state).toBeDefined();
    } finally {
      await app.close();
    }
  });

  it("issues a token from status that validates on a later mutating request", async () => {
    seed();
    const app = await newApp();
    try {
      const status = await app.inject({
        method: "GET",
        url: "/api/session/status",
        headers: { cookie: cookieHeader() },
      });
      const token = status.json().csrfToken;

      const response = await app.inject({
        method: "POST",
        url: "/api/session/notebooks",
        headers: {
          "content-type": "application/json",
          cookie: cookieHeader(),
          origin: ALLOWED,
          "x-csrf-token": token,
        },
      });
      expect(response.statusCode).not.toBe(403);
    } finally {
      await app.close();
    }
  });

  it("uses null rather than omitting an optional leaf", async () => {
    seed();
    const app = await newApp();
    try {
      const body = (
        await app.inject({
          method: "GET",
          url: "/api/session/status",
          headers: { cookie: cookieHeader() },
        })
      ).json();

      expect(body.export.id).toBeNull();
      expect(body.export.progress).toBeNull();
      expect(body.artifact.downloadUrl).toBeNull();
      expect(body.artifact.fileName).toBeNull();
      // Present as keys, not absent.
      expect(Object.keys(body.export)).toContain("finishedAt");
      expect(Object.keys(body.artifact)).toContain("partial");
    } finally {
      await app.close();
    }
  });

  it("401s an unauthenticated request", async () => {
    const app = await newApp();
    try {
      const response = await app.inject({ method: "GET", url: "/api/session/status" });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({ error: "unauthorised" });
    } finally {
      await app.close();
    }
  });

  it("401s an expired session", async () => {
    seed();
    db.run(`UPDATE sessions SET expires_at = ? WHERE guid = ?`, Date.now() - 1, GUID);
    const app = await newApp();
    try {
      const response = await app.inject({
        method: "GET",
        url: "/api/session/status",
        headers: { cookie: cookieHeader() },
      });
      expect(response.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it("builds a download url from the opaque artifact id only", async () => {
    // PLAN-v3 §5 and invariant 8: no GUID, no notebook name.
    seed(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET notebook = ?, artifact_id = ?, artifact_partial = 1 WHERE guid = ?`,
      "Personal Notebook",
      "A".repeat(43),
      GUID,
    );
    const app = await newApp();
    try {
      const body = (
        await app.inject({
          method: "GET",
          url: "/api/session/status",
          headers: { cookie: cookieHeader() },
        })
      ).json();

      expect(body.artifact.available).toBe(true);
      expect(body.artifact.partial).toBe(true);
      expect(body.artifact.downloadUrl).toBe(
        "https://one-backend.example.com/files/" + "A".repeat(43),
      );
      expect(body.artifact.downloadUrl).not.toContain(GUID);
      expect(body.artifact.downloadUrl).not.toContain("Personal");
      // The name comes from Content-Disposition at download time.
      expect(body.artifact.fileName).toBeNull();
    } finally {
      await app.close();
    }
  });

  it("restores a running export so a refresh can reattach", async () => {
    seed(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({
        state: "running",
        id: "E".repeat(43),
        notebook: "Work",
        progress: { pages: 120, sections: 8, assets: 340 },
        startedAt: Date.now() - 5000,
        finishedAt: null,
      }),
      GUID,
    );
    const app = await newApp();
    try {
      const body = (
        await app.inject({
          method: "GET",
          url: "/api/session/status",
          headers: { cookie: cookieHeader() },
        })
      ).json();

      expect(body.export.state).toBe("running");
      expect(body.export.id).toBe("E".repeat(43));
      expect(body.export.progress).toEqual({ pages: 120, sections: 8, assets: 340 });
      expect(body.export.startedAt).not.toBeNull();
      expect(body.export.finishedAt).toBeNull();
    } finally {
      await app.close();
    }
  });
});

// ---- POST /api/session/credential ----------------------------------------

describe("POST /api/session/credential", () => {
  const post = (headers: Record<string, string>, payload = "hunter2") =>
    newApp().then((app) =>
      app
        .inject({
          method: "POST",
          url: "/api/session/credential",
          headers: {
            "content-type": "text/plain",
            "x-microsoft-account": ACCOUNT,
            cookie: cookieHeader(),
            origin: ALLOWED,
            ...headers,
          },
          payload,
        })
        .finally(() => app.close()),
    );

  it("answers 501 when no runner adapter is wired, before it binds anything", async () => {
    // The unwired state. 501 rather than 409 because the missing thing *is* the
    // wiring, and saying "no runner bound" would point an operator at the pool
    // rather than at the absent adapter.
    //
    // 501 also comes first deliberately: claiming a container and then refusing
    // would leak the expensive thing for nothing.
    seed(GUID, { runnerId: null });
    const response = await post({ "x-csrf-token": derive(csrfKey, GUID) });
    expect(response.statusCode).toBe(501);
    expect(response.json().error).toBe("credential forwarding not wired yet");
  });

  // T-C3, through the real route.
  it("requires the CSRF header", async () => {
    seed();
    const response = await post({});
    expect(response.statusCode).toBe(403);
  });

  // T-C2.
  it("rejects a foreign origin with a valid cookie", async () => {
    seed();
    const response = await post({
      origin: FOREIGN,
      "x-csrf-token": derive(csrfKey, GUID),
    });
    expect(response.statusCode).toBe(403);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("rejects an oversized body before accepting it", async () => {
    seed();
    const response = await post(
      { "x-csrf-token": derive(csrfKey, GUID) },
      "x".repeat(5000),
    );
    expect(response.statusCode).toBe(413);
  });

  it("rejects a multipart body", async () => {
    seed();
    const response = await post({
      "content-type": "multipart/form-data; boundary=x",
      "x-csrf-token": derive(csrfKey, GUID),
    });
    expect(response.statusCode).toBe(415);
  });

  it("never echoes the credential in its response", async () => {
    seed();
    const response = await post({ "x-csrf-token": derive(csrfKey, GUID) });
    expect(response.body).not.toContain("hunter2");
  });

  it("accepts a json content type, because it never parses one", async () => {
    // PLAN-v3 §3.3 layer 3 does not pin a type here. The consequence is that a
    // caller which JSON-encodes is forwarded bytes-for-byte, quotes included —
    // a client bug rather than a server one. This asserts the type is *accepted*:
    // 415 here would mean the route had started caring.
    //
    // Reaches the unwired 501, which is what proves the content-type check ran
    // first and passed rather than short-circuiting.
    seed(GUID, { runnerId: null });
    const response = await post({
      "content-type": "application/json",
      "x-csrf-token": derive(csrfKey, GUID),
    });
    expect(response.statusCode).toBe(501);
    expect(response.json().error).toBe("credential forwarding not wired yet");
  });
});

// ---- the §4.7 auth_state guard -------------------------------------------

describe("POST /api/session/credential refuses a replay", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * A harness with a runner wired, which `deps()` above deliberately does not have.
   *
   * That is the whole reason these tests cannot live in the block above: a status
   * assertion against a 501 proves nothing about whether the password was forwarded
   * before the refusal, because the route never got that far. So the refusals below
   * are asserted on **the three things that must not have happened** —
   * `claimForLogin`, `submitCredential` and `sse.emit` — and each is a spy on the
   * real object rather than on a stand-in, so "not called" is a fact about the
   * production code path and not about a fake that was never wired in.
   *
   * The pool binder is the real `PoolBinder` over a `FakeOrchestrator`, so the
   * claim path is the production one and the spy counts its calls rather than
   * standing in for it.
   */
  function harness() {
    const orchestrator = new FakeOrchestrator({ size: 1 });
    syncPool(db, orchestrator.slotIds());
    const binder = new PoolBinder({ db, orchestrator, sse, now: () => Date.now() });

    const submitCredential = vi.fn().mockResolvedValue(undefined);
    const runner: RunnerAdapter = {
      submitCredential,
      listNotebooks: vi.fn().mockResolvedValue(undefined),
      startExport: vi.fn().mockResolvedValue(undefined),
      publishArtifact: vi.fn().mockResolvedValue(undefined),
      abortExport: vi.fn().mockResolvedValue(undefined),
      answerChallenge: vi.fn().mockResolvedValue(undefined),
    };

    return {
      claimForLogin: vi.spyOn(binder, "claimForLogin"),
      submitCredential,
      emit: vi.spyOn(sse, "emit"),
      deps: { db, sse, limiter, orchestrator, runner, poolBinder: binder } as ServerDeps,
    };
  }

  async function post(deps: ServerDeps) {
    const app = buildServer(config, deps);
    await app.ready();
    try {
      return await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          "x-microsoft-account": ACCOUNT,
          cookie: cookieHeader(),
          origin: ALLOWED,
          "x-csrf-token": derive(csrfKey, GUID),
        },
        payload: "hunter2",
      });
    } finally {
      await app.close();
    }
  }

  it("409s a submit against a session that is already signed in", async () => {
    // The live bug: a second submit 40 seconds after the first restarted the login
    // on a session that was already signed in, and `auth.json` was rotated away for
    // 38 seconds while a concurrent `POST /api/session/notebooks` answered `no_auth`.
    //
    // Seeded with **no** runner, so a route that skipped the guard would claim a
    // container and hand the password over — which is what makes the `claimForLogin`
    // assertion below reachable rather than trivially true.
    seed(GUID, { runnerId: null, auth: "valid" });
    const h = harness();
    const response = await post(h.deps);

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({
      error: expect.any(String),
      retryable: false,
      reason: "already-authenticated",
    });
    // `reason` and not `cause`: `ApiError` reads error/reason/retryable out of this
    // body and drops everything else, so a `cause` here would be invisible to the
    // client — asserted rather than left to a comment.
    expect(response.json()).not.toHaveProperty("cause");

    // Not one of the three things that would mean the password moved.
    expect(h.claimForLogin).not.toHaveBeenCalled();
    expect(h.submitCredential).not.toHaveBeenCalled();
    expect(h.emit).not.toHaveBeenCalled();

    // And no row was written. The refusal is a read.
    expect(db.getSession(GUID)?.auth_state).toBe("valid");
    expect(db.getSession(GUID)?.runner_id).toBeNull();
  });

  it("409s a submit while a sign-in is already in progress, and says retrying cannot help", async () => {
    // A real login takes ~38 seconds; `TTL.loginInProgress` is 15 minutes. So
    // `retryable: false` is not a formality — "try again" would be advice that
    // provably cannot work for 94x the duration of the thing it advises.
    seed(GUID, { runnerId: null, auth: "authenticating" });
    const h = harness();
    const response = await post(h.deps);

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({
      retryable: false,
      reason: "login-in-progress",
    });
    expect(h.claimForLogin).not.toHaveBeenCalled();
    expect(h.submitCredential).not.toHaveBeenCalled();
    expect(h.emit).not.toHaveBeenCalled();
    expect(db.getSession(GUID)?.auth_state).toBe("authenticating");
  });

  // The other half of the guard, and the one a reviewer should read first: a guard
  // that refuses a second submit must not refuse the *first* one. `expired`,
  // `failed` and `none` are all states a real user reaches by signing in again, and
  // all three have to reach the runner.
  it.each(["expired", "failed", "none"] as const)(
    "still forwards a credential when the session is %s",
    async (auth) => {
      seed(GUID, { runnerId: null, auth });
      const h = harness();
      const response = await post(h.deps);

      expect(response.statusCode).toBe(202);
      // All three, and the order they have to happen in: the container is claimed,
      // the login is announced, and only then is the credential handed over.
      expect(h.claimForLogin).toHaveBeenCalledTimes(1);
      expect(h.emit).toHaveBeenCalledWith(GUID, "login-started", {});
      expect(h.submitCredential).toHaveBeenCalledTimes(1);
      expect(h.submitCredential.mock.calls[0]![0]).toMatchObject({
        sessionId: GUID,
        account: ACCOUNT,
      });
    },
  );
});

// ---- the atomic claim on the same route -----------------------------------

describe("POST /api/session/credential claims the login atomically", () => {
  /**
   * The same harness, but kept open across two requests.
   *
   * The race is not between two HTTP parsers — it is between the moment the handler
   * reads the row and the moment it writes it, with an `await` across the
   * orchestrator's ~57 s claim in the middle. So these tests drive one server and
   * post twice without awaiting the first, which is the shape a double-click, two
   * tabs and a retried request all take.
   */
  function harness() {
    const orchestrator = new FakeOrchestrator({ size: 2 });
    syncPool(db, orchestrator.slotIds());
    const binder = new PoolBinder({ db, orchestrator, sse, now: () => Date.now() });

    const submitCredential = vi.fn().mockResolvedValue(undefined);
    const runner: RunnerAdapter = {
      submitCredential,
      listNotebooks: vi.fn().mockResolvedValue(undefined),
      startExport: vi.fn().mockResolvedValue(undefined),
      publishArtifact: vi.fn().mockResolvedValue(undefined),
      abortExport: vi.fn().mockResolvedValue(undefined),
      answerChallenge: vi.fn().mockResolvedValue(undefined),
    };

    return {
      claimForLogin: vi.spyOn(binder, "claimForLogin"),
      submitCredential,
      emit: vi.spyOn(sse, "emit"),
      deps: { db, sse, limiter, orchestrator, runner, poolBinder: binder } as ServerDeps,
    };
  }

  async function submit(deps: ServerDeps, app: FastifyInstance) {
    return app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: {
        "content-type": "text/plain",
        "x-microsoft-account": ACCOUNT,
        cookie: cookieHeader(),
        origin: ALLOWED,
        "x-csrf-token": derive(csrfKey, GUID),
      },
      payload: "hunter2",
    });
  }

  // The live bug, and the one the snapshot guard could never catch: the two
  // requests both read `auth_state = 'none'`, both passed, and both ran
  // `claimForLogin` — two containers for one session, with the second overwriting
  // `sessions.runner_id` and leaking the first with nothing left pointing at it.
  it("forwards the credential once when two submits arrive together", async () => {
    seed(GUID, { runnerId: null, auth: "none" });
    const h = harness();
    const app = buildServer(config, h.deps);
    await app.ready();
    try {
      const [first, second] = await Promise.all([submit(h.deps, app), submit(h.deps, app)]);

      const accepted = [first, second].filter((r) => r.statusCode === 202);
      const refused = [first, second].filter((r) => r.statusCode === 409);
      expect(accepted).toHaveLength(1);
      expect(refused).toHaveLength(1);
      expect(refused[0]!.json()).toMatchObject({ reason: "login-in-progress", retryable: false });

      // One password moved. The whole point of §4.7 — "no retry on the credential
      // route" — is that a second submit cannot restart the login, and this is what
      // a restart looked like: `auth.json` rotated away for 38 s with nothing in it.
      expect(h.submitCredential).toHaveBeenCalledTimes(1);
      // ...and only one container was claimed, which is the resource half.
      expect(h.claimForLogin).toHaveBeenCalledTimes(1);
    } finally {
      await app.close();
    }
  });

  // The compensation. `beginLogin` claims the login before the container is claimed,
  // so a claim that then fails must undo it — otherwise the session answers
  // "still signing in" to every route for the whole of `TTL.loginInProgress`
  // (15 minutes) with no credential ever submitted. Deleting the `cancelLogin` call
  // is the revert this test exists for.
  it.each([
    ["pool-exhausted", 503],
    ["orchestrator-unreachable", 502],
  ] as const)(
    "gives the session back when the runner claim fails with %s",
    async (reason, status) => {
      seed(GUID, { runnerId: null, auth: "none" });
      const h = harness();
      vi.spyOn(h.deps.poolBinder!, "claimForLogin").mockResolvedValue({
        ok: false,
        reason,
      } as never);
      const app = buildServer(config, h.deps);
      await app.ready();
      try {
        const response = await submit(h.deps, app);

        expect(response.statusCode).toBe(status);
        expect(h.submitCredential).not.toHaveBeenCalled();
        // The compensation: back to unsigned, and able to try again at once. `none`
        // rather than the `expired` it started as, which is what the SQL says and is
        // why this is not `markAuthFailed` — nothing failed, nothing was released.
        expect(db.getSession(GUID)?.auth_state).toBe("none");
        expect(db.getSession(GUID)?.state).toBe("created");
      } finally {
        await app.close();
      }
    },
  );

  // ...and it is a compensation, not a second claim. It is guarded on
  // `auth_state = 'authenticating'`, so it cannot roll back a login that succeeded
  // while this request was still claiming its container.
  it("does not roll back a login that completed in the meantime", async () => {
    seed(GUID, { runnerId: null, auth: "none" });
    const h = harness();
    vi.spyOn(h.deps.poolBinder!, "claimForLogin").mockImplementation(async () => {
      // The runner answers `login-success` while the claim is still resolving.
      db.markAuthenticated(GUID, Date.now());
      return { ok: false, reason: "orchestrator-unreachable" } as never;
    });
    const app = buildServer(config, h.deps);
    await app.ready();
    try {
      const response = await submit(h.deps, app);

      expect(response.statusCode).toBe(502);
      expect(db.getSession(GUID)?.auth_state).toBe("valid");
    } finally {
      await app.close();
    }
  });

  // The unwired state still has to reach its 409, not the compensation: nothing was
  // claimed, so there is nothing to give back. A runner adapter *is* wired — the 501
  // sits above `beginLogin` deliberately, so without one this never gets here.
  it("gives the session back when no pool binder is wired", async () => {
    seed(GUID, { runnerId: null, auth: "none" });
    const h = harness();
    const app = buildServer(config, {
      ...h.deps,
      poolBinder: undefined,
    } as ServerDeps);
    await app.ready();
    try {
      const response = await submit(h.deps, app);

      expect(response.statusCode).toBe(409);
      expect(response.json().error).toBe("no runner bound to this session");
      expect(h.submitCredential).not.toHaveBeenCalled();
      expect(db.getSession(GUID)?.auth_state).toBe("none");
    } finally {
      await app.close();
    }
  });

  // **Same refusal, for a session that already has a runner** — which it did not
  // reach before #93. The `poolBinder === undefined` check used to sit inside
  // `if (session.runner_id === null)`, so a bound session walked straight past it
  // and handed its password to a container that nothing in the process can release,
  // keep warm or account for. Moving the check above every use of `poolBinder` is
  // what makes the unwired state answer honestly in both shapes.
  it("refuses a bound session too when no pool binder is wired", async () => {
    seed(GUID, { runnerId: "slot-1", auth: "none" });
    const h = harness();
    const app = buildServer(config, {
      ...h.deps,
      poolBinder: undefined,
    } as ServerDeps);
    await app.ready();
    try {
      const response = await submit(h.deps, app);

      expect(response.statusCode).toBe(409);
      expect(response.json().error).toBe("no runner bound to this session");
      // Not forwarded: there is no pool manager, so there is no container this
      // process could create, account for, or reclaim.
      expect(h.submitCredential).not.toHaveBeenCalled();
      expect(h.claimForLogin).not.toHaveBeenCalled();
      // The compensation still runs. `beginLogin` wrote `authenticating` above, and
      // a session left claiming to be signing in for 15 minutes when no credential
      // was ever submitted is the exact state this route refuses to create.
      expect(db.getSession(GUID)?.auth_state).toBe("none");
      // ...and the binding it arrived with is untouched, because this refusal reads
      // the row rather than writing it.
      expect(db.getSession(GUID)?.runner_id).toBe("slot-1");
    } finally {
      await app.close();
    }
  });

  // F9: §4.7 lists "capStream created even on the refusal path" as load-bearing, and
  // a caller who understates `Content-Length` and sends 4 MB must be cut off at 4 KB
  // *whatever the answer is*. `.destroy()` is what stops the transfer: the handler
  // is returning without reading a byte, so nothing else would.
  //
  // Observable through the stream `capStream` hands back, which is why that module is
  // wrapped rather than asserted through the socket: `app.inject` destroys whatever
  // payload it was handed once the response is written, so `destroyed` on the request
  // body is true either way and cannot tell the two paths apart. The wrapper records
  // the call the *route* makes, which is the thing under test.
  it("destroys the capped body on the no-pool-binder refusal (F9)", async () => {
    seed(GUID, { runnerId: "slot-1", auth: "none" });
    const h = harness();
    capRecords.length = 0;
    const app = buildServer(config, {
      ...h.deps,
      poolBinder: undefined,
    } as ServerDeps);
    await app.ready();
    try {
      const response = await submit(h.deps, app);

      expect(response.statusCode).toBe(409);
      // Created — §4.7's "even on the refusal path" is about creation, not about
      // destroying, and a path that skipped both would pass a status-only assertion.
      expect(capRecords).toHaveLength(1);
      expect(capRecords[0]!.limit).toBe(MAX_CREDENTIAL_BYTES);
      expect(capRecords[0]!.destroyed).toBe(true);
    } finally {
      await app.close();
    }
  });
});

// ---- #93: a login always claims a fresh container ---------------------------

/**
 * Re-login after a failure, which is where the old `if (session.runner_id === null)`
 * skipped the claim entirely.
 *
 * The shape every test here sets up is the same one: a session bound to `slot-1`
 * whose previous login **failed**, plus a fake orchestrator that agrees slot-1 is
 * really bound to it. Both halves matter — the SQLite row without the orchestrator's
 * binding would let the claim hand back the very slot under test, and the
 * orchestrator's binding without the row would leave nothing to release.
 */
describe("POST /api/session/credential claims a fresh container on every login", () => {
  function harness() {
    const orchestrator = new FakeOrchestrator({ size: 2 });
    syncPool(db, orchestrator.slotIds());
    const binder = new PoolBinder({ db, orchestrator, sse, now: () => Date.now() });

    const submitCredential = vi.fn().mockResolvedValue(undefined);
    const runner: RunnerAdapter = {
      submitCredential,
      listNotebooks: vi.fn().mockResolvedValue(undefined),
      startExport: vi.fn().mockResolvedValue(undefined),
      publishArtifact: vi.fn().mockResolvedValue(undefined),
      abortExport: vi.fn().mockResolvedValue(undefined),
      answerChallenge: vi.fn().mockResolvedValue(undefined),
    };

    return {
      orchestrator,
      binder,
      claimForLogin: vi.spyOn(binder, "claimForLogin"),
      releaseStaleRunner: vi.spyOn(binder, "releaseStaleRunner"),
      submitCredential,
      emit: vi.spyOn(sse, "emit"),
      deps: { db, sse, limiter, orchestrator, runner, poolBinder: binder } as ServerDeps,
    };
  }

  /**
   * The container the failed login ran in, recorded on **both** sides.
   *
   * Both, because the binding has two halves and a fixture that seeds one produces
   * a state the process cannot be in. Without the orchestrator's half the claim
   * hands back slot-1 and there is nothing to observe; without SQLite's half there
   * is no row to release and the session's binding is a fiction.
   *
   * Returns the container id, which is the discriminator every assertion below is
   * built on.
   */
  async function occupy(orchestrator: FakeOrchestrator): Promise<string> {
    const claimed = await orchestrator.claim(GUID, new Date(Date.now() + TTL));
    if (!claimed.ok) throw new Error("fixture: the fake pool could not bind slot-1");
    db.run(
      `UPDATE runners SET status = 'active', container_id = ? WHERE id = ?`,
      claimed.value.containerId,
      claimed.value.slotId,
    );
    return claimed.value.containerId;
  }

  const boundRunner = () =>
    db.get<{ runner_id: string }>(`SELECT runner_id FROM sessions WHERE guid = ?`, GUID)?.runner_id;

  const containerOf = (slot: string | null) =>
    slot === null
      ? null
      : db.get<{ container_id: string }>(`SELECT container_id FROM runners WHERE id = ?`, slot)
          ?.container_id;

  async function post(deps: ServerDeps) {
    const app = buildServer(config, deps);
    await app.ready();
    try {
      return await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          "x-microsoft-account": ACCOUNT,
          cookie: cookieHeader(),
          origin: ALLOWED,
          "x-csrf-token": derive(csrfKey, GUID),
        },
        payload: "hunter2",
      });
    } finally {
      await app.close();
    }
  }

  // The whole of #93, in one assertion. Before this, `session.runner_id` was
  // non-null, so `claimForLogin` was skipped: no second container, no slot-budget
  // check, and the password went to the Chromium process whose cookie jar had just
  // been refuted.
  //
  // **`containerId`, not `slotId`, is the discriminator** — deliberately both, even
  // though the named-slot contract alone would separate them. A slot id only says
  // which *position* was drawn; what #93 is about is that the thing answering holds
  // a process nobody has inspected since a rejected password, so the assertion that
  // matters is that the container identity is new. Reverting the claim to reuse the
  // old binding leaves both facts wrong in a way that only one of these catches.
  it("claims a fresh container and releases the one the failed login ran in", async () => {
    const h = harness();
    seed(GUID, { state: "authenticating", auth: "failed", runnerId: "slot-1" });
    const staleContainerId = await occupy(h.orchestrator);

    const response = await post(h.deps);

    expect(response.statusCode).toBe(202);
    // The claim that used to be skipped.
    expect(h.claimForLogin).toHaveBeenCalledTimes(1);
    expect(h.releaseStaleRunner).toHaveBeenCalledWith(GUID, "slot-1");
    expect(h.submitCredential).toHaveBeenCalledTimes(1);

    // A different container, on a different slot, and it is the one now bound.
    const now = boundRunner();
    expect(now).not.toBe("slot-1");
    expect(containerOf(now)).toBeTruthy();
    expect(containerOf(now)).not.toBe(staleContainerId);

    // ...and the stale slot is free on *both* sides. A release that only moved the
    // SQLite row would leave the orchestrator holding the container, which is the
    // §0.9.10 lockout one field over.
    expect(
      db.get<{ status: string; session_guid: string | null }>(
        `SELECT status, session_guid FROM runners WHERE id = 'slot-1'`,
      ),
    ).toEqual({ status: "idle", session_guid: null });
  });

  // **Claim first, release second (F2).** The order is the safety property: release
  // first and a claim that then fails has destroyed a working binding and put
  // nothing back. This drives exactly that sequence — the pool is full, so the claim
  // cannot succeed — and asserts the old container is still there afterwards.
  it("keeps the old container when the fresh claim fails", async () => {
    seed(GUID, { state: "authenticating", auth: "failed", runnerId: "slot-1" });
    const h = harness();
    const staleContainerId = await occupy(h.orchestrator);
    // Fill the other slot with somebody else, on **both** sides, so the draw really
    // is empty. A fake-only binding would be a disagreement this process would
    // repair rather than a pool that is full, and the test would then be asserting
    // the repair's answer rather than the claim's.
    const other = await h.orchestrator.claim(OTHER_GUID, new Date(Date.now() + TTL));
    if (!other.ok) throw new Error("fixture: the fake pool could not fill slot-2");
    db.run(
      `UPDATE runners SET status = 'active', container_id = ?, session_guid = ? WHERE id = ?`,
      other.value.containerId,
      OTHER_GUID,
      other.value.slotId,
    );

    const response = await post(h.deps);

    expect(response.statusCode).toBe(503);
    // Nothing was released on the way to failing.
    expect(h.releaseStaleRunner).not.toHaveBeenCalled();
    expect(h.submitCredential).not.toHaveBeenCalled();
    // The session is left exactly as it was bound: a broken container it can still
    // be retried on, and no slot freed on the orchestrator's side for nothing.
    expect(boundRunner()).toBe("slot-1");
    expect(containerOf("slot-1")).toBe(staleContainerId);
  });

  // The same order, seen from the other side: a release that fails is logged and the
  // login still succeeds. By the time it runs a working container exists and the
  // credential is about to reach it, so refusing here would report a sign-in as
  // failed that has not.
  it("keeps the fresh login when the stale release fails", async () => {
    seed(GUID, { state: "authenticating", auth: "failed", runnerId: "slot-1" });
    const h = harness();
    await occupy(h.orchestrator);
    vi.spyOn(h.orchestrator, "release").mockResolvedValue({
      ok: false,
      error: { kind: "unreachable" },
    } as never);

    const response = await post(h.deps);

    expect(response.statusCode).toBe(202);
    expect(h.submitCredential).toHaveBeenCalledTimes(1);
    // Bound to the new container. The failed release cost a container nothing
    // points at, which the sweeper's orphan branch reclaims — it did not cost the
    // session its runner, and it did not become the user's problem.
    expect(boundRunner()).not.toBe("slot-1");
    expect(containerOf(boundRunner())).toBeTruthy();
  });

  // The §4.7 guard at routes.ts:633, which runs *above* everything in this file's
  // subject. A session that is already signed in must not have its runner replaced
  // however healthy it is — the credential route is not a rebind, and
  // `claimBindingWrite("login")` would write `auth_state = 'authenticating'` over a
  // `valid` account and push a signed-in user back to the sign-in form.
  it("leaves a session that is already signed in completely alone", async () => {
    seed(GUID, { state: "authenticated", auth: "valid", runnerId: "slot-1" });
    const h = harness();
    const liveContainerId = await occupy(h.orchestrator);

    const response = await post(h.deps);

    expect(response.statusCode).toBe(409);
    expect(response.json()).toMatchObject({ reason: "already-authenticated", retryable: false });
    expect(h.claimForLogin).not.toHaveBeenCalled();
    expect(h.releaseStaleRunner).not.toHaveBeenCalled();
    expect(h.submitCredential).not.toHaveBeenCalled();
    expect(boundRunner()).toBe("slot-1");
    expect(containerOf("slot-1")).toBe(liveContainerId);
  });

  // The atomic claim, re-asked for the shape that #93 changed. The existing
  // double-submit test seeds `runnerId: null` — one session, one free slot, the
  // easy case. This is the one that regressed: with a container already bound, a
  // second submit that got past the snapshot guard used to forward the password
  // straight into the first one's login.
  it("forwards the credential once when two submits race on a bound session", async () => {
    seed(GUID, { state: "authenticating", auth: "failed", runnerId: "slot-1" });
    const h = harness();
    await occupy(h.orchestrator);
    const app = buildServer(config, h.deps);
    await app.ready();
    try {
      const submitHere = () =>
        app.inject({
          method: "POST",
          url: "/api/session/credential",
          headers: {
            "content-type": "text/plain",
            "x-microsoft-account": ACCOUNT,
            cookie: cookieHeader(),
            origin: ALLOWED,
            "x-csrf-token": derive(csrfKey, GUID),
          },
          payload: "hunter2",
        });
      const [first, second] = await Promise.all([submitHere(), submitHere()]);

      expect([first, second].filter((r) => r.statusCode === 202)).toHaveLength(1);
      expect([first, second].filter((r) => r.statusCode === 409)).toHaveLength(1);
      expect(h.submitCredential).toHaveBeenCalledTimes(1);
      // One claim, and therefore one release. Two would be two containers created
      // for one session, with the second unreferenced the moment it was made.
      expect(h.claimForLogin).toHaveBeenCalledTimes(1);
      expect(h.releaseStaleRunner).toHaveBeenCalledTimes(1);
    } finally {
      await app.close();
    }
  });

  // A first login has no stale runner, so the release must not run at all. Asserted
  // because "release the runner this session was on" reads fine as a description of
  // something that would happily release a *different* session's slot if it were
  // reached — and the guard for that is the branch, not the callee.
  it("releases nothing on a first login, because there is nothing stale", async () => {
    seed(GUID, { runnerId: null, auth: "none" });
    const h = harness();

    const response = await post(h.deps);

    expect(response.statusCode).toBe(202);
    expect(h.claimForLogin).toHaveBeenCalledTimes(1);
    expect(h.releaseStaleRunner).not.toHaveBeenCalled();
    expect(boundRunner()).not.toBeNull();
  });
});

// ---- POST /api/session/notebooks -----------------------------------------

describe("POST /api/session/notebooks", () => {
  const post = (headers: Record<string, string>, payload?: string) =>
    newApp().then((app) =>
      app
        .inject({
          method: "POST",
          url: "/api/session/notebooks",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader(),
            origin: ALLOWED,
            "x-csrf-token": derive(csrfKey, GUID),
            ...headers,
          },
          ...(payload === undefined ? {} : { payload }),
        })
        .finally(() => app.close()),
    );

  it("requires authentication before listing", async () => {
    seed(GUID, { auth: "none" });
    const response = await post({});
    expect(response.statusCode).toBe(409);
    // Used to assert the single string "not authenticated", which was the same answer
    // for four different states. A session that never signed in now says so, and says
    // it is not retryable — the exhaustive version is in `auth-state-answer.test.ts`.
    expect(response.json().error).toBe("sign in before using a runner");
    expect(response.json().reason).toBe("none");
    expect(response.json().retryable).toBe(false);
  });

  it("requires a bound runner", async () => {
    seed(GUID, { runnerId: null });
    const response = await post({});
    expect(response.statusCode).toBe(409);
  });

  it("accepts an empty body, since the route takes no parameters", async () => {
    seed();
    const response = await post({});
    expect(response.statusCode).toBe(501);
  });

  it("rejects a body with parameters", async () => {
    // A listing route that silently accepted parameters would suggest it honours
    // them.
    seed();
    const response = await post({}, JSON.stringify({ notebook: "Work" }));
    expect(response.statusCode).toBe(400);
  });
});

// ---- POST /api/session/challenge/answer ----------------------------------

/**
 * Answering a typed MFA code.
 *
 * The route exists because `@msout/microsoft-webauth` reads `process.stdin` for a
 * code, which a container does not have: a `challenge` of kind `code` used to hang
 * for 120 seconds and then be reported as "sign-in failed" by this component, for an
 * account whose credentials were perfectly good.
 *
 * The three refusals below are the ones that must happen **before** anything is
 * forwarded — an unauthenticated caller must not be able to resolve somebody else's
 * pending prompt, and a blank code must not burn the user's one chance to answer.
 */
describe("POST /api/session/challenge/answer", () => {
  const answerChallenge = vi.fn().mockResolvedValue(undefined);

  function harness() {
    answerChallenge.mockClear();
    const runner: RunnerAdapter = {
      submitCredential: vi.fn().mockResolvedValue(undefined),
      listNotebooks: vi.fn().mockResolvedValue(undefined),
      startExport: vi.fn().mockResolvedValue(undefined),
      publishArtifact: vi.fn().mockResolvedValue(undefined),
      abortExport: vi.fn().mockResolvedValue(undefined),
      answerChallenge,
    };
    return { emit: vi.spyOn(sse, "emit"), deps: { db, sse, limiter, runner } as ServerDeps };
  }

  async function post(
    deps: ServerDeps,
    body: unknown,
    headers: Record<string, string> = {},
  ) {
    const app = buildServer(config, deps);
    await app.ready();
    try {
      return await app.inject({
        method: "POST",
        url: "/api/session/challenge/answer",
        headers: {
          "content-type": "application/json",
          cookie: cookieHeader(),
          origin: ALLOWED,
          "x-csrf-token": derive(csrfKey, GUID),
          ...headers,
        },
        payload: JSON.stringify(body),
      });
    } finally {
      await app.close();
    }
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("403s without a CSRF token, and forwards nothing", async () => {
    // The structural layer (§3.3). A cross-origin page that could post a code here
    // could resolve a pending prompt for a session it does not hold — so the refusal
    // has to be the hook's, before the handler runs at all.
    seed(GUID, { auth: "authenticating" });
    const h = harness();
    const response = await post(h.deps, { code: "123456" }, { "x-csrf-token": "" });

    expect(response.statusCode).toBe(403);
    expect(answerChallenge).not.toHaveBeenCalled();
  });

  it("403s from a foreign origin", async () => {
    // Origin is the other half of the same layer, and it is checked in the same hook.
    seed(GUID, { auth: "authenticating" });
    const h = harness();
    const response = await post(h.deps, { code: "123456" }, { origin: FOREIGN });

    expect(response.statusCode).toBe(403);
    expect(answerChallenge).not.toHaveBeenCalled();
  });

  it("400s an empty code, and forwards nothing", async () => {
    // A blank would resolve the package's pending prompt with nothing: the user's one
    // chance to answer, spent on a typo, turning into a login failure.
    seed(GUID, { auth: "authenticating" });
    const h = harness();
    for (const code of ["", "   ", undefined, 42, null]) {
      const response = await post(h.deps, { code });
      expect(response.statusCode, JSON.stringify({ code })).toBe(400);
    }
    expect(answerChallenge).not.toHaveBeenCalled();
  });

  it("400s a code longer than 32 characters, and forwards nothing", async () => {
    // The same bound the runner applies, so a body this route calls valid is not
    // refused there. The boundary is the assertion: 32 is accepted, 33 is not.
    seed(GUID, { auth: "authenticating" });
    const h = harness();

    expect((await post(h.deps, { code: "1".repeat(33) })).statusCode).toBe(400);
    expect(answerChallenge).not.toHaveBeenCalled();

    expect((await post(h.deps, { code: "1".repeat(32) })).statusCode).toBe(202);
    expect(answerChallenge).toHaveBeenCalledTimes(1);
  });

  it("202s a valid code, forwards it unchanged, and says so on the stream", async () => {
    seed(GUID, { auth: "authenticating" });
    const h = harness();
    const response = await post(h.deps, { code: "123456" });

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ accepted: true });

    // The far side is the assertion. A route that validated the body and returned 202
    // without calling the adapter would pass every status assertion above.
    expect(answerChallenge).toHaveBeenCalledTimes(1);
    expect(answerChallenge).toHaveBeenCalledWith(GUID, "123456");

    // Exactly one `challenge-seen`: a second tab reads it and stops showing an input
    // for a prompt that is already answered.
    const seen = h.emit.mock.calls.filter(([, type]) => type === "challenge-seen");
    expect(seen).toHaveLength(1);
    expect(seen[0]![0]).toBe(GUID);
  });

  it("forwards the code exactly as typed rather than trimming it", async () => {
    // Same rule as the credential: a transformation applied here is a value the user
    // cannot inspect again once it has been handed over.
    seed(GUID, { auth: "authenticating" });
    const h = harness();
    const response = await post(h.deps, { code: " 123456 " });

    expect(response.statusCode).toBe(202);
    expect(answerChallenge).toHaveBeenCalledWith(GUID, " 123456 ");
  });

  it("answers for a session that is still authenticating, because that is the only time a challenge exists", async () => {
    // **No `requireAuthenticated` here, and this is the test that says why.** Every
    // other runner route refuses a session that is not `valid`, and a challenge only
    // exists while the session is `authenticating` — so that guard would refuse every
    // request the route exists to make.
    seed(GUID, { auth: "authenticating" });
    const h = harness();
    const response = await post(h.deps, { code: "123456" });

    expect(response.statusCode).toBe(202);
  });

  it("401s without a session cookie", async () => {
    // The refusal is the hook's, not the handler's: `onRequest` answers before a
    // route runs, which is why the handler's own `session === null` guard cannot be
    // reached from a test at all. That is the property — one place decides, every
    // route inherits it — and this asserts the outcome rather than the line.
    seed(GUID, { auth: "authenticating" });
    const h = harness();
    const response = await post(h.deps, { code: "123456" }, { cookie: "" });

    expect(response.statusCode).toBe(401);
    expect(answerChallenge).not.toHaveBeenCalled();
  });

  it("rejects a body with unknown fields", async () => {
    // A caller that sent `email` and got a 202 would reasonably conclude it was set.
    seed(GUID, { auth: "authenticating" });
    const h = harness();
    const response = await post(h.deps, { code: "123456", email: "someone@example.com" });

    expect(response.statusCode).toBe(400);
    expect(answerChallenge).not.toHaveBeenCalled();
  });

  it("reports a runner that could not be reached, rather than a wrong code", async () => {
    // The failure this route can name honestly. A 409 from the runner means no prompt
    // is pending — the challenge expired, or it was a push approval needing no code —
    // and that is a different thing to tell a user than "sign-in failed".
    seed(GUID, { auth: "authenticating" });
    const h = harness();
    answerChallenge.mockRejectedValueOnce(
      new RunnerCallError(
        { kind: "not-ready", reason: "conflict" },
        "the runner refused the request: no challenge is waiting for a code",
      ),
    );
    const response = await post(h.deps, { code: "123456" });

    expect(response.statusCode).toBe(409);
    expect(response.json().reason).toBe("not-ready:conflict");
    // Nothing was answered, so nothing is announced.
    expect(h.emit.mock.calls.filter(([, type]) => type === "challenge-seen")).toHaveLength(0);
  });

  it("501s when no runner is wired, which is the unwired state", async () => {
    seed(GUID, { auth: "authenticating" });
    const app = buildServer(config, deps());
    await app.ready();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/challenge/answer",
        headers: {
          "content-type": "application/json",
          cookie: cookieHeader(),
          origin: ALLOWED,
          "x-csrf-token": derive(csrfKey, GUID),
        },
        payload: JSON.stringify({ code: "123456" }),
      });
      expect(response.statusCode).toBe(501);
    } finally {
      await app.close();
    }
  });
});

// ---- POST /api/export -----------------------------------------------------

describe("POST /api/export", () => {
  const post = (payload: unknown, extra: Record<string, string> = {}) =>
    newApp().then((app) =>
      app
        .inject({
          method: "POST",
          url: "/api/export",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader(),
            origin: ALLOWED,
            "x-csrf-token": derive(csrfKey, GUID),
            ...extra,
          },
          payload: JSON.stringify(payload),
        })
        .finally(() => app.close()),
    );

  it("requires a notebook", async () => {
    seed();
    for (const payload of [{}, { notebook: "" }, { notebook: 42 }]) {
      const response = await post(payload);
      expect(response.statusCode).toBe(400);
    }
  });

  it("requires an authenticated session", async () => {
    seed(GUID, { auth: "none" });
    const response = await post({ notebook: "Work" });
    expect(response.statusCode).toBe(409);
  });

  // §8.1: one active export per session, driven from stored state so a second
  // tab cannot lie its way into a second export.
  it("409s a second concurrent export", async () => {
    seed(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({ state: "running", id: "E".repeat(43) }),
      GUID,
    );
    const response = await post({ notebook: "Work" });
    expect(response.statusCode).toBe(409);
    expect(response.json().error).toBe("an export is already running");
  });

  it("allows a second export once the first finished", async () => {
    seed(GUID, { state: "authenticated" });
    db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({ state: "done", id: "E".repeat(43) }),
      GUID,
    );
    const response = await post({ notebook: "Work" });
    expect(response.statusCode).not.toBe(409);
  });

  it("rejects an unknown field", async () => {
    seed();
    const response = await post({ notebook: "Work", image: "evil" });
    expect(response.statusCode).toBe(400);
  });

  it("does not consume a global slot when it refuses", async () => {
    // A failed start must not leak a slot, or enough refusals would exhaust the
    // global cap without a single export running.
    seed(GUID, { runnerId: null });
    const app = await newApp();
    try {
      for (let i = 0; i < 10; i++) {
        await app.inject({
          method: "POST",
          url: "/api/export",
          headers: {
            "content-type": "application/json",
            cookie: cookieHeader(),
            origin: ALLOWED,
            "x-csrf-token": derive(csrfKey, GUID),
          },
          payload: JSON.stringify({ notebook: "Work" }),
        });
      }
      expect(limiter.activeExports).toBe(0);
    } finally {
      await app.close();
    }
  });

  // ---- §8.1's per-session half, under concurrency --------------------------
  //
  // The guard used to be a read of `session.export_state` off the request's
  // snapshot followed, two awaits later, by an **unconditional** UPDATE. Six
  // requests in flight therefore all read "no export", all passed, and all queued
  // one — and the row ended up holding the *last* writer's id, so the export the
  // user was told about in `export-queued` was not the one that ran.
  //
  // Everything here runs against a real server and the real `Db`, because the race
  // is between two statements in a database and a stubbed `db` would be asserting
  // the stub. `Promise.all` over one `app.inject` is enough: Fastify starts each
  // handler on the microtask queue, so they interleave where two concurrent
  // requests would.
  async function exportHarness() {
    const orchestrator = new FakeOrchestrator({ size: 1 });
    syncPool(db, orchestrator.slotIds());
    const poolBinder = new PoolBinder({ db, orchestrator, sse, now: () => Date.now() });
    const startExport = vi.fn().mockResolvedValue(undefined);
    const runner: RunnerAdapter = {
      submitCredential: vi.fn().mockResolvedValue(undefined),
      listNotebooks: vi.fn().mockResolvedValue(undefined),
      startExport,
      publishArtifact: vi.fn().mockResolvedValue(undefined),
      abortExport: vi.fn().mockResolvedValue(undefined),
      answerChallenge: vi.fn().mockResolvedValue(undefined),
    };
    const app = buildServer(config, {
      db,
      sse,
      limiter,
      orchestrator,
      runner,
      poolBinder,
    } as ServerDeps);
    await app.ready();
    return { app, startExport };
  }

  const exportHeaders = () => ({
    "content-type": "application/json",
    cookie: cookieHeader(),
    origin: ALLOWED,
    "x-csrf-token": derive(csrfKey, GUID),
  });

  it("lets exactly one of six simultaneous exports through", async () => {
    seed(GUID, { state: "authenticated", runnerId: "slot-1" });
    const { app, startExport } = await exportHarness();
    try {
      const responses = await Promise.all(
        [1, 2, 3, 4, 5, 6].map((n) =>
          app.inject({
            method: "POST",
            url: "/api/export",
            headers: exportHeaders(),
            payload: JSON.stringify({ notebook: `Notebook ${n}` }),
          }),
        ),
      );

      const accepted = responses.filter((r) => r.statusCode === 202);
      const refused = responses.filter((r) => r.statusCode === 409);
      expect(accepted).toHaveLength(1);
      expect(refused).toHaveLength(5);
      for (const r of refused) {
        expect(r.json().error).toBe("an export is already running");
      }

      // ...and only the winner reached the runner. Five runners told to walk the
      // same vault is the resource half of the bug; a refusal that still started a
      // walk is worse than no fix at all.
      expect(startExport).toHaveBeenCalledTimes(1);

      // The row holds the **winner's** id and notebook, not a loser's. Before the fix
      // this was whichever request happened to write last, which is what makes the
      // rest invisible: five exports queued, and the one the user was told about in
      // `export-queued` was not the one that ran.
      const winner = [1, 2, 3, 4, 5, 6][responses.indexOf(accepted[0]!)];
      const stored = JSON.parse(db.getSession(GUID)?.export_state ?? "{}");
      expect(stored.id).toBe(accepted[0]!.json().id);
      expect(stored.notebook).toBe(`Notebook ${winner}`);
    } finally {
      await app.close();
    }
  });

  // A refusal must be a **refusal**: nothing queued, nothing announced. Five
  // `export-queued` frames for five exports that will never run is what a second
  // tab sees, and it is why the old version was survivable only by accident.
  it("emits export-queued only for the export it actually started", async () => {
    seed(GUID, { state: "authenticated", runnerId: "slot-1" });
    const emit = vi.spyOn(sse, "emit");
    const { app } = await exportHarness();
    try {
      await Promise.all(
        [1, 2, 3].map(() =>
          app.inject({
            method: "POST",
            url: "/api/export",
            headers: exportHeaders(),
            payload: JSON.stringify({ notebook: "Work" }),
          }),
        ),
      );
      expect(emit.mock.calls.filter((call) => call[1] === "export-queued")).toHaveLength(1);
    } finally {
      await app.close();
      emit.mockRestore();
    }
  });

  // §8.1's global cap is six, so five refused claims that leaked their slot would
  // cost five of the six. `release()` on the refusal path is what prevents it, and
  // the leak is invisible until the 429s start.
  it("does not leak a global slot for any export the §8.1 claim refused", async () => {
    seed(GUID, { state: "authenticated", runnerId: "slot-1" });
    const { app } = await exportHarness();
    try {
      await Promise.all(
        [1, 2, 3, 4, 5, 6].map(() =>
          app.inject({
            method: "POST",
            url: "/api/export",
            headers: exportHeaders(),
            payload: JSON.stringify({ notebook: "Work" }),
          }),
        ),
      );
      expect(limiter.activeExports).toBe(0);
    } finally {
      await app.close();
    }
  });

  // The claim must not throw on a corrupt column: a throw is a 500, the column
  // survives it, and the session would be refused every export for the life of the
  // row — the opposite of the read-then-check's `catch`, which treated garbage as
  // "no export".
  it("still starts an export when export_state is corrupt", async () => {
    seed(GUID, { state: "authenticated", runnerId: "slot-1" });
    db.run(`UPDATE sessions SET export_state = ? WHERE guid = ?`, "{not json", GUID);
    const { app, startExport } = await exportHarness();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/export",
        headers: exportHeaders(),
        payload: JSON.stringify({ notebook: "Work" }),
      });
      expect(response.statusCode).toBe(202);
      expect(startExport).toHaveBeenCalledTimes(1);
    } finally {
      await app.close();
    }
  });
});

// ---- POST /api/export/:id/abort ------------------------------------------

describe("POST /api/export/:id/abort", () => {
  const EXPORT_ID = "E".repeat(43);
  const abort = (id: string, cookie = cookieHeader()) =>
    newApp().then((app) =>
      app
        .inject({
          method: "POST",
          url: `/api/export/${id}/abort`,
          headers: { cookie, origin: ALLOWED, "x-csrf-token": derive(csrfKey, GUID) },
        })
        .finally(() => app.close()),
    );

  it("rejects a malformed export id", async () => {
    seed(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({ state: "running", id: EXPORT_ID }),
      GUID,
    );
    for (const id of ["short", "x".repeat(44), "../../etc"]) {
      const response = await abort(encodeURIComponent(id));
      expect([400, 404]).toContain(response.statusCode);
    }
  });

  // Shape is not authorisation: one session must not be able to abort another's
  // export, however it learned the id.
  it("404s an id this session does not own", async () => {
    seed(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({ state: "running", id: "A".repeat(43) }),
      GUID,
    );
    const response = await abort(EXPORT_ID);
    expect(response.statusCode).toBe(404);
  });

  it("404s when there is no export at all", async () => {
    seed();
    const response = await abort(EXPORT_ID);
    expect(response.statusCode).toBe(404);
  });

  it("marks the export partial, because abort preserves what is on disk", async () => {
    seed(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({ state: "running", id: EXPORT_ID }),
      GUID,
    );
    const app = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: `/api/export/${EXPORT_ID}/abort`,
        headers: { cookie: cookieHeader(), origin: ALLOWED, "x-csrf-token": derive(csrfKey, GUID) },
      });
      expect(response.statusCode).toBe(501);

      // The state change is recorded so a refresh shows "partial" rather than an
      // export that will never finish.
      const stored = JSON.parse(db.getSession(GUID)!.export_state ?? "{}");
      expect(stored.state).toBe("partial");
    } finally {
      await app.close();
    }
  });

  it("emits export-aborted and export-partial", async () => {
    seed(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({ state: "running", id: EXPORT_ID }),
      GUID,
    );
    const app = await newApp();
    try {
      await app.inject({
        method: "POST",
        url: `/api/export/${EXPORT_ID}/abort`,
        headers: { cookie: cookieHeader(), origin: ALLOWED, "x-csrf-token": derive(csrfKey, GUID) },
      });
      // Two events, so a second tab sees the abort without polling.
      expect(sse.stats()[GUID]).toBeUndefined();
    } finally {
      await app.close();
    }
  });
});

// ---- Health and the artifact route ---------------------------------------

describe("misc routes", () => {
  it("serves /healthz without a session", async () => {
    const app = await newApp();
    try {
      const response = await app.inject({ method: "GET", url: "/healthz" });
      expect(response.statusCode).toBe(200);
      expect(response.json().ok).toBe(true);
    } finally {
      await app.close();
    }
  });

  // Artifacts are served by Caddy with forward_auth, so a multi-gigabyte vault
  // never passes through Node.
  it("refuses to serve artifacts itself", async () => {
    seed();
    const app = await newApp();
    try {
      const response = await app.inject({
        method: "GET",
        url: `/files/${"A".repeat(43)}`,
        headers: { cookie: cookieHeader() },
      });
      expect(response.statusCode).toBe(501);
      expect(response.json().error).toContain("Caddy");
    } finally {
      await app.close();
    }
  });

  // Authentication runs before routing, so an unauthenticated request to a path
  // that does not exist gets 401 rather than 404. That is the correct order: a
  // 404 would tell a caller which paths exist before it had proved anything.
  // An authenticated caller does get the real answer.
  // mac's finding: `request.url` carries the query string, so a
  // `Set.has(request.url)` test fails for `/api/public/version?cb=123`. He
  // probed fastify directly rather than trusting the docs, and he was right.
  //
  // The version handshake is the important case — it is the first thing a client
  // calls, and a cache-buster on it is the single most likely query in the app.
  it("serves the version handshake with a query string", async () => {
    const app = await newApp();
    try {
      for (const url of [
        "/api/public/version?cb=123",
        "/api/public/version?cb=123&ts=456",
        "/healthz?probe=1",
      ]) {
        const response = await app.inject({ method: "GET", url });
        expect(response.statusCode).toBe(200);
      }
    } finally {
      await app.close();
    }
  });

  it("creates a session with a query string on the url", async () => {
    // MINT_PATHS is matched the same way, so the same bug would 401 the one route
    // that mints a credential.
    const app = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session?client=v1",
        headers: { "content-type": "application/json", origin: ALLOWED },
        payload: JSON.stringify({ guid: GUID, secret: SECRET }),
      });
      expect(response.statusCode).toBe(201);
    } finally {
      await app.close();
    }
  });

  // The credential route's framing checks live in onRequest, keyed on the same
  // path set. With a query string they were being skipped entirely.
  it("still applies the credential framing checks with a query string", async () => {
    seed();
    const app = await newApp();
    try {
      const oversized = await app.inject({
        method: "POST",
        url: "/api/session/credential?x=1",
        headers: {
          "content-type": "text/plain",
          "x-microsoft-account": ACCOUNT,
          cookie: cookieHeader(),
          origin: ALLOWED,
          "x-csrf-token": derive(csrfKey, GUID),
        },
        payload: "x".repeat(5000),
      });
      expect(oversized.statusCode).toBe(413);

      const multipart = await app.inject({
        method: "POST",
        url: "/api/session/credential?x=1",
        headers: {
          "content-type": "multipart/form-data; boundary=x",
          cookie: cookieHeader(),
          origin: ALLOWED,
          "x-csrf-token": derive(csrfKey, GUID),
          "content-length": "11",
        },
        payload: "hunter2",
      });
      expect(multipart.statusCode).toBe(415);
    } finally {
      await app.close();
    }
  });

  it("404s an unknown path for an authenticated caller", async () => {
    seed();
    const app = await newApp();
    try {
      const response = await app.inject({
        method: "GET",
        url: "/api/nope",
        headers: { cookie: cookieHeader() },
      });
      expect(response.statusCode).toBe(404);
    } finally {
      await app.close();
    }
  });

  it("401s an unknown path for an anonymous caller, revealing nothing", async () => {
    const app = await newApp();
    try {
      const anonymous = await app.inject({ method: "GET", url: "/api/nope" });
      expect(anonymous.statusCode).toBe(401);

      // Same status as a real-but-unauthenticated path, so the two are
      // indistinguishable.
      const real = await app.inject({ method: "GET", url: "/api/session/status" });
      expect(real.statusCode).toBe(anonymous.statusCode);
      expect(real.body).toBe(anonymous.body);
    } finally {
      await app.close();
    }
  });
});