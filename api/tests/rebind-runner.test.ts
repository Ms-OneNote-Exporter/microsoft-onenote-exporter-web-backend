/**
 * Re-binding a runner to a session that has none.
 *
 * ## The lockout this closes
 *
 * `releaseForIdle` nulls `runner_id` once the 30-minute idle deadline passes. Both
 * runner-facing routes then refused:
 *
 *     POST /api/session/notebooks → 409 no runner bound to this session
 *     POST /api/export           → 409 no runner bound to this session
 *
 * Only `POST /api/session/credential` ever claimed on demand, so a signed-in session
 * could export **once**. Every later attempt was refused until the user signed in
 * again — for an account whose `auth.json` was still sitting in the vault, and whose
 * plan says the runner is meant to come back transparently (§2.3 step 3→4).
 *
 * Observed live on 2026-10-09, seconds after a first successful export.
 *
 * ## What is asserted, and why it is the database
 *
 * The row. The temptation is to assert the HTTP status, and a status-only test would
 * have passed against the old code for the *wrong* reason — this route answers 202
 * once a runner exists. The claim's real output is the session row: `runner_id` set,
 * and — the part that matters — `auth_state` **still `valid`**.
 *
 * The second one is load-bearing. `claimForLogin` writes
 * `auth_state = 'authenticating'`, which for a rebind is a lie: the session never
 * stopped being signed in. Reusing it here would have made every later route answer
 * *"still signing in; the service is not ready yet"* and told the browser to show a
 * sign-in screen for a valid session. That is bug #21's shape, reintroduced.
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { buildServer, type ServerDeps } from "../src/server.js";
import { ApiConfig } from "../src/config.js";
import { Db, type SessionRow } from "../src/db.js";
import { OrchestratorClient } from "../src/orchestrator-client.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";
import { PoolBinder } from "../src/sweep.js";
import { derive } from "./helpers.js";

const ALLOWED = "https://app.example.com";
const SECRET = "A".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const TTL = 43_200_000;
const NOW = 1_700_000_000_000;

const config: ApiConfig = {
  allowedOrigins: new Set([ALLOWED]),
  csrfKey: "C".repeat(43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  publicOrigin: "https://one-backend.example.com",
  orchestratorUrl: "http://orchestrator:9100",
  orchestratorSecret: "B".repeat(43),
  orchestratorReplayWindowSeconds: 60,
  logLevel: "silent",
  listen: "127.0.0.1:0",
  databasePath: ":memory:",
  sseBufferEvents: 500,
  sseKeepaliveMs: 15_000,
};

let db: Db;
let sse: SseHub;
let limiter: RateLimiter;
let csrfKey: string;
/** Every claim the binder was asked for, so "did it rebind?" is answerable. */
let claims: Array<{ kind: string; guid: string }>;

/**
 * A stub orchestrator that answers a claim and records it.
 *
 * The recording matters: the point of several cases below is that a rebind happened
 * **at all**, and a response status alone cannot distinguish "claimed a runner" from
 * "answered 409 because there was nothing to claim".
 */
function stubOrchestrator(): OrchestratorClient {
  return new OrchestratorClient({
    baseUrl: "http://127.0.0.1:1",
    secret: config.orchestratorSecret,
    now: () => new Date(NOW),
    fetchImpl: (async (url: string, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      if (path === "/claim") {
        claims.push({ kind: "claim", guid: String(init?.headers?.["x-msout-ts"] ?? "") });
        const asked =
          (() => {
            try {
              const body = JSON.parse(
                init?.body instanceof Uint8Array
                  ? new TextDecoder().decode(init.body)
                  : String(init?.body ?? "{}"),
              ) as { slotId?: string };
              return body.slotId ?? "slot-1";
            } catch {
              return "slot-1";
            }
          })() ?? "slot-1";
        return new Response(
          JSON.stringify({
            slotId: asked,
            containerId: "ctr-rebind",
            runnerUrl: `http://msout-runner-${asked}:3100`,
          }),
        );
      }
      if (path === "/stats") {
        return new Response(
          JSON.stringify({
            size: 1,
            byState: { idle: 1 },
            runnerTtlSeconds: 300,
            slotIds: ["slot-1"],
          }),
        );
      }
      return new Response("{}", { status: 404 });
    }) as typeof fetch,
  });
}

/**
 * A runner stub that records nothing and refuses nothing.
 *
 * Present by default because **501 is a real answer** and several of these tests are
 * about what happens when it is *not* the answer: without an adapter the notebooks
 * route answers 501 and the rebind never gets as far as being interesting.
 */
const runnerStub = {
  listNotebooks: async () => {},
  startExport: async () => {},
  submitCredential: async () => {},
  abortExport: async () => {},
};

function deps(binder?: PoolBinder): ServerDeps {
  return {
    db,
    sse,
    limiter,
    orchestrator: stubOrchestrator(),
    runner: runnerStub,
    ...(binder === undefined ? {} : { poolBinder: binder }),
  };
}

async function newApp(binder?: PoolBinder): Promise<FastifyInstance> {
  const app = buildServer(config, deps(binder));
  await app.ready();
  return app;
}

function binder(): PoolBinder {
  return new PoolBinder({ db, orchestrator: stubOrchestrator(), sse, now: () => NOW });
}

/** A session that is signed in, valid, and has no runner — the state under test. */
function seedSignedInWithoutRunner(): void {
  // **Real clock, not the fixed `NOW`.** `authenticate` compares `expires_at` against
  // the wall clock, so a session seeded against a pinned `NOW` (1.7e12) while the
  // server is at 1.79e12 reads as expired and every route answers 401 — for reasons
  // that have nothing to do with what is under test. `NOW` stays for the binder's
  // clock, which is what the claim's idle deadline is asserted against.
  const wall = Date.now();
  csrfKey = generateCsrfKey();
  db.createSession({
    guid: GUID,
    secretHash: hashSecret(SECRET),
    csrfKey,
    now: wall,
    expiresAt: wall + TTL,
  });
  db.run(
    `UPDATE sessions SET state = 'authenticated', runner_id = NULL, auth_state = 'valid',
                        idle_expires_at = ?, last_activity_at = ? WHERE guid = ?`,
    wall - 1_000,
    wall - 1_000,
    GUID,
  );
  db.registerRunner("slot-1", "", "idle");
}

function row(): SessionRow {
  return db.getSession(GUID)!;
}

// Derived from the key **stored on the row**, not from `config.csrfKey`. The token is
// an HMAC over the session's own key, so deriving with the config value produces a
// token that is well-formed and wrong — and every route answers 401 for reasons that
// have nothing to do with what is under test.
/**
 * framesFrom parses the bytes the hub wrote to a subscriber.
 *
 * **Bytes, not internals.** The question this file asks — "what does a browser get
 * told about the sign-in state?" — is answered by the wire, so it is asserted on the
 * wire. Reaching into the hub's buffer instead would pass even if `emit` wrote a
 * frame a browser could not parse.
 */
function framesFrom(res: { written: string[] }): readonly { type: string; data: unknown }[] {
  return res.written
    .join("")
    .split("\n\n")
    .filter((frame) => frame.trim() !== "" && !frame.startsWith(":"))
    .map((frame) => {
      const out: { type: string; data: unknown } = { type: "", data: null };
      for (const line of frame.split("\n")) {
        if (line.startsWith("event: ")) out.type = line.slice("event: ".length);
        else if (line.startsWith("data: ")) {
          try {
            out.data = JSON.parse(line.slice("data: ".length)) as unknown;
          } catch {
            out.data = line.slice("data: ".length);
          }
        }
      }
      return out;
    });
}

/** A subscriber that records the frames written to it, like a browser's EventSource. */
function watch(sse: SseHub, guid: string) {
  const written: string[] = [];
  const res = {
    written,
    write: (chunk: string) => {
      written.push(String(chunk));
      return true;
    },
    end: () => undefined,
  };
  sse.attach(guid, res as never, null);
  return () => framesFrom(res);
}

const authHeaders = () => ({
  cookie: `${SESSION_COOKIE}=${GUID}:${SECRET}`,
  origin: ALLOWED,
  "x-csrf-token": derive(csrfKey, GUID),
});

beforeEach(() => {
  db = new Db(":memory:");
  sse = new SseHub();
  limiter = new RateLimiter({ logSalt: "test" });
  claims = [];
});

describe("a signed-in session whose runner was released", () => {
  it("re-binds a runner on POST /api/session/notebooks instead of refusing", async () => {
    seedSignedInWithoutRunner();
    const app = await newApp(binder());

    const response = await app.inject({
      method: "POST",
      url: "/api/session/notebooks",
      headers: authHeaders(),
    });
    await app.close();

    // The old code answered exactly this, for a session that was still signed in.
    expect(response.statusCode).not.toBe(409);
    expect(response.statusCode).toBe(202);
    expect(row().runner_id).toBe("slot-1");
  });

  it("leaves auth_state 'valid' — a rebind is not a sign-in", async () => {
    seedSignedInWithoutRunner();
    const app = await newApp(binder());

    const response = await app.inject({
      method: "POST",
      url: "/api/session/notebooks",
      headers: authHeaders(),
    });
    await app.close();

    expect(response.statusCode).toBe(202);
    // **The claim under test.** `claimForLogin` would have written 'authenticating'
    // here, which is a lie — the vault still holds the auth.json — and would make
    // every later route answer "still signing in".
    expect(row().auth_state).toBe("valid");
    expect(row().auth_state).not.toBe("authenticating");
    expect(row().state).toBe("authenticated");
  });

  it("re-binds on POST /api/export, so a second export works", async () => {
    seedSignedInWithoutRunner();
    // The export route reaches the runner, so it needs one that answers.
    const app = await newApp(binder());

    const response = await app.inject({
      method: "POST",
      url: "/api/export",
      headers: { ...authHeaders(), "content-type": "application/json" },
      payload: JSON.stringify({ notebook: "Notebook" }),
    });
    await app.close();

    expect(response.statusCode).not.toBe(409);
    expect(response.statusCode).toBe(202);
    expect(row().runner_id).toBe("slot-1");
    // And the export actually started, rather than the route answering 202 for a
    // session it could not have run.
    expect(row().state).toBe("exporting");
  });

  it("does not demote auth_state when it re-binds for an export", async () => {
    seedSignedInWithoutRunner();
    const app = await newApp(binder());

    await app.inject({
      method: "POST",
      url: "/api/export",
      headers: { ...authHeaders(), "content-type": "application/json" },
      payload: JSON.stringify({ notebook: "Notebook" }),
    });
    await app.close();

    // 'exporting' is right — an export is running. 'authenticating' would not be.
    expect(row().auth_state).toBe("valid");
    expect(row().state).toBe("exporting");
  });

  it("does not claim when the session already has a runner", async () => {
    seedSignedInWithoutRunner();
    db.run(`UPDATE sessions SET runner_id = 'slot-1' WHERE guid = ?`, GUID);
    const app = await newApp(binder());

    await app.inject({
      method: "POST",
      url: "/api/session/notebooks",
      headers: authHeaders(),
    });
    await app.close();

    // A second claim would burn a second slot for nothing, and `claimRunner` is
    // atomic precisely so two routes cannot both believe they own the pool.
    expect(claims).toHaveLength(0);
    expect(row().runner_id).toBe("slot-1");
  });

  it("still refuses when there is no pool binder at all", async () => {
    // The unwired state is unchanged, and says so plainly rather than pretending
    // the pool is busy.
    seedSignedInWithoutRunner();
    const app = await newApp();

    const response = await app.inject({
      method: "POST",
      url: "/api/session/notebooks",
      headers: authHeaders(),
    });
    await app.close();

    expect(response.statusCode).toBe(409);
    expect(response.json().error).toBe("no runner bound to this session");
    expect(row().runner_id).toBeNull();
  });

  it("reports a busy pool as retryable, not as a dead control plane", async () => {
    // Every pool row taken, so the claim cannot succeed. The answer must still be
    // the four-way vocabulary rather than a flat "no runner bound".
    seedSignedInWithoutRunner();
    db.run(`UPDATE runners SET status = 'claimed' WHERE id = 'slot-1'`);
    const app = await newApp(binder());

    const response = await app.inject({
      method: "POST",
      url: "/api/session/notebooks",
      headers: authHeaders(),
    });
    await app.close();

    expect(response.statusCode).toBe(503);
    expect(response.json().error).toBe("every session is busy");
    expect(response.json().retryable).toBe(true);
  });

  it("tells the browser the session is authenticated, not signing in", async () => {
    // The route used to emit `auth-state: authenticating` one line after
    // `requireAuthenticated` proved the session was `valid`. A browser reading that
    // shows the sign-in screen for a signed-in session.
    seedSignedInWithoutRunner();
    const frames = watch(sse, GUID);
    const app = await newApp(binder());

    await app.inject({
      method: "POST",
      url: "/api/session/notebooks",
      headers: authHeaders(),
    });
    await app.close();

    const received = frames();
    // Nothing at all claims the session is authenticating. The session is `valid` and
    // the vault still holds its cookie jar; telling a browser otherwise is what made a
    // signed-in user believe they had been signed out.
    expect(received.filter((e) => e.type === "auth-state")).toHaveLength(0);
    // What it is told is true: still authenticated, and working.
    expect(received.some((e) => e.type === "session-status")).toBe(true);
  });
});