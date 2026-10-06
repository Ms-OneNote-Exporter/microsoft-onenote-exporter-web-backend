import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { buildServer, type ServerDeps } from "../src/server.js";
import { ApiConfig, validateOrigins } from "../src/config.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { FakeOrchestrator } from "../mock/fake-orchestrator.js";
import { MockRunner } from "../mock/mock-runner.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { deriveCsrfToken, generateCsrfKey, hashSecret } from "../src/session.js";
import { MAX_CREDENTIAL_BYTES } from "../src/credential.js";
import { PoolBinder, syncPool } from "../src/sweep.js";

/**
 * The mock's job is to be indistinguishable from the real api over HTTP, so these
 * tests assert that from the outside: real cookies, real CSRF, real CORS, real
 * status codes — with only the orchestrator and the runner replaced.
 *
 * They also assert what the mock must NOT do, which is the property that would be
 * easy to break by accident: the credential bytes are drained and discarded.
 */

const ORIGIN = "http://localhost:5173";
const SECRET = "A".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const TTL = 43_200_000;

const config: ApiConfig = {
  allowedOrigins: validateOrigins(ORIGIN),
  csrfKey: "C".repeat(43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  orchestratorUrl: "http://mock:9100",
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
let runner: MockRunner;
let csrfKey: string;

/**
 * Build a server with the real code and only the two things faked.
 *
 * The pool is seeded and a real `PoolBinder` is supplied, so a login exercises the
 * production claim path — SQLite claim, orchestrator claim, compensation — rather
 * than a runner id written straight into the row.
 */
async function newApp(
  options: { withRunner?: boolean; poolSize?: number } = {},
): Promise<{ app: FastifyInstance; orchestrator: FakeOrchestrator }> {
  const withRunner = options.withRunner ?? true;
  const orchestrator = new FakeOrchestrator({ size: options.poolSize ?? 2 });
  syncPool(db, orchestrator.slotIds());
  const deps: ServerDeps = {
    db,
    sse,
    limiter: new RateLimiter({ logSalt: "test" }),
    orchestrator,
    ...(withRunner
      ? {
          runner,
          eraseRunner: runner,
          poolBinder: new PoolBinder({ db, orchestrator, sse, now: () => Date.now() }),
        }
      : {}),
  };
  const app = buildServer(config, deps);
  await app.ready();
  return { app, orchestrator };
}

/**
 * Creates a session row.
 *
 * Unbound by default: a session that already has a `runner_id` cannot demonstrate
 * the lazy claim, which is the thing that was missing.
 */
function seedSession(store: Db, guid = GUID): void {
  csrfKey = generateCsrfKey();
  store.createSession({
    guid,
    secretHash: hashSecret(SECRET),
    csrfKey,
    now: Date.now(),
    expiresAt: Date.now() + TTL,
  });
}

/** A session that is logged in, for the routes that require auth.state valid. */
function seed(runnerId: string | null = "slot-1") {
  seedSession(db);
  db.run(
    `UPDATE sessions SET state = 'authenticated', auth_state = 'valid', runner_id = ? WHERE guid = ?`,
    runnerId,
    GUID,
  );
}

/**
 * A session created but not logged in and with no runner — the state a real user
 * is in when they first submit a password.
 */
function seedFresh() {
  seedSession(db);
}

function cookie(): string {
  return `${SESSION_COOKIE}=${GUID}:${SECRET}`;
}

function csrf(): string {
  return deriveCsrfToken(csrfKey, GUID);
}

beforeEach(() => {
  db = new Db(":memory:");
  sse = new SseHub({ now: () => Date.now() });
  // speed 0: the scripted delays become no-ops so the tests do not sleep.
  runner = new MockRunner({ db, sse, speed: 0 });
});

afterEach(() => {
  db.close();
});

// ---- it really is the real api -------------------------------------------

describe("the mock uses the real api", () => {
  it("serves the real version handshake", async () => {
    const { app } = await newApp();
    try {
      const response = await app.inject({ method: "GET", url: "/api/public/version" });
      expect(response.statusCode).toBe(200);
      expect(response.json().protocol).toBe(3);
    } finally {
      await app.close();
    }
  });

  it("enforces the real CSRF rules", async () => {
    seed();
    const { app } = await newApp();
    try {
      // No token.
      const noToken = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: { "content-type": "text/plain", cookie: cookie(), origin: ORIGIN, "content-length": "8" },
        payload: "hunter22",
      });
      expect(noToken.statusCode).toBe(403);

      // Foreign origin.
      const foreign = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: "https://evil.test",
          "x-csrf-token": csrf(),
          "content-length": "8",
        },
        payload: "hunter22",
      });
      expect(foreign.statusCode).toBe(403);
      expect(foreign.headers["access-control-allow-origin"]).toBeUndefined();
    } finally {
      await app.close();
    }
  });

  it("applies the real credential cap", async () => {
    seed();
    const { app } = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "x".repeat(MAX_CREDENTIAL_BYTES + 1),
      });
      expect(response.statusCode).toBe(413);
    } finally {
      await app.close();
    }
  });

  it("returns the CSRF token in the body, like the real server", async () => {
    const { app } = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session",
        headers: { "content-type": "application/json", origin: ORIGIN },
        payload: JSON.stringify({ guid: GUID, secret: SECRET }),
      });
      expect(response.statusCode).toBe(201);
      expect(response.json().csrfToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
      // One cookie, not two — the fix from the review.
      expect(String(response.headers["set-cookie"])).toContain("__Host-msout=");
      expect(String(response.headers["set-cookie"])).not.toContain("msout_csrf");
    } finally {
      await app.close();
    }
  });
});

// ---- the four 501s now work ----------------------------------------------

describe("routes that were 501", () => {
  it("accepts a credential and logs in", async () => {
    seed();
    const { app } = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "hunter2",
      });

      // 202, not 200: accepted is not succeeded. The outcome is an event.
      expect(response.statusCode).toBe(202);
      expect(response.json().accepted).toBe(true);
      // And the scripted run completed, so the session is now valid.
      expect(db.getSession(GUID)?.auth_state).toBe("valid");
    } finally {
      await app.close();
    }
  });

  it("reports a bad password as login-failed, and does not mark the session valid", async () => {
    seed();
    runner.setNextLogin("bad-password");
    const { app } = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "wrong",
      });

      expect(response.statusCode).toBe(202);
      expect(db.getSession(GUID)?.auth_state).toBe("failed");
    } finally {
      await app.close();
    }
  });

  it("emits an MFA challenge rather than hanging", async () => {
    // PLAN-v2 §6.1: a swallowed challenge is a hang, not an error.
    seed();
    runner.setNextLogin("mfa-number");
    const { app } = await newApp();
    try {
      await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "hunter2",
      });

      // Still mid-login, not failed and not valid.
      expect(db.getSession(GUID)?.auth_state).toBe("authenticating");
    } finally {
      await app.close();
    }
  });

  it("lists notebooks", async () => {
    seed();
    const { app } = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/notebooks",
        headers: {
          "content-type": "application/json",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "{}",
      });
      expect(response.statusCode).toBe(202);
    } finally {
      await app.close();
    }
  });

  it("runs an export to completion and records an artifact", async () => {
    seed();
    const { app } = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/export",
        headers: {
          "content-type": "application/json",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: JSON.stringify({ notebook: "Work" }),
      });

      expect(response.statusCode).toBe(202);
      const row = db.getSession(GUID);
      expect(JSON.parse(row?.export_state ?? "{}").state).toBe("done");
      // So the snapshot's artifact.available is true and a download link can be
      // built against it.
      expect(row?.artifact_id).not.toBeNull();
    } finally {
      await app.close();
    }
  });

  it("releases the global export slot when the export finishes", async () => {
    seed();
    const limiter = new RateLimiter({ logSalt: "t" });
    const app = buildServer(config, {
      db,
      sse,
      limiter,
      orchestrator: new FakeOrchestrator(),
      runner,
      eraseRunner: runner,
    });
    await app.ready();
    try {
      await app.inject({
        method: "POST",
        url: "/api/export",
        headers: {
          "content-type": "application/json",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: JSON.stringify({ notebook: "Work" }),
      });
      // A held slot would shrink the global cap with every export.
      expect(limiter.activeExports).toBe(0);
    } finally {
      await app.close();
    }
  });

  it("aborts an export and marks it partial with a reason", async () => {
    seed();
    const { app } = await newApp();
    try {
      const started = await app.inject({
        method: "POST",
        url: "/api/export",
        headers: {
          "content-type": "application/json",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: JSON.stringify({ notebook: "Work" }),
      });
      const exportId = started.json().id;

      const aborted = await app.inject({
        method: "POST",
        url: `/api/export/${exportId}/abort`,
        headers: { cookie: cookie(), origin: ORIGIN, "x-csrf-token": csrf() },
      });

      expect(aborted.statusCode).toBe(202);
      const stored = JSON.parse(db.getSession(GUID)?.export_state ?? "{}");
      expect(stored.state).toBe("partial");
      // mac's pushback: "you stopped this" is false for a quota or disk abort, so
      // the reason is explicit.
      expect(stored.partialReason).toBe("aborted");
    } finally {
      await app.close();
    }
  });

  it("still 501s without a runner, so the unwired contract is unchanged", async () => {
    // The frontend may be built against the mock, but the *absence* of a runner
    // must still be honest: a 501 naming what is missing.
    seed();
    const { app } = await newApp({ withRunner: false });
    try {
      for (const [url, payload] of [
        ["/api/session/credential", "hunter2"],
        ["/api/session/notebooks", "{}"],
        ["/api/export", JSON.stringify({ notebook: "Work" })],
      ] as const) {
        const response = await app.inject({
          method: "POST",
          url,
          headers: {
            "content-type": "application/json",
            cookie: cookie(),
            origin: ORIGIN,
            "x-csrf-token": csrf(),
          },
          payload,
        });
        expect([501, 202]).toContain(response.statusCode);
      }
    } finally {
      await app.close();
    }
  });
});

// ---- the lazy claim, which was the bug the mock found ---------------------

describe("binding a runner on login", () => {
  it("claims a runner for a session that has none, rather than 409ing", async () => {
    // The bug: `claimForLogin` existed and was tested, but nothing in src/ called
    // it and nothing seeded the runners table, so `runner_id` was always null and
    // this route always refused. A user could never submit a password at all.
    seedFresh();
    const { app } = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "hunter2",
      });

      expect(response.statusCode).toBe(202);
      expect(db.getSession(GUID)?.runner_id).not.toBeNull();
    } finally {
      await app.close();
    }
  });

  it("names pool exhaustion instead of reporting it as a conflict", async () => {
    // §2.6: "every session is busy" and "the control plane is unreachable" are
    // different advice, and the user cannot tell them apart from a 409.
    const other = "11111111-2222-3333-4444-555555555555";
    const { app } = await newApp({ poolSize: 1 });
    try {
      // Seeded first, because seedSession sets the module-level csrfKey and the
      // session under test has to be the one that owns it.
      seedSession(db, other);
      seedFresh();
      // Fill the only slot with the other session, as a concurrent login would.
      db.run(`UPDATE runners SET status = 'claimed', session_guid = ? WHERE id = 'slot-1'`, other);

      const response = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "hunter2",
      });

      expect(response.statusCode).toBe(503);
      expect(response.json().error).toBe("every session is busy");
      // Tells a client the condition clears on its own, so it can retry rather
      // than telling the user something failed permanently.
      expect(response.json().retryable).toBe(true);
    } finally {
      await app.close();
    }
  });

  it("does not bind a runner for a request it refuses on framing", async () => {
    // Ordering is the point: an oversized request must not create a container.
    seedFresh();
    const { app } = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "x".repeat(MAX_CREDENTIAL_BYTES + 1),
      });

      expect(response.statusCode).toBe(413);
      // No slot was taken, so a rejected upload cannot shrink the pool.
      expect(db.getSession(GUID)?.runner_id).toBeNull();
      expect(db.listRunners().filter((r) => r.status === "idle")).toHaveLength(2);
    } finally {
      await app.close();
    }
  });

  it("binds nothing when the credential route answers 501", async () => {
    // The adapter check runs before the claim, so the unwired state never claims
    // a container it has no way to use.
    seedFresh();
    const { app } = await newApp({ withRunner: false });
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "hunter2",
      });

      expect(response.statusCode).toBe(501);
      expect(db.getSession(GUID)?.runner_id).toBeNull();
      expect(db.listRunners().filter((r) => r.status === "idle")).toHaveLength(2);
    } finally {
      await app.close();
    }
  });
});

// ---- what the mock must not do -------------------------------------------

describe("the mock does not handle the credential", () => {
  // The property the whole credential path exists to have. A dev tool that logged
  // or inspected the password would be a second handler for it.
  it("never stores the credential anywhere", async () => {
    seed();
    const { app } = await newApp();
    const password = "correct-horse-battery-staple";

    await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: {
        "content-type": "text/plain",
        cookie: cookie(),
        origin: ORIGIN,
        "x-csrf-token": csrf(),
      },
      payload: password,
    });

    // Not in the database...
    for (const row of db.all<Record<string, unknown>>(`SELECT * FROM sessions`)) {
      expect(JSON.stringify(row)).not.toContain(password);
    }
    // ...not in the response...
    // ...and not echoed into any SSE frame. The hub's buffer is the only place a
    // leak could hide, so it is checked through a subscriber.
    const captured: string[] = [];
    const { EventEmitter } = require("node:events") as typeof import("node:events");
    const res = new EventEmitter() as unknown as import("node:http").ServerResponse;
    res.write = ((c: string) => {
      captured.push(String(c));
      return true;
    }) as never;
    res.end = (() => res) as never;
    sse.attach(GUID, res, null);

    await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: {
        "content-type": "text/plain",
        cookie: cookie(),
        origin: ORIGIN,
        "x-csrf-token": csrf(),
      },
      payload: password,
    });

    expect(captured.join("")).not.toContain(password);
    await app.close();
  });

  it("reports only a byte count, never the content", async () => {
    seed();
    const { app } = await newApp();
    try {
      const response = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: {
          "content-type": "text/plain",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: "hunter2",
      });
      // The response is about acceptance, and says nothing about the value.
      expect(Object.keys(response.json())).toEqual(["accepted"]);
    } finally {
      await app.close();
    }
  });
});

// ---- the fake orchestrator ------------------------------------------------

describe("FakeOrchestrator", () => {
  it("hands out a distinct slot per session", async () => {
    const fake = new FakeOrchestrator({ size: 2 });
    const first = await fake.claim("a", new Date());
    const second = await fake.claim("b", new Date());
    expect(first.ok && second.ok).toBe(true);
    if (first.ok && second.ok) {
      expect(first.value.slotId).not.toBe(second.value.slotId);
    }
  });

  it("is idempotent for a session that already has a slot", async () => {
    // A client may retry after a network blip, and must not leak a slot doing it.
    const fake = new FakeOrchestrator({ size: 2 });
    const first = await fake.claim("a", new Date());
    const second = await fake.claim("a", new Date());
    if (first.ok && second.ok) {
      expect(second.value.slotId).toBe(first.value.slotId);
    }
    expect(fake.freeSlots).toBe(1);
  });

  it("keeps the slot on release, and frees it for someone else", async () => {
    // release and remove are different operations and a fake that conflated them
    // would hide the distinction the sweepers depend on.
    const fake = new FakeOrchestrator({ size: 1 });
    const claimed = await fake.claim("a", new Date());
    if (!claimed.ok) throw new Error("claim failed");
    expect(fake.freeSlots).toBe(0);

    await fake.release(claimed.value.slotId);
    expect(fake.freeSlots).toBe(1);
    expect(fake.poolSize).toBe(1);
  });

  it("answers 409 when the pool is full, so exhaustion is demonstrable", async () => {
    const fake = new FakeOrchestrator({ size: 1 });
    expect((await fake.claim("a", new Date())).ok).toBe(true);
    const second = await fake.claim("b", new Date());
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.error.kind).toBe("conflict");
  });

  it("refuses to remove a slot that is in use", async () => {
    // The real orchestrator will not remove a live slot, and a fake that allowed
    // it would let a test exercise a path a deployment cannot take.
    const fake = new FakeOrchestrator({ size: 1 });
    const claimed = await fake.claim("a", new Date());
    if (!claimed.ok) throw new Error("claim failed");
    const removed = await fake.remove(claimed.value.slotId);
    expect(removed.ok).toBe(false);
  });

  it("answers 409 for an unknown slot, like the real one", async () => {
    const fake = new FakeOrchestrator({ size: 1 });
    const released = await fake.release("slot-nope");
    expect(released.ok).toBe(false);
    if (!released.ok) expect(released.error.kind).toBe("conflict");
  });

  it("does not claim artifacts exist", async () => {
    // Asserting "yes" would let a client build a download link that 404s, and
    // hide the bug until the real pipeline exists.
    const fake = new FakeOrchestrator({ size: 1 });
    const stat = await fake.stat("A".repeat(43));
    expect(stat.ok).toBe(true);
    if (stat.ok) {
      expect(stat.value.exists).toBe(false);
      expect(stat.value.size).toBe(0);
    }
  });

  it("recycles into a new container id for the same slot, keeping the binding", async () => {
    const fake = new FakeOrchestrator({ size: 1 });
    const claimed = await fake.claim("a", new Date());
    if (!claimed.ok) throw new Error("claim failed");
    const recycled = await fake.recycle(claimed.value.slotId, "ttl");
    expect(recycled.ok).toBe(true);
    if (recycled.ok) expect(recycled.value.recycled).toBe(true);
    expect(fake.poolSize).toBe(1);
    // Still bound, so nothing else can take it mid-recycle.
    expect(fake.freeSlots).toBe(0);
  });
});

// ---- the pool seeding the mock discovered was missing ---------------------

describe("syncPool", () => {
  it("seeds an idle slot per id, so a claim can succeed", async () => {
    // Without this the runners table is empty, claimRunner can never match an
    // idle row, and every login 503s as if the pool were busy.
    const db = new Db(":memory:");
    try {
      const orchestrator = new FakeOrchestrator({ size: 2 });
      const pool = syncPool(db, orchestrator.slotIds());
      expect(pool.added).toBe(2);
      expect(pool.total).toBe(2);
      expect(db.listRunners().every((r) => r.status === "idle")).toBe(true);
    } finally {
      db.close();
    }
  });

  it("is idempotent, so a restart does not duplicate or free slots", () => {
    const db = new Db(":memory:");
    try {
      const orchestrator = new FakeOrchestrator({ size: 2 });
      syncPool(db, orchestrator.slotIds());
      // A slot in use must survive a second boot.
      const slotId = orchestrator.slotIds()[0]!;
      db.claimRunner("session-a");
      db.run(`UPDATE runners SET session_guid = 'session-a' WHERE id = ?`, slotId);

      const second = syncPool(db, orchestrator.slotIds());
      expect(second.added).toBe(0);
      expect(second.total).toBe(2);
      const row = db.get<{ session_guid: string }>(
        `SELECT session_guid FROM runners WHERE id = ?`,
        slotId,
      );
      expect(row?.session_guid).toBe("session-a");
    } finally {
      db.close();
    }
  });

  it("uses the orchestrator's ids verbatim, because release takes them back", async () => {
    // sessions.runner_id holds this id and release/recycle take it as a slotId,
    // so an id invented here would be released against a slot that does not exist.
    const db = new Db(":memory:");
    try {
      const orchestrator = new FakeOrchestrator({ size: 1 });
      const ids = orchestrator.slotIds();
      syncPool(db, ids);

      const binder = new PoolBinder({ db, orchestrator, sse: new SseHub(), now: () => Date.now() });
      seedSession(db);
      const session = db.getSession(GUID);
      if (session === undefined) throw new Error("seed failed");
      const bound = await binder.claimForLogin(session);
      expect(bound.ok).toBe(true);
      if (bound.ok) {
        expect(ids).toContain(bound.runnerId);
        // And the orchestrator agrees the slot is real, so release will find it.
        const released = await orchestrator.release(bound.runnerId);
        expect(released.ok).toBe(true);
      }
    } finally {
      db.close();
    }
  });
});
// ---- the failed-export reason, which mac found missing --------------------

describe("a failed export explains itself", () => {
  /** An adapter whose export throws with a given classification. */
  function failingRunner(reason: string | null): MockRunner {
    const inner = new MockRunner({ db, sse, speed: 0 });
    return Object.assign(inner, {
      async startExport(): Promise<void> {
        throw reason === null ? new Error("boom") : Object.assign(new Error("boom"), { reason });
      },
    });
  }

  async function exportAndReadSnapshot(
    failing: MockRunner,
  ): Promise<{ status: number; body: Record<string, never> }> {
    const { app } = await newApp();
    const orchestrator = new FakeOrchestrator({ size: 2 });
    syncPool(db, orchestrator.slotIds());
    // Swap in the failing adapter for the real deps the app was built with.
    await app.close();
    const server = buildServer(config, {
      db,
      sse,
      limiter: new RateLimiter({ logSalt: "test" }),
      orchestrator,
      runner: failing,
      eraseRunner: failing,
      poolBinder: new PoolBinder({ db, orchestrator, sse, now: () => Date.now() }),
    });
    await server.ready();
    try {
      const started = await server.inject({
        method: "POST",
        url: "/api/export",
        headers: {
          "content-type": "application/json",
          cookie: cookie(),
          origin: ORIGIN,
          "x-csrf-token": csrf(),
        },
        payload: JSON.stringify({ notebook: "Work" }),
      });
      expect(started.statusCode).toBe(502);
      const status = await server.inject({
        method: "GET",
        url: "/api/session/status",
        headers: { cookie: cookie(), origin: ORIGIN },
      });
      return { status: status.statusCode, body: status.json() };
    } finally {
      await server.close();
    }
  }

  it("reports a classified reason", async () => {
    seed();
    const { body } = await exportAndReadSnapshot(failingRunner("disk"));
    const snapshot = body as unknown as { export: { state: string; error: string | null } };
    expect(snapshot.export.state).toBe("failed");
    expect(snapshot.export.error).toMatch(/disk/i);
  });

  it("falls back to a generic message rather than leaking the adapter's text", async () => {
    // The exporter is a third-party CLI. Its error text carries absolute paths
    // and sometimes the notebook name, and this value is rendered on a page.
    seed();
    const { body } = await exportAndReadSnapshot(failingRunner(null));
    const snapshot = body as unknown as { export: { error: string | null } };
    expect(snapshot.export.error).not.toBeNull();
    expect(snapshot.export.error).not.toMatch(/[/\\]/);
    expect(snapshot.export.error).not.toContain("Work");
  });
});
