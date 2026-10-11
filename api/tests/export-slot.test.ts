/**
 * The six global export slots, and the guarantee that every export route gives
 * its slot back.
 *
 * ## The outage this file is *not* about
 *
 * The symptom that prompted it was six successful exports followed by a 429 that
 * never cleared without a restart. **That outage does not exist.** `POST
 * /api/export` has released the global slot on its 202 path since PR #4
 * (`263c550`, 2026-10-06), the deployed host carries the same four releases in
 * `/app/dist/routes.js`, and an eight-export drive through the real route
 * answers 202 eight times with the counter at zero. The signature is real and
 * reproducible — but only by *removing* that release, which is the mutation
 * test A below is built to catch.
 *
 * What is real is the *shape* underneath it: `acquireExportSlot()` (routes.ts:946)
 * and the handler's exits are joined by nothing but discipline. The four bails that
 * release explicitly (`routes.ts:971`, `996`, `1044`, `1110`) are correct and stay
 * where they are. An unplanned exit — a `db.run` throwing SQLITE_BUSY, a throw out
 * of the start-failure path's own writes — skips every one of them, and the slot is
 * held until the process restarts. Six of those and the api refuses exports for
 * everyone, with no log line and no metric to point at it, because the 429 that
 * finally shows it is refused at the front door and `RateLimiter.stats()` is not
 * called from `src/` anywhere.
 *
 * The fix is a `finally` around the body of the handler. The slot comes back on
 * every exit, and the one log line the net can emit says when it was the net that
 * returned it.
 *
 * ## Why these three, and what each would catch
 *
 *   A. A leak on the 202 path — the phantom outage's exact signature, asserted
 *      after every single request rather than at the end.
 *   B. That the cap is real and is enforced by the limiter and not by the
 *      per-session guard in front of it. Seven *distinct* sessions, because one
 *      session can never hold two slots: the guard at routes.ts:930-942 answers
 *      `409` before the acquire is ever reached.
 *   C. That the `finally` actually fires, by throwing out of the handler and
 *      checking the counter rather than trusting the shape of the code.
 *
 * ## The cap is a constant, not a fixture
 *
 * Six is `globalConcurrentExports` (`rate-limit.ts:43`), and `buildRateLimiter`
 * deliberately does not take it from configuration (`rate-limit.ts:82-101`: a
 * deployment that could raise the global backstop could raise the one control that
 * holds when the per-IP limits are wrong). So there is no knob to raise it, and
 * these tests are shaped around six rather than around a limit they supply. That is
 * a constraint, not an accident — it is why B needs seven sessions and a gate.
 */

import { randomUUID } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildServer, type ServerDeps } from "../src/server.js";
import { ApiConfig, validateOrigins } from "../src/config.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { FakeOrchestrator } from "../mock/fake-orchestrator.js";
import { MockRunner } from "../mock/mock-runner.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { deriveCsrfToken, generateCsrfKey, hashSecret } from "../src/session.js";
import { PoolBinder } from "../src/sweep.js";

const ORIGIN = "http://localhost:5173";
const SECRET = "A".repeat(43);
const TTL = 43_200_000;
/** How many global slots there are, and therefore how many exports can be parked. */
const CAP = 6;

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

/**
 * Per-session CSRF keys, kept because `deriveCsrfToken` needs the *session's* key
 * and the tests below use several sessions at once. `mock.test.ts` cannot be
 * imported for this: its helpers are hardwired to one guid and one module-level
 * key, which is exactly the shape B cannot use.
 */
const csrfKeys = new Map<string, string>();

/**
 * Seeds a session that is signed in and already bound to a runner.
 *
 * Bound on purpose: `runner_id = null` sends the export route into `rebindRunner`,
 * which needs a pool and an orchestrator and is not what any of these tests is
 * about. Each session gets its own runner id and its own CSRF key.
 */
function seedBound(store: Db, guid: string, runnerId: string): void {
  const csrfKey = generateCsrfKey();
  csrfKeys.set(guid, csrfKey);
  store.createSession({
    guid,
    secretHash: hashSecret(SECRET),
    csrfKey,
    now: Date.now(),
    expiresAt: Date.now() + TTL,
  });
  store.run(
    `UPDATE sessions SET state = 'authenticated', auth_state = 'valid', runner_id = ? WHERE guid = ?`,
    runnerId,
    guid,
  );
}

function cookieFor(guid: string): string {
  return `${SESSION_COOKIE}=${guid}:${SECRET}`;
}

function csrfFor(guid: string): string {
  const key = csrfKeys.get(guid);
  if (key === undefined) throw new Error(`no csrf key seeded for ${guid}`);
  return deriveCsrfToken(key, guid);
}

/** A complete, honest `POST /api/export` — real cookie, real CSRF, real origin. */
function exportRequest(guid: string) {
  return {
    method: "POST" as const,
    url: "/api/export",
    headers: {
      "content-type": "application/json",
      cookie: cookieFor(guid),
      origin: ORIGIN,
      "x-csrf-token": csrfFor(guid),
    },
    payload: JSON.stringify({ notebook: "Work" }),
  };
}

/**
 * The deps, with the limiter passed in rather than constructed here.
 *
 * `mock.test.ts`'s `newApp` builds its own limiter, which hides the one counter
 * every assertion in this file is about: `activeExports` lives on the limiter
 * instance, so the test has to be the one holding it.
 */
function depsFor(store: Db, limiter: RateLimiter, runner: MockRunner): ServerDeps {
  const orchestrator = new FakeOrchestrator({ size: 2 });
  return {
    db: store,
    sse,
    limiter,
    // Unused — `runner_id` is bound on every session seeded here, so the rebind
    // path is never taken and the pool is never consulted.
    orchestrator,
    runner,
    eraseRunner: runner,
    poolBinder: new PoolBinder({ db: store, orchestrator, sse, now: () => Date.now() }),
  };
}

/**
 * Polls a condition, failing rather than hanging.
 *
 * `expect.poll` is not used because a condition that never becomes true must
 * produce a *failure naming the state it was stuck at* — and "only 4 of 6 runners
 * were entered" is the whole diagnosis. A timeout would say only that something,
 * somewhere, was slow.
 */
async function waitForExports(entered: () => number, target: number): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (entered() >= target) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`timed out waiting for ${target} gated exports to start; ${entered()} entered`);
}

beforeEach(() => {
  db = new Db(":memory:");
  sse = new SseHub({ now: () => Date.now() });
  csrfKeys.clear();
});

afterEach(() => {
  db.close();
});

describe("the global export slot", () => {
  it("eight exports in a row never accumulate a slot", async () => {
    // **The regression test for an outage that never happened.** A leak on the 202
    // path produces exactly `[202 x6, 429, 429]` — and a test that asserted only at
    // the end would pass that shape, because the 429s free nothing and the final
    // counter could read 0 for the wrong reason. Asserted inside the loop, the
    // leak is caught at the *first* request: the counter reads 1 the moment the
    // second request begins, long before the 429 at #7 is ever reached.
    //
    // The mutation that proves it: delete **both** releases on the 202 path —
    // `release()` at routes.ts:1110 *and* `release()` in the handler's `finally`.
    // This then fails on `expected 1 to be +0` at the first iteration (verified,
    // not assumed). Deleting only the first of the two is invisible here, and that
    // is the point of the `finally`: it is a net under a deliberate release, not
    // a replacement for it.
    const guid = randomUUID();
    seedBound(db, guid, "slot-1");
    const limiter = new RateLimiter({ logSalt: "test" });
    const runner = new MockRunner({ db, sse, speed: 0 });
    const app = buildServer(config, depsFor(db, limiter, runner));
    await app.ready();
    try {
      for (let attempt = 1; attempt <= CAP + 2; attempt++) {
        const response = await app.inject(exportRequest(guid));
        expect(response.statusCode).toBe(202);
        expect(limiter.activeExports).toBe(0);
      }
    } finally {
      await app.close();
    }
  });

  it("refuses a seventh export while six starts are in flight", async () => {
    // Seven **distinct** sessions, and that is not pedantry: the per-session guard
    // at routes.ts:930-942 refuses a second export with `409` before the acquire is
    // reached, so six exports on one session would never get near the limiter and
    // the test would pass without having tested it.
    const guids = Array.from({ length: CAP + 1 }, () => randomUUID());
    guids.forEach((guid, index) => seedBound(db, guid, `slot-${index}`));
    const seventh = guids[CAP];
    if (seventh === undefined) throw new Error("expected a seventh session");

    const limiter = new RateLimiter({ logSalt: "test" });
    // A runner that parks inside `startExport` and never comes back on its own, so
    // six slots are provably held at the moment the seventh request arrives. The
    // counter increments **synchronously**, before any await: by the time it is
    // read, the acquire on the route above it has already happened, which is what
    // makes this deterministic rather than a race with fastify's dispatcher.
    const gate = { entered: 0, resolve: [] as Array<() => void> };
    const gated = Object.assign(new MockRunner({ db, sse, speed: 0 }), {
      startExport(): Promise<void> {
        gate.entered += 1;
        return new Promise<void>((resolve) => {
          gate.resolve.push(resolve);
        });
      },
    });

    const app = buildServer(config, depsFor(db, limiter, gated));
    await app.ready();
    const inflight = guids.slice(0, CAP).map((guid) => app.inject(exportRequest(guid)));
    let statuses: number[] = [];
    try {
      await waitForExports(() => gate.entered, CAP);

      const refused = await app.inject(exportRequest(seventh));
      expect(refused.statusCode).toBe(429);
      const body = refused.json() as { error?: string; retryAfterSeconds?: number };
      // The reason is what the browser turns into a wait message, and the retry
      // hint is the only thing standing between a refused user and a support call.
      expect(body.error).toBe("too-many-exports");
      expect(typeof body.retryAfterSeconds).toBe("number");
    } finally {
      // Let the parked starts finish even when an assertion above threw, so the
      // injected requests cannot outlive the test and leak into the next one.
      for (const open of gate.resolve) open();
      // A rejection is recorded as 0 rather than propagated: the point of the
      // finally is cleanup, and the assertion below is what should report the
      // failure, with all six statuses in one place.
      const settled = await Promise.allSettled(inflight);
      statuses = settled.map((outcome) =>
        outcome.status === "fulfilled" ? outcome.value.statusCode : 0,
      );
      await app.close();
    }

    expect(statuses).toEqual([202, 202, 202, 202, 202, 202]);
    expect(limiter.activeExports).toBe(0);
  });

  it("releases the global slot when the route throws before the export starts", async () => {
    // The unplanned exit, made real. The first `db.run` inside the handler's try
    // (routes.ts:977) throws, which is the shape a locked SQLite file takes in
    // production; fastify turns it into a 500, and without the `finally` the slot
    // taken at routes.ts:946 is never returned.
    //
    // The mutation that proves it: delete the `finally`. Nothing else in this file
    // turns red — the four explicit releases are on paths this request never
    // reaches, because the throw happens before the first of them.
    class ThrowingDb extends Db {
      override run(sql: string, ...params: unknown[]): number {
        if (sql.includes("state = 'exporting', notebook")) {
          throw new Error("simulated SQLITE_BUSY");
        }
        return super.run(sql, ...params);
      }
    }

    // Seeded through **this** instance. A second `Db(":memory:")` is a second, empty
    // database: the route would answer 401 for want of a session and the test would
    // be asserting that a 401 releases a slot.
    const store = new ThrowingDb(":memory:");
    const guid = randomUUID();
    seedBound(store, guid, "slot-1");

    const limiter = new RateLimiter({ logSalt: "test" });
    const runner = new MockRunner({ db: store, sse, speed: 0 });
    const app = buildServer(config, depsFor(store, limiter, runner));
    await app.ready();
    try {
      const response = await app.inject(exportRequest(guid));
      expect(response.statusCode).toBe(500);
      expect(limiter.activeExports).toBe(0);
    } finally {
      await app.close();
      store.close();
    }
  });
});