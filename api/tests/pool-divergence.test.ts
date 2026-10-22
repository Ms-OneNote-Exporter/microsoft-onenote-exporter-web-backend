// A login could not start at all, and the error said the wrong thing.
//
// ## What the user saw
//
//     1. generated a session GUID
//     2. started a session
//     3. logged in
//     → "The service returned 502 (runner control plane unreachable)."
//
// ## What the three views said
//
//     api  /claim    → 409 conflict, for slot-2
//     api  runners   → [{"id":"slot-1","status":"idle"},{"id":"slot-2","status":"idle"}]
//     orch /stats    → {"size":1,"byState":{"idle":1},"slotIds":["slot-1"]}
//
// The control plane was perfectly reachable. It answered in milliseconds, clearly, and
// the answer was "no": it does not have a `slot-2`. The api asked for a slot by name,
// the orchestrator refused it, and the api reported the refusal as an unreachable
// component.
//
// Two defects, and they are independent:
//
//   - the api offered a slot that does not exist, from a `runners` table that only ever
//     grows. `claimRunner` picks with `ORDER BY RANDOM()`, so it would pick the stale row
//     again on the next login, forever.
//   - the refusal was reported as a 5xx, which told the user to retry something that
//     could not work, and told an operator a component was down.
//
// The stale row is not an accident of this process. The orchestrator's slot ids come
// from a package-level counter (`nextSlotSeq`), which is documented as "a log handle
// rather than a durable identity" — while the api stores them in SQLite rows that
// outlive the orchestrator and uses them for `release`. Boot reconciliation then
// *deleted* every runner, because it ran before `EnsurePool` with an empty slot map, so
// no slot ever survived a restart to disagree about. That is fixed in the orchestrator;
// this file covers the api's half, which has to cope regardless, because two durable
// records of one pool will drift again.
//
// ## What these tests assert
//
// That a refused slot is dropped rather than released, that a different slot is tried,
// that the pool is re-learned so the replacement row exists, and that exhausting the
// attempts produces an honest 409 instead of a 502.

import { beforeEach, describe, expect, it } from "vitest";

import { Db } from "../src/db.js";
import { OrchestratorClient } from "../src/orchestrator-client.js";
import { PoolBinder } from "../src/sweep.js";

const SECRET = "S".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const EXPIRES = new Date("2030-01-01T00:00:00Z");

let db: Db;

const logs: Array<{ level: string; message: string; fields: Record<string, unknown> }> = [];

function seedSession(): void {
  db.createSession({
    guid: GUID,
    secretHash: SECRET,
    csrfKey: "C".repeat(43),
    now: Date.now(),
    expiresAt: EXPIRES.getTime(),
  });
}

/**
 * An orchestrator that only knows `liveSlots`.
 *
 * Anything the api asks for outside that set is refused with a 409 — the orchestrator's
 * real answer for both "unknown slot" and "slot state does not allow this", because the
 * api cannot tell them apart and must treat them the same way.
 */
function orchestratorStub(opts: {
  liveSlots: string[];
  claimAttempts: string[];
  /**
   * Report the slots in `/stats` and then refuse every claim.
   *
   * The genuinely unresolvable disagreement: the api learns a slot that the
   * orchestrator itself named, and is then told it cannot have it. No amount of
   * dropping rows or re-learning helps, which is exactly why the retry is bounded.
   * Without this, "the orchestrator has no slots at all" would be the only failure
   * reachable, and that case is honest to report as exhaustion.
   */
  stubborn?: boolean;
  /**
   * The slots the orchestrator reports as claimable. When omitted, the stub
   * omits the field entirely (rolling-deploy shape).
   */
  claimableSlots?: readonly string[];
}): OrchestratorClient {
  return new OrchestratorClient({
    baseUrl: "http://orchestrator:9100",
    secret: "B".repeat(43),
    fetchImpl: (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.pathname === "/stats") {
        return new Response(
          JSON.stringify({
            size: opts.liveSlots.length,
            byState: Object.fromEntries(opts.liveSlots.map((s) => [s, 1])),
            runnerTtlSeconds: 300,
            slotIds: opts.liveSlots,
            ...(opts.claimableSlots === undefined
              ? {}
              : { claimableSlotIds: opts.claimableSlots }),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.pathname === "/claim") {
        const body = JSON.parse(
          init?.body instanceof Uint8Array ? new TextDecoder().decode(init.body) : "{}",
        ) as { slotId?: string };
        const asked = body.slotId ?? "";
        opts.claimAttempts.push(asked);
        if (opts.stubborn === true || !opts.liveSlots.includes(asked)) {
          // The real body for both 409 paths.
          return new Response(JSON.stringify({ error: "unknown slot" }), {
            status: 409,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(
          JSON.stringify({
            slotId: asked,
            containerId: `ctr-${asked}`,
            runnerUrl: `http://msout-runner-${asked}:3100`,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response("{}", { status: 404 });
    }) as typeof fetch,
  });
}

function binder(client: OrchestratorClient): PoolBinder {
  return new PoolBinder({
    db,
    orchestrator: client,
    sse: { emit: () => {}, drop: () => {} } as never,
    log: {
      info: (message: string, fields: Record<string, unknown> = {}) =>
        logs.push({ level: "info", message, fields }),
      warn: (message: string, fields: Record<string, unknown> = {}) =>
        logs.push({ level: "warn", message, fields }),
    },
    now: () => Date.now(),
  });
}

function rows(): Array<{
  id: string;
  status: string;
  session_guid: string | null;
  runner_url: string | null;
}> {
  return db.all(`SELECT id, status, session_guid, runner_url FROM runners`);
}

function sessionRow(): { runner_id: string | null } | undefined {
  return db.get<{ runner_id: string | null }>(
    `SELECT runner_id FROM sessions WHERE guid = ?`,
    GUID,
  );
}

beforeEach(() => {
  db = new Db(":memory:");
  seedSession();
  logs.length = 0;
});

// ## A note on determinism, which cost one rewrite of this file
//
// `claimRunner` picks with `ORDER BY RANDOM()`. So a test that registers two rows and
// lets the stub refuse one of them passes or fails **depending on the pick** — it is a
// coin flip, and a green run proves nothing. The first version of these tests did
// exactly that.
//
// Every case here therefore registers only the **stale** row and lets the orchestrator
// name the real one. The first attempt is then certain to be refused, and the retry is
// certain to see a row that was learned from the orchestrator rather than remembered.
// The production host had both rows present; the disagreement between them is covered
// by `claim-slot.test.ts`, which forces it with a stub that answers a different slot
// than the one asked for.

describe("a slot the orchestrator does not have", () => {
  it("recovers on a second attempt rather than failing the login", async () => {
    db.registerRunner("slot-2", "", "idle");

    const attempts: string[] = [];
    const result = await binder(orchestratorStub({ liveSlots: ["slot-1"], claimAttempts: attempts }))
      .claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.runnerId).toBe("slot-1");
    // The first attempt really was made, and really was refused.
    expect(attempts[0]).toBe("slot-2");
  });

  it("drops the refused row instead of releasing it", async () => {
    // Release would leave the row `idle` and claimable, so `ORDER BY RANDOM()` would
    // offer it again on the next login — forever. The api would burn a session against
    // the same bad row every time, which is exactly what the user experienced.
    db.registerRunner("slot-2", "", "idle");

    const attempts: string[] = [];
    await binder(orchestratorStub({ liveSlots: ["slot-1"], claimAttempts: attempts })).claimForLogin(
      db.getSession(GUID)!,
    );

    const ids = rows().map((r) => r.id).sort();
    // The stale row is **gone**, not idle. The live one arrived from `/stats`.
    expect(ids).toEqual(["slot-1"]);
    expect(ids).not.toContain("slot-2");
  });

  it("never binds the session to a slot that was refused", async () => {
    db.registerRunner("slot-2", "", "idle");

    const attempts: string[] = [];
    await binder(orchestratorStub({ liveSlots: ["slot-1"], claimAttempts: attempts })).claimForLogin(
      db.getSession(GUID)!,
    );

    // The refused slot is `slot-2`; the session must not end up on it, and must be on
    // the one the orchestrator reported.
    expect(sessionRow()?.runner_id).toBe("slot-1");
    expect(sessionRow()?.runner_id).not.toBe("slot-2");
    expect(attempts).toContain("slot-2");
  });

  it("uses the slot the orchestrator actually reports", async () => {
    db.registerRunner("slot-2", "", "idle");

    const attempts: string[] = [];
    const result = await binder(orchestratorStub({ liveSlots: ["slot-7"], claimAttempts: attempts }))
      .claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Not merely "some slot" — the one the orchestrator says exists. A retry that
    // succeeded by accident on a slot the orchestrator had refused would leave the
    // session bound to nothing.
    expect(result.runnerId).toBe("slot-7");
    expect(attempts).toContain("slot-7");
    expect(rows().find((r) => r.id === "slot-7")?.runner_url).toBe(
      "http://msout-runner-slot-7:3100",
    );
  });

  it("says it re-learned the pool, so the recovery is visible", async () => {
    db.registerRunner("slot-2", "", "idle");

    const attempts: string[] = [];
    await binder(orchestratorStub({ liveSlots: ["slot-1"], claimAttempts: attempts })).claimForLogin(
      db.getSession(GUID)!,
    );

    const learned = logs.find((l) => l.message.includes("re-learned"));
    expect(learned).toBeDefined();
    expect(learned?.fields.added).toBe(1);
  });
});

describe("when the peer cannot be reconciled with", () => {
  // A slot it reports and then refuses: the api learns `slot-1` from `/stats`, asks for
  // it, and is told no. Nothing the api can do helps, so the retry must stop and say so
  // rather than spin.
  function stubbornPeer(): { attempts: string[]; binder: PoolBinder } {
    const attempts: string[] = [];
    return {
      attempts,
      binder: binder(orchestratorStub({ liveSlots: ["slot-1"], claimAttempts: attempts, stubborn: true })),
    };
  }

  it("gives up with a conflict, not a lie about unreachability", async () => {
    db.registerRunner("slot-2", "", "idle");
    const { binder: b } = stubbornPeer();

    const result = await b.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    // Not `orchestrator-unreachable`: the orchestrator answered, clearly, and the
    // answer was "no". Calling that a transport failure is what told the user to retry
    // a login that could not succeed.
    expect(result.reason).toBe("slot-conflict");
  });

  it("stops after a bounded number of attempts", async () => {
    // A peer this process cannot agree with must produce an error a human can see, not
    // a request that never returns.
    db.registerRunner("slot-2", "", "idle");
    const { attempts, binder: b } = stubbornPeer();

    await b.claimForLogin(db.getSession(GUID)!);

    expect(attempts.length).toBeGreaterThan(0);
    expect(attempts.length).toBeLessThanOrEqual(3);
  });

  it("says so in the log, naming the session", async () => {
    db.registerRunner("slot-2", "", "idle");
    const { binder: b } = stubbornPeer();

    await b.claimForLogin(db.getSession(GUID)!);

    const gaveUp = logs.find((l) => l.message.includes("giving up"));
    expect(gaveUp).toBeDefined();
    expect(gaveUp?.level).toBe("warn");
    expect(gaveUp?.fields.session).toBe(GUID);
  });

  it("leaves no session bound to a refused slot", async () => {
    db.registerRunner("slot-2", "", "idle");
    const { binder: b } = stubbornPeer();

    await b.claimForLogin(db.getSession(GUID)!);

    expect(sessionRow()?.runner_id).toBeNull();
    expect(rows().filter((r) => r.session_guid === GUID)).toHaveLength(0);
  });
});

// An empty pool is exhaustion, not divergence, and must keep saying so: the
// orchestrator reported no slots at all, so "every session is busy" is the honest
// answer and 503 is the right code.
describe("an orchestrator with no slots at all", () => {
  it("reports exhaustion rather than pretending the two sides disagree", async () => {
    db.registerRunner("slot-2", "", "idle");

    const result = await binder(orchestratorStub({ liveSlots: [], claimAttempts: [] })).claimForLogin(
      db.getSession(GUID)!,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("pool-exhausted");
  });
});

describe("a healthy pool is not disturbed", () => {
  it("claims the first slot it is offered, with no retry", async () => {
    // The retry must cost nothing on the happy path.
    db.registerRunner("slot-1", "", "idle");

    const attempts: string[] = [];
    const statsCalls: number[] = [];
    const client = new OrchestratorClient({
      baseUrl: "http://orchestrator:9100",
      secret: "B".repeat(43),
      fetchImpl: (async (input: string | URL | Request, init?: RequestInit) => {
        const url = new URL(String(input));
        if (url.pathname === "/stats") {
          statsCalls.push(1);
          // No `slotRemainingSec`: the orchestrator this stub stands for does not
          // report one, so the claim's floor check fails open. That is the case this
          // test is about — a claim that proceeds — and the floor has its own tests.
          return new Response(JSON.stringify({ size: 1, byState: {}, slotIds: ["slot-1"] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        const body = JSON.parse(
          init?.body instanceof Uint8Array ? new TextDecoder().decode(init.body) : "{}",
        ) as { slotId?: string };
        attempts.push(body.slotId ?? "");
        return new Response(
          JSON.stringify({
            slotId: body.slotId,
            containerId: "ctr1",
            runnerUrl: `http://msout-runner-${body.slotId}:3100`,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }) as typeof fetch,
    });

    const result = await binder(client).claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    expect(attempts).toHaveLength(1);
    // Exactly one `/stats`, and it is the claim's floor check — **not** the retry's
    // re-learn. This used to be `toHaveLength(0)`, which asserted that a healthy
    // claim touches `/stats` not at all; the floor check made that untrue, and the
    // number that still matters is that the re-learn does not happen: one stats
    // call, not two. A second one would be the retry path running on a claim that
    // needed no retry.
    expect(statsCalls).toHaveLength(1);
  });
});
describe("a pool with a non-claimable slot", () => {
  // T-6: a login against a pool with a non-claimable slot never names that slot
  // to /claim. The orchestrator reports slot-1 as claimable and slot-2 as not.
  // The api seeds its pool snapshot from the orchestrator's /stats, and the draw
  // excludes slot-2. Asking forty times over is how the property is asked when
  // it cannot be assumed.
  it("never offers the non-claimable slot", async () => {
    db.registerRunner("slot-1", "", "idle");
    db.registerRunner("slot-2", "", "idle");
    const claimAttempts: string[] = [];
    const client = orchestratorStub({
      liveSlots: ["slot-1", "slot-2"],
      claimAttempts,
      claimableSlots: ["slot-1"],
    });
    const b = new PoolBinder({
      db,
      orchestrator: client,
      sse: { emit: () => {}, drop: () => {} } as never,
      log: {
        info: (m: string, f?: Record<string, unknown>) =>
          logs.push({ level: "info", message: m, fields: f ?? {} }),
        warn: (m: string, f?: Record<string, unknown>) =>
          logs.push({ level: "warn", message: m, fields: f ?? {} }),
      },
      now: () => Date.now(),
    });
    const stats = await client.stats();
    if (stats.ok) b.poolUpdate(stats.value);

    for (let i = 0; i < 40; i++) {
      const sessionGuid = `session-${i}`;
      db.createSession({
        guid: sessionGuid,
        secretHash: SECRET,
        csrfKey: "C".repeat(43),
        now: Date.now(),
        expiresAt: EXPIRES.getTime(),
      });
      await b.claimForLogin(db.getSession(sessionGuid)!);
    }

    // slot-2 is never offered, because the orchestrator said it is not claimable.
    expect(claimAttempts.filter((s) => s === "slot-2")).toEqual([]);
  });
});
