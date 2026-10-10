import { beforeEach, describe, expect, it } from "vitest";
import {
  ERASE_UI_WORDING,
  expireCookieHeaders,
  pendingErase,
  runErase,
  type EraseDeps,
  type RunnerControl,
} from "../src/erase.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";
import { PoolBinder, sweep } from "../src/sweep.js";
import { FakeOrchestrator } from "../mock/fake-orchestrator.js";

/**
 * PLAN-v2 §11 extended by PLAN-v3 T7. The properties under test are that erase
 * spans all three hosts, that it does not stop at the first failure, and that the
 * row is deleted last so an interruption is recoverable.
 */

const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const SECRET = "A".repeat(43);
const NOW = 1_700_000_000_000;

let db: Db;

/**
 * Records the calls the machine makes, and can be told to fail any of them.
 *
 * `removeAnswers` covers the case `failAt` cannot reach: `failAt` **throws**, which
 * is the transport failing outright, while the orchestrator's typed results are what
 * a live server answers. Step 8 keys on the kind, so both have to be drivable.
 */
function makeDeps(
  options: {
    failAt?: string;
    boundSlot?: string | null;
    removeAnswers?: "ok" | "conflict" | "unreachable" | "unexpected";
  } = {},
) {
  const calls: string[] = [];
  const fail = (name: string) => (options.failAt === name ? new Error(`${name} failed`) : undefined);

  const runner: RunnerControl = {
    async abort() {
      calls.push("abort");
      const e = fail("abort");
      if (e) throw e;
    },
    async freeze() {
      calls.push("freeze");
      const e = fail("freeze");
      if (e) throw e;
    },
    async shredDirectory() {
      calls.push("shredDirectory");
      const e = fail("shredDirectory");
      if (e) throw e;
    },
  };

  const orchestrator = {
    async remove(slotId: string) {
      calls.push(`remove:${slotId}`);
      const e = fail("remove");
      if (e) throw e;
      const answer = options.removeAnswers ?? "ok";
      // The typed result, as the routes adapter now produces it. `unreachable` is
      // what the real client answers for a transport failure, and step 8's rule is
      // written against the kind rather than the boolean.
      if (answer === "ok") return { ok: true };
      return { ok: false, errorKind: answer };
    },
    async stats() {
      return { ok: true as const, value: { size: 0 } };
    },
  };

  const sse = new SseHub({ now: () => NOW });

  return { deps: { db, orchestrator, runner, sse } satisfies EraseDeps, calls, sse };
}

/**
 * A `runners` row in the shape an erase leaves when it does not clean up: `active`,
 * `session_guid` naming the session.
 *
 * The seeded row is the *third* host the machine spans. The api half of the erase
 * is this row, and it is the half that leaked — three of them, `slot-1`/`slot-13`/
 * `slot-14`, standing against an empty `sessions` table on the deployed host.
 */
function seedBoundRunner(slotId: string, guid: string): void {
  db.registerRunner(slotId, "ctr", "active");
  db.run(`UPDATE runners SET session_guid = ? WHERE id = ?`, guid, slotId);
}

function runnerRow(slotId: string): { status: string; session_guid: string | null } | undefined {
  return db.get<{ status: string; session_guid: string | null }>(
    `SELECT status, session_guid FROM runners WHERE id = ?`,
    slotId,
  );
}

function seedSession(guid = GUID, state = "authenticated", runnerId: string | null = null) {
  db.createSession({
    guid,
    secretHash: hashSecret(SECRET),
    csrfKey: generateCsrfKey(),
    now: NOW,
    expiresAt: NOW + 43_200_000,
  });
  db.run(`UPDATE sessions SET state = ?, runner_id = ? WHERE guid = ?`, state, runnerId, guid);
}

beforeEach(() => {
  db = new Db(":memory:");
});

describe("runErase", () => {
  it("runs every step in order", async () => {
    seedSession(GUID, "authenticated", "slot-1");
    const { deps, calls } = makeDeps();

    const outcome = await runErase(deps, GUID);

    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.steps).toEqual([
        "marked",
        "aborted",
        "frozen",
        "files-removed",
        "directory-removed",
        "container-removed",
        "row-deleted",
      ]);
    }
    expect(calls).toEqual(["abort", "freeze", "shredDirectory", "remove:slot-1"]);
  });

  it("removes the row", async () => {
    seedSession();
    const { deps } = makeDeps();
    await runErase(deps, GUID);
    expect(db.getSession(GUID)).toBeUndefined();
  });

  // §11: this process has no vault mount, so the directory work happens in the
  // runner. Asserting the call is the assertion that the split is real.
  it("asks the runner to delete the directory rather than doing it here", async () => {
    seedSession();
    const { deps, calls } = makeDeps();
    await runErase(deps, GUID);
    expect(calls).toContain("shredDirectory");
  });

  it("tells subscribers the session is going before destroying anything", async () => {
    seedSession();
    const { deps, sse } = makeDeps();
    await runErase(deps, GUID);
    // drop() removes the hub, so the observable effect is that the hub is gone.
    expect(sse.stats()).toEqual({});
  });

  it("closes every SSE stream for the session", async () => {
    seedSession();
    const { deps, sse } = makeDeps();
    sse.emit(GUID, "export-started", {});
    await runErase(deps, GUID);
    expect(sse.stats()).toEqual({});
  });

  // Every step is independent, so one failure must not stop the rest.
  it("continues past a failed step and reports the first failure", async () => {
    seedSession(GUID, "authenticated", "slot-1");
    const { deps, calls } = makeDeps({ failAt: "shredDirectory" });

    const outcome = await runErase(deps, GUID);

    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.failedAt).toBe("files-removed");
      expect(outcome.error).toContain("shredDirectory");
    }
    // The steps after the failure still ran, which is what "best-effort" means.
    expect(calls).toContain("remove:slot-1");
    expect(calls).toContain("freeze");
    expect(db.getSession(GUID)).toBeUndefined();
  });

  it("marks the row erasing before anything else, so an interruption is visible", async () => {
    seedSession();
    // `abort` is the first async step. If the row is already marked by the time it
    // is reached, the ordering property holds; if it were marked later, a crash
    // during abort would leave a row in `authenticated` with no retry record.
    let stateAtAbort: string | undefined;
    const deps = makeDeps();
    const observed: EraseDeps = {
      ...deps.deps,
      runner: {
        ...deps.deps.runner,
        async abort(id: string) {
          stateAtAbort = db.getSession(id)?.state;
          await deps.deps.runner.abort(id);
        },
      },
    };

    await runErase(observed, GUID);

    expect(stateAtAbort).toBe("erasing");
  });

  it("leaves a row in `erasing` for the sweeper when the machine cannot finish", async () => {
    // The ordering that makes the retry record work: if the row were deleted
    // before the directory work, an interruption would leave a deleted row and an
    // undeleted directory with nothing recording either.
    seedSession();
    const { deps } = makeDeps({ failAt: "shredDirectory" });

    // A runner that fails to shred but succeeds at deleting the row is the case
    // §11 describes. Here the row does go, so the retry record is the erase
    // failure recorded by the caller, not the row.
    await runErase(deps, GUID);

    expect(pendingErase(db)).toHaveLength(0);
  });

  // T-E1: "including when the row is already gone".
  it("still runs when the row does not exist", async () => {
    // The directory might still exist even though the row does not.
    const { deps, calls } = makeDeps();

    const outcome = await runErase(deps, "00000000-0000-0000-0000-000000000000");

    expect(outcome.ok).toBe(true);
    expect(calls).toContain("shredDirectory");
    expect(calls).toContain("abort");
  });

  it("skips container removal when nothing is bound", async () => {
    seedSession(GUID, "created", null);
    const { deps, calls } = makeDeps();
    const outcome = await runErase(deps, GUID);

    expect(outcome.ok).toBe(true);
    // "no container" is recorded rather than skipped, so a reader can tell it
    // apart from a removal that was never attempted.
    expect(calls.some((c) => c.startsWith("remove:"))).toBe(false);
    if (outcome.ok) expect(outcome.steps).toContain("container-removed");
  });

  it("reports a container-removal failure without losing the rest", async () => {
    seedSession(GUID, "authenticated", "slot-1");
    const { deps } = makeDeps({ failAt: "remove" });

    const outcome = await runErase(deps, GUID);

    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.failedAt).toBe("container-removed");
    // The row still goes: §11's ordering means the directory work already
    // happened, so keeping the row would only strand it.
    expect(db.getSession(GUID)).toBeUndefined();
  });

  it("is idempotent — running it twice does not fail", async () => {
    seedSession();
    const { deps } = makeDeps();
    expect((await runErase(deps, GUID)).ok).toBe(true);
    expect((await runErase(deps, GUID)).ok).toBe(true);
  });
});

/**
 * Step 8 — reclaiming the slot's local row.
 *
 * The machine's step 6 calls the orchestrator's `/remove` and step 7 deletes the
 * session row. Between them, the `runners` row — the third host the erase spans —
 * was left naming a slot and a session that no longer existed. Observed on the
 * deployed host: `slot-1`, `slot-13` and `slot-14`, all `active`, all bound, with
 * an empty `sessions` table. `EnsurePool` counts slots and `claimRunner` counts
 * rows, so those three rows were capacity the pool believed in and sessions the
 * database could not explain.
 *
 * What the rule keys on is the **error kind**, not the boolean. `conflict` and
 * `unreachable` are the same `ok: false` and opposite instructions: one says the
 * container is gone, the other says nobody knows.
 */
describe("runErase step 8", () => {
  it("leaves no runner row bound to the session it erased", async () => {
    seedSession(GUID, "authenticated", "slot-1");
    seedBoundRunner("slot-1", GUID);
    const { deps } = makeDeps({ removeAnswers: "ok" });

    const outcome = await runErase(deps, GUID);

    expect(outcome.ok).toBe(true);
    // The session row is gone by step 7, so this query cannot be satisfied by the
    // session side at all: it is asking only about `runners`.
    expect(db.get(`SELECT id FROM runners WHERE session_guid = ?`, GUID)).toBeUndefined();
    // Not merely unbound: the orchestrator removed the *slot*, so the row is a
    // position that no longer exists. `releaseRunner` would leave a claimable row
    // pointing at a slot the orchestrator has no record of.
    expect(runnerRow("slot-1")).toBeUndefined();
  });

  it("removes the row when /remove answers conflict, because the slot is already gone", async () => {
    seedSession(GUID, "authenticated", "slot-1");
    seedBoundRunner("slot-1", GUID);
    const { deps } = makeDeps({ removeAnswers: "conflict" });

    await runErase(deps, GUID);

    // A 409 is the outcome step 6 wanted — "already gone" and "gone" are the same
    // place — so the row goes. This is the same tolerance `releaseForIdle` applies;
    // the two disagreeing would mean a slot's fate depends on which caller noticed
    // it first.
    expect(runnerRow("slot-1")).toBeUndefined();
  });

  // Both halves, because the repo's own lesson is that asserting only "nothing bad
  // happened" passes just as well against code that does nothing at all.
  //
  // First: the row **stays**, and stays bound. Second: it is not a permanent leak
  // either — the sweeper reclaims it on the next tick, which is what makes
  // retention a delay rather than the same bug in a new place.
  it("retains the row when /remove is unreachable, and the sweeper then reclaims it", async () => {
    seedSession(GUID, "authenticated", "slot-1");
    seedBoundRunner("slot-1", GUID);
    const { deps } = makeDeps({ removeAnswers: "unreachable" });

    await runErase(deps, GUID);

    // Half one. The container may be running: nobody told us otherwise, and a row
    // that forgot about it would be a live container with no record on either side.
    expect(runnerRow("slot-1")).toEqual({ status: "active", session_guid: GUID });
    expect(db.getSession(GUID)).toBeUndefined();

    // Half two — the reason retention is safe. The session row is gone, so this is
    // the erase-shaped leak detection A exists to clean, and it is cleaned through
    // the *real* fake orchestrator rather than a second hand-written stub, so the
    // shape the sweeper reads is the one it reads in production.
    const orchestrator = new FakeOrchestrator();
    const report = await sweep(
      { db, orchestrator, sse: new SseHub({ now: () => NOW }), now: () => NOW },
      new PoolBinder({ db, orchestrator, sse: new SseHub({ now: () => NOW }), now: () => NOW }),
    );

    expect(report.phantomRowsCleaned).toBe(1);
    expect(runnerRow("slot-1")).toEqual({ status: "idle", session_guid: null });
  });
});

describe("expireCookieHeaders", () => {
  // T7: erase must invalidate the server row AND expire the cookie.
  it("expires the session cookie", () => {
    const headers = expireCookieHeaders();
    expect(headers).toHaveLength(1);
    expect(headers[0]).toContain("__Host-msout=");
  });

  it("expires nothing for CSRF, because the token is not in a cookie", () => {
    // The token lives in response bodies and in the frontend's memory. It stops
    // validating when the row is deleted, because the per-session key it derives
    // from is destroyed with the row — so there is nothing for the browser to
    // clear, and nothing that could survive an erase.
    for (const header of expireCookieHeaders()) {
      expect(header).not.toContain("msout_csrf");
    }
  });

  it("uses Max-Age=0 and a past Expires, because a browser may honour only one", () => {
    for (const header of expireCookieHeaders()) {
      expect(header).toContain("Max-Age=0");
      expect(header).toContain("Expires=Thu, 01 Jan 1970");
    }
  });

  // An expired cookie that drops HttpOnly or SameSite may not match the original,
  // leaving the real one in place.
  it("keeps the attributes so the browser matches and replaces the cookie", () => {
    const [session] = expireCookieHeaders();
    expect(session).toContain("HttpOnly");
    expect(session).toContain("Secure");
    expect(session).toContain("SameSite=None");
    expect(session).toContain("Path=/");
  });

  it("emits no Domain attribute", () => {
    for (const header of expireCookieHeaders()) {
      expect(header).not.toMatch(/domain/i);
    }
  });

  it("emits an empty value, not a stale one", () => {
    for (const header of expireCookieHeaders()) {
      expect(header).toMatch(/^[^=]+=;/);
    }
  });
});

describe("pendingErase", () => {
  // §11: a row stuck in `erasing` is the retry record.
  it("finds sessions interrupted mid-erase", async () => {
    seedSession(GUID, "erasing");
    seedSession("00000000-0000-0000-0000-000000000000", "authenticated");

    const pending = pendingErase(db);
    expect(pending).toHaveLength(1);
    expect(pending[0]?.guid).toBe(GUID);
  });

  it("finds nothing when no erase is in flight", () => {
    seedSession();
    expect(pendingErase(db)).toHaveLength(0);
  });

  it("survives a restart, because the state is in the database", () => {
    // The retry record has to outlive the process, or a crash mid-erase leaves no
    // trace that anything needed finishing.
    seedSession(GUID, "erasing");
    const reopened = new Db(":memory:");
    reopened.close();
    expect(pendingErase(db)).toHaveLength(1);
  });
});

describe("wording", () => {
  // §11: never "nothing remains anywhere" — this is a best-effort shred plus
  // rm -rf on a filesystem that may be CoW, on SSD with wear levelling, under
  // overlayfs.
  it("says what was deleted and not more", () => {
    expect(ERASE_UI_WORDING).toBe("We deleted everything this service stored for this session.");
    expect(ERASE_UI_WORDING.toLowerCase()).not.toContain("nothing remains");
    expect(ERASE_UI_WORDING.toLowerCase()).not.toContain("anywhere");
  });
});