// The api's slot and the orchestrator's slot were chosen independently.
//
// ## Why this file exists
//
// Found on a real host immediately after the first successful login, by comparing the
// three views of the same fact:
//
//     runners: [{"id":"slot-1","status":"active",
//                "runner_url":"http://msout-runner-slot-2:3100"}]
//     /stats : {"size":1,"byState":{"bound":1},"slotIds":["slot-2"]}
//
// `slot-1` recorded as **active**, carrying `slot-2`'s address. No slot-1 container
// existed anywhere. Nothing failed: the login worked, the runner was healthy, and the
// api believed it held slot-1.
//
// The cause is two independent random picks. `claimRunner` takes a SQLite row with
// `ORDER BY RANDOM()`, and `Pool.Claim` takes an idle slot with its own `rnd`. Each is
// correct alone; together they are a coin toss.
//
// ## Why it matters beyond tidiness
//
// The SQLite claim exists so that a later `release` or `recycle` is *guaranteed* to find
// that slot idle again. If the claim locked a row that is not the slot holding the
// container, it is not a lock — it is a coin toss with a transaction around it. So:
//
//   - the api **names** the slot it claimed, and
//   - it records **the orchestrator's answer**, not its own guess
//
// The second is what makes the first safe to add rather than merely tidy: if an older
// orchestrator ignores the field and picks its own slot, what gets recorded is still
// correct, and the disagreement is *visible* rather than silent.
//
// ## What these tests assert
//
// That after a claim, the slot in `sessions.runner_id` is the slot the orchestrator
// reports, and the slot's recorded `runner_url` belongs to it. Those two facts together
// are what every later `release` depends on.

import { beforeEach, describe, expect, it } from "vitest";

import { Db } from "../src/db.js";
import { OrchestratorClient } from "../src/orchestrator-client.js";
import { PoolBinder } from "../src/sweep.js";

const SECRET = "S".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const EXPIRES = new Date("2030-01-01T00:00:00Z");

let db: Db;

/** Two idle slots, as the orchestrator reports them. */
const SLOT_IDS = ["slot-1", "slot-2"];

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
 * An orchestrator that answers `/claim` with whatever slot the test says, and records
 * what it was *asked* for.
 *
 * `answerWith` exists so a test can model an orchestrator that ignored the field —
 * which is a real state during a rolling deploy, and the case where recording the
 * answer rather than the guess is what keeps the database correct.
 */
function orchestratorStub(opts: {
  /**
   * The slot to answer with. `"other"` means *deliberately a different slot than the
   * one asked for* — which is how the disagreement is made deterministic.
   *
   * It has to be deliberate. `claimRunner` picks with `ORDER BY RANDOM()`, so a stub
   * that simply answers a fixed slot agrees with the api roughly half the time, and a
   * test written against that **passes without the fix about half the time**. The
   * first version of the divergence test did exactly that and I only found out because
   * removing the second write left it green.
   */
  answerWith: string | "other";
  requests: Array<Record<string, unknown>>;
}): OrchestratorClient {
  return new OrchestratorClient({
    baseUrl: "http://orchestrator:9100",
    secret: "B".repeat(43),
    fetchImpl: (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.pathname === "/stats") {
        return new Response(
          JSON.stringify({
            size: SLOT_IDS.length,
            byState: { idle: SLOT_IDS.length },
            runnerTtlSeconds: 300,
            slotIds: SLOT_IDS,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.pathname === "/claim") {
        const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
        opts.requests.push(body);
        const asked = typeof body.slotId === "string" ? body.slotId : SLOT_IDS[0]!;
        const answered =
          opts.answerWith === "other"
            ? SLOT_IDS.find((id) => id !== asked) ?? SLOT_IDS[0]!
            : opts.answerWith;
        return new Response(
          JSON.stringify({
            slotId: answered,
            containerId: `ctr-${answered}`,
            runnerUrl: `http://msout-runner-${answered}:3100`,
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
    log: { info: () => {}, warn: () => {} },
    now: () => Date.now(),
  });
}

function row(guid = GUID): { runner_id: string | null; auth_state: string } | undefined {
  return db.get<{ runner_id: string | null; auth_state: string }>(
    `SELECT runner_id, auth_state FROM sessions WHERE guid = ?`,
    guid,
  );
}

function runnerRow(id: string): { status: string; runner_url: string | null } | undefined {
  return db.get<{ status: string; runner_url: string | null }>(
    `SELECT status, runner_url FROM runners WHERE id = ?`,
    id,
  );
}

beforeEach(() => {
  db = new Db(":memory:");
  seedSession();
  for (const id of SLOT_IDS) db.registerRunner(id, "", "idle");
});

describe("naming the slot", () => {
  it("sends the slot it claimed, rather than letting the orchestrator choose", async () => {
    const requests: Array<Record<string, unknown>> = [];
    const result = await binder(orchestratorStub({ answerWith: "slot-1", requests })).claimForLogin(
      db.getSession(GUID)!,
    );

    expect(result.ok).toBe(true);
    expect(requests[0]?.slotId).toBeDefined();
    // The value sent must be a slot this process actually holds a claim on, or the
    // transaction was locking nothing.
    expect(SLOT_IDS).toContain(requests[0]?.slotId as string);
  });

  it("records the slot the orchestrator reports", async () => {
    const result = await binder(
      orchestratorStub({ answerWith: "slot-1", requests: [] }),
    ).claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    expect(row()?.runner_id).toBe("slot-1");
  });

  it("records a matching runner_url, so release can address the slot it released", async () => {
    await binder(orchestratorStub({ answerWith: "slot-2", requests: [] })).claimForLogin(
      db.getSession(GUID)!,
    );

    // The mismatch this whole file is about: `slot-2` bound, but `slot-1` carrying
    // slot-2's address.
    expect(runnerRow("slot-2")?.runner_url).toBe("http://msout-runner-slot-2:3100");
    expect(runnerRow("slot-1")?.runner_url).toBeNull();
  });

  it("binds the session and the runner row to the same slot", async () => {
    await binder(orchestratorStub({ answerWith: "slot-2", requests: [] })).claimForLogin(
      db.getSession(GUID)!,
    );

    const bound = row()?.runner_id;
    expect(bound).toBe("slot-2");
    expect(runnerRow(bound!)?.status).toBe("active");
  });
});

describe("an orchestrator that ignored the requested slot", () => {
  // A real state during a rolling deploy: the field is unknown, so the pool picks.
  // Recording the *answer* keeps the database correct; recording our guess would not.
  it("records the slot the orchestrator chose, not the one claimed", async () => {
    const result = await binder(
      orchestratorStub({ answerWith: "other", requests: [] }),
    ).claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Whatever the claim landed on, it is the slot that got the container.
    const answered = `http://msout-runner-${result.runnerId}:3100`;
    expect(row()?.runner_id).toBe(result.runnerId);
    expect(runnerRow(result.runnerId)?.runner_url).toBe(answered);
  });

  it("gives the wrongly-claimed row back, so capacity is not lost", async () => {
    // The api claimed one row and the orchestrator used another. The claimed row holds
    // nothing — leaving it `claimed` is capacity the pool believes it has lost, which
    // is how a pool drains itself one login at a time.
    const requests: Array<Record<string, unknown>> = [];
    await binder(orchestratorStub({ answerWith: "other", requests })).claimForLogin(
      db.getSession(GUID)!,
    );

    const asked = requests[0]?.slotId as string;
    // `active`, not `claimed`: the slot in use is promoted. What matters is that
    // **exactly one** row is in use and it is the one holding the container.
    const inUse = db
      .all<{ id: string; status: string; session_guid: string | null }>(
        `SELECT id, status, session_guid FROM runners`,
      )
      .filter((r) => r.status === "active");

    expect(inUse).toHaveLength(1);
    expect(inUse[0]?.id).not.toBe(asked);
    expect(runnerRow(asked)?.status).not.toBe("active");
    expect(runnerRow(asked)?.status).not.toBe("claimed");
  });

  // The gap the first version of this fix left: `claimRunner` had put `session_guid`
  // on the *claimed* row, so the row that actually got the container stayed idle and
  // unclaimed — and the pool would hand it to a second session while this one was
  // still using it.
  it("claims the slot the orchestrator used, not only the one it asked for", async () => {
    const requests: Array<Record<string, unknown>> = [];
    await binder(orchestratorStub({ answerWith: "other", requests })).claimForLogin(
      db.getSession(GUID)!,
    );

    const rows = db.all<{ id: string; status: string; session_guid: string | null }>(
      `SELECT id, status, session_guid FROM runners`,
    );
    const bound = rows.filter((r) => r.session_guid === GUID);

    // Exactly one row may name this session, and it must be the one in use.
    expect(bound).toHaveLength(1);
    expect(bound[0]?.id).not.toBe(requests[0]?.slotId as string);
    expect(bound[0]?.status).toBe("active");
  });

  it("still leaves one usable slot, because the wrong row was released", async () => {
    await binder(orchestratorStub({ answerWith: "other", requests: [] })).claimForLogin(
      db.getSession(GUID)!,
    );

    const idle = db
      .all<{ status: string }>(`SELECT status FROM runners`)
      .filter((r) => r.status === "idle");
    expect(idle.length).toBeGreaterThan(0);
  });
});

describe("the property the whole thing rests on", () => {
  it("the recorded runner_url always belongs to the session's own slot", async () => {
    // Stated as the invariant rather than as one example, because every earlier test
    // was a single instance of it and the bug was precisely that nobody checked all
    // of them at once.
    for (const answered of SLOT_IDS) {
      db = new Db(":memory:");
      seedSession();
      for (const id of SLOT_IDS) db.registerRunner(id, "", "idle");

      await binder(orchestratorStub({ answerWith: answered, requests: [] })).claimForLogin(
        db.getSession(GUID)!,
      );

      const bound = row()?.runner_id;
      expect(bound).toBe(answered);
      const url = runnerRow(bound!)?.runner_url;
      // The address must name the slot it belongs to — it is derived from the slot id
      // by the orchestrator, so a mismatch means the two sides disagree about which
      // slot exists.
      expect(url).toBe(`http://msout-runner-${answered}:3100`);
    }
  });
});