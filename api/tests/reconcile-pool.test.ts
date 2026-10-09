/**
 * `reconcile` — the api's half of boot reconciliation.
 *
 * ## The bug this file exists for
 *
 * The reconciler was called with **the api's own runner row ids** as the set of
 * ids that are live:
 *
 *     db.reconcileRunners(new Set(rows.map((r) => r.id)), now)
 *
 * Every row it was asked to check was therefore, by construction, in the set it was
 * handed — so it could never delete anything. It was a no-op that read like a
 * reconciliation, and `reconcileRunners`'s own doc comment ("removes runner rows
 * whose container the orchestrator no longer has") described behaviour the caller
 * had disabled.
 *
 * `syncPool` upserts and never removes, and the orchestrator renumbers slots across
 * restarts, so the table grew a phantom row per slot the orchestrator had ever
 * used: **39 rows against 4 real slots** on the live host. `claimRunner` selects by
 * `ORDER BY RANDOM()`, so ~9 times in 10 a login offered a slot the orchestrator had
 * never heard of and the user got
 * `409 the service's view of its runner pool is out of date`.
 *
 * ## Why these assert the row count, not the return value
 *
 * `reconciled: true` was returned by the broken version too. The only observable
 * difference is which rows survive, so the assertions read the table.
 */

import { describe, expect, it } from "vitest";

import { Db } from "../src/db.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";
import { reconcile } from "../src/sweep.js";
import type { OrchestratorApi } from "../src/orchestrator-client.js";

const NOW = 1_700_000_000_000;
const SESSION = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

/** stats answers with a pool of `slotIds`, or with no ids at all. */
function statsOrchestrator(slotIds?: readonly string[]): OrchestratorApi {
  return {
    stats: async () =>
      slotIds === undefined
        ? { ok: true, value: { size: 4, byState: {}, runnerTtlSeconds: 300 } }
        : { ok: true, value: { size: slotIds.length, byState: {}, runnerTtlSeconds: 300, slotIds } },
    // Unused by this path; present because `OrchestratorApi` is closed.
    claim: async () => ({ ok: false, error: { kind: "unexpected", status: 500, body: "" } }),
    release: async () => ({ ok: false, error: { kind: "unexpected", status: 500, body: "" } }),
    recycle: async () => ({ ok: false, error: { kind: "unexpected", status: 500, body: "" } }),
    remove: async () => ({ ok: false, error: { kind: "unexpected", status: 500, body: "" } }),
    stat: async () => ({ ok: false, error: { kind: "unexpected", status: 500, body: "" } }),
    healthz: async () => ({ ok: false, error: { kind: "unexpected", status: 500, body: "" } }),
    finalize: async () => ({ ok: false, error: { kind: "conflict", status: 409 } }),
  } as OrchestratorApi;
}

function dbWithSlots(ids: readonly string[]): Db {
  const db = new Db(":memory:");
  for (const id of ids) db.registerRunner(id, "", "idle");
  return db;
}

function slotIds(db: Db): string[] {
  return db
    .all<{ id: string }>(`SELECT id FROM runners ORDER BY id`)
    .map((r) => r.id);
}

describe("reconcile", () => {
  it("deletes runner rows for slots the orchestrator does not have", async () => {
    // The live host's shape: a table that has accumulated every slot the
    // orchestrator has ever used, against a pool of four.
    const db = dbWithSlots([
      "slot-1", "slot-2", "slot-3", "slot-36", "slot-37", "slot-38", "slot-39",
    ]);
    const before = slotIds(db).length;
    expect(before).toBe(7);

    await reconcile({ db, orchestrator: statsOrchestrator(["slot-36", "slot-37", "slot-38", "slot-39"]) , now: () => NOW } as never);

    // The three that survive are the ones the orchestrator actually has. The
    // previous version returned `reconciled: true` here and changed nothing.
    expect(slotIds(db)).toEqual(["slot-36", "slot-37", "slot-38", "slot-39"]);
    db.close();
  });

  it("keeps every slot when the orchestrator agrees with the table", async () => {
    const db = dbWithSlots(["slot-1", "slot-2"]);

    await reconcile({ db, orchestrator: statsOrchestrator(["slot-1", "slot-2"]) , now: () => NOW } as never);

    expect(slotIds(db)).toEqual(["slot-1", "slot-2"]);
    db.close();
  });

  it("learns a slot it has never seen before reconciling, rather than deleting it", async () => {
    // Order matters: if `reconcileRunners` ran first with the orchestrator's ids,
    // a slot the api had never heard of would simply be absent, and a slot it had
    // heard of but the orchestrator had not would go — which is right — but a
    // session bound to a brand-new slot would be unbound for no reason. Learning
    // first is what keeps "the orchestrator has a slot" from looking like "the api
    // is wrong about a slot".
    const db = dbWithSlots(["slot-36"]);

    await reconcile({ db, orchestrator: statsOrchestrator(["slot-36", "slot-37"]) , now: () => NOW } as never);

    expect(slotIds(db)).toEqual(["slot-36", "slot-37"]);
    db.close();
  });

  it("rebinds a session whose runner row is gone", async () => {
    const db = dbWithSlots(["slot-1", "slot-36"]);
    db.run(
      `INSERT INTO sessions
         (guid, secret_hash, csrf_key, runner_id, state, auth_state,
          created_at, expires_at, idle_expires_at, last_activity_at)
       VALUES (?, ?, ?, 'slot-1', 'authenticated', 'valid', ?, ?, NULL, ?)`,
      SESSION,
      hashSecret("A".repeat(43)),
      generateCsrfKey(),
      NOW,
      NOW + 43_200_000,
      NOW,
    );

    // The orchestrator only has slot-36, so slot-1 goes and the session must be
    // told to re-claim rather than left pointing at a slot that no longer exists.
    await reconcile({ db, orchestrator: statsOrchestrator(["slot-36"]) , now: () => NOW } as never);

    expect(slotIds(db)).toEqual(["slot-36"]);
    const session = db.getSession(SESSION);
    expect(session?.runner_id).toBeNull();
    db.close();
  });

  it("deletes nothing when the orchestrator reports no slot ids", async () => {
    // An api can briefly talk to an orchestrator predating `slotIds`. Acting on a
    // **count** alone would destroy every session binding on the orchestrator's
    // say-so; the old safe behaviour is the right fallback and must be kept.
    const db = dbWithSlots(["slot-1", "slot-2", "slot-3"]);

    const result = await reconcile({ db, orchestrator: statsOrchestrator() , now: () => NOW } as never);

    expect(slotIds(db)).toEqual(["slot-1", "slot-2", "slot-3"]);
    // And it says so, rather than claiming a reconciliation that did not happen.
    expect(result.reconciled).toBe(false);
    db.close();
  });

  it("deletes nothing when the orchestrator is unreachable", async () => {
    const db = dbWithSlots(["slot-1", "slot-2"]);
    const unreachable = {
      ...statsOrchestrator(["slot-1"]),
      stats: async () => ({ ok: false as const, error: { kind: "unreachable" as const, cause: "x" } }),
    };

    const result = await reconcile({ db, orchestrator: unreachable , now: () => NOW } as never);

    // "Unreachable" must never be read as "no runners exist". That would delete
    // every session binding on a transient network failure.
    expect(slotIds(db)).toEqual(["slot-1", "slot-2"]);
    expect(result.reconciled).toBe(false);
    db.close();
  });
});