import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Db, type SessionRow } from "../src/db.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";

/**
 * PLAN-v2 §2.4: SQLite in WAL mode is the only live source of truth. The tests
 * here cover the parts that are load-bearing rather than mechanical — the atomic
 * claim, the two reconcilers, and the rule that an expired session is never
 * resurrected.
 */

let db: Db;
const NOW = 1_700_000_000_000;
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

function seedSession(guid: string, overrides: Partial<SessionRow> = {}): void {
  db.run(
    `INSERT INTO sessions
       (guid, secret_hash, csrf_key, runner_id, state, auth_state,
        created_at, expires_at, idle_expires_at, last_activity_at,
        notebook, export_state, artifact_id, artifact_partial)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 0)`,
    guid,
    hashSecret("A".repeat(43)),
    generateCsrfKey(),
    overrides.runner_id ?? null,
    overrides.state ?? "created",
    overrides.auth_state ?? "none",
    overrides.created_at ?? NOW,
    overrides.expires_at ?? NOW + 43_200_000,
    overrides.idle_expires_at ?? null,
    overrides.last_activity_at ?? NOW,
  );
}

beforeEach(() => {
  // In-memory per test: no cross-test state, no filesystem, and WAL is a no-op
  // for :memory: — the journal mode pragma is still asserted separately.
  db = new Db(":memory:");
});

afterEach(() => {
  db.close();
});

describe("schema", () => {
  it("creates both tables idempotently", () => {
    // Opening twice must not throw: an api that restarted into an existing
    // database would otherwise fail to boot.
    const second = new Db(":memory:");
    expect(() => second.run(`SELECT COUNT(*) FROM sessions`)).not.toThrow();
    second.close();
  });

  it("rejects an out-of-range runner status at the database level", () => {
    // The CHECK constraint is the enforcement, not the TypeScript type: a bug
    // elsewhere in the process cannot write a status the reconciler cannot read.
    expect(() =>
      db.run(
        `INSERT INTO runners (id, container_id, status) VALUES ('r1', 'c1', 'banana')`,
      ),
    ).toThrow();
  });

  it("accepts every legal runner status", () => {
    for (const status of ["idle", "claimed", "active", "draining", "dead"]) {
      expect(() =>
        db.run(`INSERT INTO runners (id, container_id, status) VALUES (?, 'c', ?)`, status, status),
      ).not.toThrow();
    }
  });
});

describe("sessions", () => {
  it("round-trips a session", () => {
    db.createSession({
      guid: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
      secretHash: hashSecret("A".repeat(43)),
      csrfKey: generateCsrfKey(),
      now: NOW,
      expiresAt: NOW + 43_200_000,
    });

    const row = db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
    expect(row?.state).toBe("created");
    expect(row?.auth_state).toBe("none");
    expect(row?.expires_at).toBe(NOW + 43_200_000);
  });

  it("never stores the secret in the clear", () => {
    const secret = "A".repeat(43);
    db.createSession({
      guid: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
      secretHash: hashSecret(secret),
      csrfKey: generateCsrfKey(),
      now: NOW,
      expiresAt: NOW + 1,
    });
    const raw = db.get<{ secret_hash: string }>(
      `SELECT secret_hash FROM sessions`,
    );
    expect(raw?.secret_hash).not.toContain(secret);
    expect(raw?.secret_hash).toBe(hashSecret(secret));
  });

  it("records activity and extends the idle deadline", () => {
    seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", { idle_expires_at: NOW });
    db.touchSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", NOW + 5_000, NOW + 1_800_000);

    const row = db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
    expect(row?.last_activity_at).toBe(NOW + 5_000);
    expect(row?.idle_expires_at).toBe(NOW + 1_800_000);
  });

  it("keeps the existing idle deadline when null is passed", () => {
    // A login in flight has no idle deadline to set; COALESCE means an
    // unconditional touch does not clear one that is already running.
    seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", { idle_expires_at: NOW + 500 });
    db.touchSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", NOW + 5_000, null);
    expect(db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")?.idle_expires_at).toBe(
      NOW + 500,
    );
  });

  it("deletes a session and reports whether a row went away", () => {
    seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
    expect(db.deleteSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBe(1);
    // Erasing twice is not an error: the state machine tolerates the row
    // already being gone (PLAN-v3 T-E1, "including when the row is already gone").
    expect(db.deleteSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBe(0);
  });

  it("counts sessions holding a runner", () => {
    seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", { runner_id: "slot-1" });
    seedSession("00000000-0000-0000-0000-000000000000", { runner_id: "slot-2" });
    seedSession("11111111-1111-1111-1111-111111111111");
    expect(db.countActiveSessions()).toBe(2);
  });
});

/**
 * `beginExport` — §8.1's per-session half, as one statement.
 *
 * The property under test is that **exactly one** of a set of simultaneous claims
 * succeeds. A read-then-check cannot have it; an unconditional UPDATE cannot have
 * it either. Every test here is written so that reverting the guard in the SQL
 * turns it red: dropping the `AND (…)` clause makes "one winner" fail, and
 * replacing the claim with an unconditional write makes every "refused" test fail.
 */
describe("beginExport", () => {
  const EXPORT_ID = "E".repeat(43);
  const queued = (id: string) => JSON.stringify({ state: "queued", id });

  function stored(): string | null {
    return db.getSession(GUID)?.export_state ?? null;
  }

  it("starts an export when there is none", () => {
    seedSession(GUID, { state: "authenticated" });
    expect(db.beginExport(GUID, "Work", queued(EXPORT_ID))).toBe(true);

    const row = db.getSession(GUID);
    expect(row?.state).toBe("exporting");
    expect(row?.notebook).toBe("Work");
    expect(JSON.parse(row?.export_state ?? "{}")).toMatchObject({
      state: "queued",
      id: EXPORT_ID,
    });
  });

  // The whole point, and the bug: six requests, one row, one winner. Before this
  // was an atomic conditional UPDATE, the route read `export_state` and then wrote
  // it unconditionally — so all six read "no export" and all six queued one.
  it("gives the export to exactly one of six simultaneous claims", () => {
    seedSession(GUID, { state: "authenticated" });

    const winners = [1, 2, 3, 4, 5, 6].filter((n) =>
      db.beginExport(GUID, `Notebook ${n}`, queued(EXPORT_ID)),
    );

    expect(winners).toHaveLength(1);
    // And the row carries that one, not the last — the loser's notebook never
    // reached disk, which is what "the export that won is the export that runs".
    expect(db.getSession(GUID)?.notebook).toBe(`Notebook ${winners[0]}`);
  });

  it.each(["queued", "running"] as const)(
    "refuses while an export is %s",
    (state) => {
      seedSession(GUID, { state: "exporting" });
      db.run(
        `UPDATE sessions SET export_state = ? WHERE guid = ?`,
        JSON.stringify({ state, id: EXPORT_ID }),
        GUID,
      );

      expect(db.beginExport(GUID, "Work", queued("F".repeat(43)))).toBe(false);
      // Untouched: a refused claim must not have written the loser's id over the
      // winner's, or the in-flight export would become untrackable.
      expect(stored()).toBe(JSON.stringify({ state, id: EXPORT_ID }));
    },
  );

  it.each(["done", "partial", "failed", "none"])(
    "allows a new export once the last one is %s",
    (state) => {
      seedSession(GUID, { state: "authenticated" });
      db.run(
        `UPDATE sessions SET export_state = ? WHERE guid = ?`,
        JSON.stringify({ state, id: EXPORT_ID }),
        GUID,
      );

      expect(db.beginExport(GUID, "Work", queued("F".repeat(43)))).toBe(true);
      expect(JSON.parse(stored() ?? "{}").id).toBe("F".repeat(43));
    },
  );

  // `NULL NOT IN ('queued','running')` is **NULL**, not true, so without an explicit
  // `IS NULL` term a session that had never exported — `export_state = NULL` — and
  // one whose column is `{}` would both be treated as "an export is already
  // running" and refused forever.
  it("allows an export when the column is NULL", () => {
    seedSession(GUID, { state: "authenticated" });
    expect(stored()).toBeNull();
    expect(db.beginExport(GUID, "Work", queued(EXPORT_ID))).toBe(true);
  });

  it("allows an export when the column is valid JSON with no state", () => {
    // The other half of the NULL-state trap: `{}` parses, `json_extract` returns
    // NULL for the missing path, and SQL's three-valued logic would reject it.
    seedSession(GUID, { state: "authenticated" });
    db.run(`UPDATE sessions SET export_state = ? WHERE guid = ?`, "{}", GUID);
    expect(db.beginExport(GUID, "Work", queued(EXPORT_ID))).toBe(true);
  });

  // `json_extract` **throws** on malformed JSON. A throw out of this method is a
  // 500 from the route, and a corrupt column would have turned "this session may
  // export" into "this session can never export again" — the opposite of the
  // read-then-check's `catch`, which treated garbage as no export.
  it("allows an export when the column is not valid JSON, rather than throwing", () => {
    seedSession(GUID, { state: "authenticated" });
    db.run(`UPDATE sessions SET export_state = ? WHERE guid = ?`, "{not json", GUID);

    // A throw out of this method is a 500 from the route, and the corrupt column
    // would survive it — so the session would be refused forever, which is the
    // opposite of the read-then-check's `catch`.
    expect(db.beginExport(GUID, "Work", queued(EXPORT_ID))).toBe(true);
    expect(stored()).toBe(queued(EXPORT_ID));
  });

  it("reports false for a session that does not exist", () => {
    expect(db.beginExport("00000000-0000-0000-0000-000000000000", "Work", queued(EXPORT_ID))).toBe(
      false,
    );
  });

  // `completeExport` reads `artifact_id`, and `markExportStranded`'s comment names
  // this exact row as one whose download was destroyed by an over-eager write. The
  // claim must not touch it either.
  it("leaves a finished artifact alone when it refuses a second export", () => {
    seedSession(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET export_state = ?, artifact_id = ?, artifact_partial = 1
        WHERE guid = ?`,
      JSON.stringify({ state: "running", id: EXPORT_ID }),
      EXPORT_ID,
      GUID,
    );

    expect(db.beginExport(GUID, "Other", queued("F".repeat(43)))).toBe(false);
    const row = db.getSession(GUID);
    expect(row?.artifact_id).toBe(EXPORT_ID);
    expect(row?.artifact_partial).toBe(1);
  });
});

/**
 * `beginLogin` and `cancelLogin` — the credential route's claim and its undo.
 *
 * Same shape as `beginExport`: the assertion is that exactly one of a set of
 * simultaneous claims wins, which a snapshot read followed by an unconditional
 * write cannot satisfy.
 */
describe("beginLogin / cancelLogin", () => {
  function authState(): string | undefined {
    return db.getSession(GUID)?.auth_state;
  }

  // The three states a real user reaches by signing in again. A guard that is
  // stricter than this locks out every returning user; one that is looser accepts a
  // credential on a session that never asked to be signed in.
  it.each(["none", "expired", "failed"] as const)("claims a session that is %s", (auth) => {
    seedSession(GUID, { auth_state: auth, state: "authenticated" });
    expect(db.beginLogin(GUID, NOW)).toBe(true);

    const row = db.getSession(GUID);
    expect(row?.auth_state).toBe("authenticating");
    expect(row?.state).toBe("authenticating");
    expect(row?.last_activity_at).toBe(NOW);
  });

  it.each(["valid", "authenticating"] as const)("refuses a session that is %s", (auth) => {
    seedSession(GUID, { auth_state: auth });
    expect(db.beginLogin(GUID, NOW)).toBe(false);
    expect(authState()).toBe(auth);
  });

  // The live bug: two submits served from one snapshot both passed the read
  // guard, both claimed a container, and the second overwrote `runner_id` —
  // leaking the first with nothing left pointing at it.
  it("gives the login to exactly one of six simultaneous submits", () => {
    seedSession(GUID, { auth_state: "none" });

    const winners = [1, 2, 3, 4, 5, 6].filter(() => db.beginLogin(GUID, NOW));
    expect(winners).toHaveLength(1);
  });

  it("does not move a session whose login is already valid", () => {
    // The compensation's whole safety property: it is guarded on
    // `authenticating`, so a login that completed in the meantime survives it.
    seedSession(GUID, { auth_state: "valid", state: "authenticated" });
    expect(db.cancelLogin(GUID)).toBe(false);
    expect(db.getSession(GUID)?.state).toBe("authenticated");
  });

  it("undoes a claim that was never handed a credential", () => {
    // Without this the session reports "still signing in" to every route for the
    // whole of `TTL.loginInProgress` (15 minutes) with nothing in flight.
    seedSession(GUID, { auth_state: "none", state: "created" });
    expect(db.beginLogin(GUID, NOW)).toBe(true);
    expect(db.cancelLogin(GUID)).toBe(true);

    const row = db.getSession(GUID);
    expect(row?.auth_state).toBe("none");
    expect(row?.state).toBe("created");
    // And the session can log in again straight away, which is the point.
    expect(db.beginLogin(GUID, NOW)).toBe(true);
  });

  it("leaves a session that never claimed anything alone", () => {
    seedSession(GUID, { auth_state: "expired", state: "authenticated" });
    expect(db.cancelLogin(GUID)).toBe(false);
    const row = db.getSession(GUID);
    expect(row?.auth_state).toBe("expired");
    expect(row?.state).toBe("authenticated");
  });

  // `cancelLogin` is not `markAuthFailed`, and the difference is load-bearing:
  // `markAuthFailed` records a *reported* login failure, drives
  // `releaseForAuthFailure` and sets `failed`. Nothing failed here — no credential
  // was ever submitted — so the session must come back as simply unsigned.
  it("does not record a failure, so no slot is released and nothing is alerted on", () => {
    seedSession(GUID, { auth_state: "none", state: "created" });
    db.beginLogin(GUID, NOW);
    db.cancelLogin(GUID);

    const row = db.getSession(GUID);
    expect(row?.auth_state).not.toBe("failed");
    expect(row?.runner_id).toBeNull();
  });
});

describe("claimRunner", () => {
  beforeEach(() => {
    db.registerRunner("slot-1", "c1", "idle");
    db.registerRunner("slot-2", "c2", "idle");
    db.registerRunner("slot-3", "c3", "claimed");
  });

  it("claims exactly one idle slot", () => {
    expect(db.claimRunner("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBe(true);
    expect(
      db.get<{ session_guid: string }>(
        `SELECT session_guid FROM runners WHERE session_guid IS NOT NULL`,
      )?.session_guid,
    ).toBe("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
  });

  // PLAN-v2 §16: two concurrent claims never receive the same runner.
  it("never hands the same slot to two sessions", () => {
    db.claimRunner("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
    db.claimRunner("00000000-0000-0000-0000-000000000000");

    const bound = db.all<{ id: string; session_guid: string }>(
      `SELECT id, session_guid FROM runners WHERE session_guid IS NOT NULL`,
    );
    expect(bound).toHaveLength(2);
    expect(new Set(bound.map((r) => r.id)).size).toBe(2);
  });

  it("reports exhaustion rather than claiming a busy slot", () => {
    db.claimRunner("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
    db.claimRunner("00000000-0000-0000-0000-000000000000");

    // Two idle slots, both now bound; slot-3 was already claimed.
    expect(db.claimRunner("11111111-1111-1111-1111-111111111111")).toBe(false);
  });

  it("does not claim a slot that is not idle", () => {
    db.registerRunner("slot-4", "c4", "dead");
    db.claimRunner("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
    db.claimRunner("00000000-0000-0000-0000-000000000000");

    const claimed = db.all<{ id: string }>(`SELECT id FROM runners WHERE session_guid IS NOT NULL`);
    expect(claimed.map((r) => r.id)).not.toContain("slot-3");
    expect(claimed.map((r) => r.id)).not.toContain("slot-4");
  });

  it("spreads claims across slots rather than always taking the first", () => {
    // ORDER BY RANDOM() spreads load so one container stays warm while the rest
    // stay cold. A deterministic order would make every session fight over slot-1.
    const picked = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const guid = `3f2504e0-4f89-11d3-9a0c-${String(i).padStart(12, "0")}`;
      if (db.claimRunner(guid)) {
        picked.add(
          db.get<{ id: string }>(
            `SELECT id FROM runners WHERE session_guid = ?`,
            guid,
          )!.id,
        );
      }
      // Return one slot to idle so the loop can keep claiming.
      db.run(`UPDATE runners SET status='idle', session_guid=NULL WHERE id = (SELECT id FROM runners WHERE status='claimed' LIMIT 1)`);
    }
    expect(picked.size).toBe(2);
  });

  it("releases a slot back to idle", () => {
    db.claimRunner("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
    db.releaseRunner("slot-1");
    const row = db.get<{ status: string; session_guid: string | null }>(
      `SELECT status, session_guid FROM runners WHERE id = 'slot-1'`,
    );
    expect(row?.status).toBe("idle");
    expect(row?.session_guid).toBeNull();
  });

  // ---- the exclusion set ---------------------------------------------------
  //
  // `claimRunner` draws with `ORDER BY RANDOM()`, and that is what keeps the pool's
  // load spread — and what makes a slot the caller already knows to be bad a coin
  // flip on the next attempt rather than a certainty. The exclusion set is the
  // caller's way of turning that into "the other one", so these tests are about a
  // slot *not* being drawn rather than about one being drawn.

  it("claims the other slot when one is excluded", () => {
    // The loop is the assertion. One draw with `ORDER BY RANDOM()` cannot tell an
    // honoured exclusion from a lucky one; fifty draws can — and fifty draws of the
    // old behaviour would pass with probability 2^-50.
    for (let i = 0; i < 50; i++) {
      const guid = `3f2504e0-4f89-11d3-9a0c-${String(i).padStart(12, "0")}`;
      expect(db.claimRunner(guid, ["slot-1"])).toBe(true);
      expect(
        db.get<{ id: string }>(`SELECT id FROM runners WHERE session_guid = ?`, guid)?.id,
      ).toBe("slot-2");
      db.releaseRunner("slot-2");
    }
  });

  it("treats an empty exclusion list as no exclusion at all", () => {
    // SQLite does accept `NOT IN ()` and reads it as the empty set, so nothing here
    // is a syntax-error trap — but the clause is still omitted when the list is
    // empty, because the dialects this could be ported to are not so forgiving. The
    // observable contract is the one asserted here: an empty list changes nothing at
    // all. It fails if the empty list is ever read as excluding something, and it
    // fails if the clause is emitted with no placeholders to bind and the draw ends
    // up restricted.
    const picked = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const guid = `3f2504e0-4f89-11d3-9a0c-${String(i).padStart(12, "0")}`;
      expect(db.claimRunner(guid, [])).toBe(true);
      picked.add(db.get<{ id: string }>(`SELECT id FROM runners WHERE session_guid = ?`, guid)!.id);
      db.run(`UPDATE runners SET status='idle', session_guid=NULL WHERE session_guid = ?`, guid);
    }
    expect([...picked].sort()).toEqual(["slot-1", "slot-2"]);
  });

  it("claims nothing when every idle slot is excluded", () => {
    // A boolean, not a slot: this is the whole answer `claimRunner` has to give, and it
    // is what the retry sees once every slot has been refused. Whether that empty draw
    // is reported as exhaustion or as the disagreement it is, is decided one level up,
    // in `#claimOnce`.
    expect(db.claimRunner("3f2504e0-4f89-11d3-9a0c-0305e82c3301", ["slot-1", "slot-2"])).toBe(false);
    expect(
      db.get<{ session_guid: string }>(`SELECT session_guid FROM runners WHERE session_guid IS NOT NULL`),
    ).toBeUndefined();
    // The already-claimed row is untouched: an exclusion is not a release.
    expect(
      db.get<{ status: string; session_guid: string | null }>(
        `SELECT status, session_guid FROM runners WHERE id = 'slot-3'`,
      ),
    ).toEqual({ status: "claimed", session_guid: null });
  });

  it("binds the session rather than an excluded id, whatever the order of the placeholders", () => {
    // `NOT IN` placeholders sit after `session_guid` in the statement, so their
    // bindings must sit after it in the argument list. An id that matches no row is
    // the case that catches the two lists drifting apart: with the arguments
    // transposed, the session would be recorded under a slot name.
    expect(db.claimRunner("3f2504e0-4f89-11d3-9a0c-0305e82c3301", ["slot-9"])).toBe(true);
    expect(
      db.get<{ session_guid: string; status: string }>(
        `SELECT session_guid, status FROM runners WHERE session_guid IS NOT NULL`,
      ),
    ).toEqual({ session_guid: "3f2504e0-4f89-11d3-9a0c-0305e82c3301", status: "claimed" });
  });
});

describe("reconcileRunners", () => {
  it("removes runner rows the orchestrator no longer has", () => {
    db.registerRunner("slot-1", "c1", "idle");
    db.registerRunner("slot-2", "c2", "idle");

    db.reconcileRunners(new Set(["slot-1"]), NOW);

    const rows = db.all<{ id: string }>(`SELECT id FROM runners`);
    expect(rows.map((r) => r.id)).toEqual(["slot-1"]);
  });

  it("clears a vanished runner from its session so it can rebind", () => {
    // PLAN-v2 §2.3 step 4: the vault survives, so re-claiming a slot restores
    // the session without a re-login.
    db.registerRunner("slot-1", "c1", "claimed");
    seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", { runner_id: "slot-1" });

    db.reconcileRunners(new Set(), NOW);

    const row = db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
    expect(row).toBeDefined();
    expect(row?.runner_id).toBeNull();
  });

  it("deletes expired sessions", () => {
    seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", { expires_at: NOW - 1 });
    seedSession("00000000-0000-0000-0000-000000000000", { expires_at: NOW + 1 });

    db.reconcileRunners(new Set(), NOW);

    expect(db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBeUndefined();
    expect(db.getSession("00000000-0000-0000-0000-000000000000")).toBeDefined();
  });

  it("never resurrects an expired session", () => {
    // The rule from PLAN-v2 §2.5, stated as a test because it is the one a
    // future reconciler could plausibly get wrong.
    seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", { expires_at: NOW - 1 });
    db.reconcileRunners(new Set(), NOW);
    expect(db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBeUndefined();
  });

  it("leaves an in-flight erase alone", () => {
    // Deleting the row out from under the erase state machine would strand the
    // vault: the machine stops and nothing records that it was meant to finish.
    seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", {
      expires_at: NOW - 1,
      state: "erasing",
    });
    db.reconcileRunners(new Set(), NOW);
    expect(db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBeDefined();
  });

  it("is idempotent", () => {
    db.registerRunner("slot-1", "c1", "idle");
    seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301", {
      runner_id: "slot-1",
      expires_at: NOW - 1,
    });
    for (let i = 0; i < 3; i++) {
      db.reconcileRunners(new Set(["slot-1"]), NOW);
    }
    expect(db.listRunners()).toHaveLength(1);
    expect(db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBeUndefined();
  });
});

/**
 * releaseRunner's guard, and the return value it needs to be a guard at all.
 *
 * §4.9's dual-reconciler mechanism: two processes keep independent records of the
 * same pool, and every write that a stale snapshot could make destructive carries
 * the value it read as a predicate. `runners.session_guid` is the half of the
 * binding the caller *didn't* read in a lot of places, which is why it is the one
 * the predicate tests.
 */
describe("releaseRunner", () => {
  const OTHER = "00000000-0000-0000-0000-000000000000";

  beforeEach(() => {
    db.registerRunner("slot-1", "c1", "claimed");
    db.run(`UPDATE runners SET session_guid = ? WHERE id = 'slot-1'`, GUID);
  });

  const row = () => db.get<{ status: string; session_guid: string | null }>(
    `SELECT status, session_guid FROM runners WHERE id = 'slot-1'`,
  );

  it("frees the row and reports one change when the session is the one it read", () => {
    // The positive case, and the reason `1` is worth returning: a caller that has
    // just destroyed a container needs to distinguish "the row is free" from "the
    // row was not mine", and `void` threw that away.
    expect(db.releaseRunner("slot-1", GUID)).toBe(1);
    expect(row()).toEqual({ status: "idle", session_guid: null });
  });

  it("changes nothing and reports no change when the row names another session", () => {
    // The guard's whole job. A slot re-bound between a caller's read and its write
    // belongs to somebody else now; clearing it hands a container another session
    // is using back to the pool while that session still believes it has one.
    expect(db.releaseRunner("slot-1", OTHER)).toBe(0);
    // Byte-for-byte unchanged, not merely "still bound somewhere".
    expect(row()).toEqual({ status: "claimed", session_guid: GUID });
  });

  it("stays unconditional without the parameter, so existing callers are unaffected", () => {
    // Backward compatibility is the reason the parameter is optional rather than
    // required. `reclaimOrphanBindings` must stay unguarded (F6) — its own predicate
    // is a `session_guid` with no session row, so a guard could never match — and a
    // required parameter would have made that a compile error instead of a
    // documented decision.
    expect(db.releaseRunner("slot-1")).toBe(1);
    expect(row()).toEqual({ status: "idle", session_guid: null });

    // ...and it really is unguarded: a row bound to *any* session is freed, which is
    // the behaviour the unguarded call sites depend on.
    db.registerRunner("slot-1", "c1", "claimed");
    db.run(`UPDATE runners SET session_guid = ? WHERE id = 'slot-1'`, OTHER);
    expect(db.releaseRunner("slot-1")).toBe(1);
    expect(row()).toEqual({ status: "idle", session_guid: null });
  });

  it("reports zero for a slot that does not exist, rather than throwing", () => {
    // A stale id is an ordinary outcome of a re-read — the row was deleted by the
    // boot reconciler — and it must read as "nothing to free" for the same reason
    // the guarded mismatch does.
    expect(db.releaseRunner("slot-9", GUID)).toBe(0);
  });
});

/**
 * clearSessionRunner's guard (F8).
 *
 * The same §4.9 predicate one level up: the sweeper's dead-runner repair works from
 * a tick-old snapshot, and an unguarded `WHERE guid = ?` clears whatever the column
 * holds *now* — including a live binding a re-login landed in the meantime.
 */
describe("clearSessionRunner", () => {
  it("clears the binding it was given the id for", () => {
    seedSession(GUID, { runner_id: "slot-1" });
    expect(db.clearSessionRunner(GUID, "slot-1")).toBe(1);
    expect(db.getSession(GUID)?.runner_id).toBeNull();
  });

  it("leaves a binding that has already moved on alone", () => {
    // The sweeper decided about slot-1; a re-login then claimed slot-2 and wrote
    // it. The unguarded form would clear *that* — handing a working container away
    // from a session in the middle of a sign-in, which no reconciler can repair
    // because both records are then consistent and both wrong.
    //
    // The change count is what tells the caller its unstick did not happen, and
    // `markExportStranded`'s `runner_id IS NULL` guard is meaningless without it.
    seedSession(GUID, { runner_id: "slot-2" });
    expect(db.clearSessionRunner(GUID, "slot-1")).toBe(0);
    expect(db.getSession(GUID)?.runner_id).toBe("slot-2");
  });
});

describe("transactions", () => {
  it("commits on success", () => {
    db.transaction(() => {
      seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
    });
    expect(db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBeDefined();
  });

  it("rolls back on a throw, so a failed claim writes nothing", () => {
    expect(() =>
      db.transaction(() => {
        seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
        throw new Error("boom");
      }),
    ).toThrow("boom");

    expect(db.getSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).toBeUndefined();
  });

  it("releases the write lock after a rollback, so later writes still work", () => {
    // A held lock would deadlock every subsequent request rather than failing
    // this one, which is the worse failure to debug.
    expect(() =>
      db.transaction(() => {
        throw new Error("boom");
      }),
    ).toThrow();
    expect(() => seedSession("3f2504e0-4f89-11d3-9a0c-0305e82c3301")).not.toThrow();
  });
});

describe("WAL mode", () => {
  it("is enabled on a file-backed database", () => {
    // :memory: cannot do WAL, so this asserts on a real file.
    const { mkdtempSync, rmSync } = require("node:fs") as typeof import("node:fs");
    const { tmpdir } = require("node:os") as typeof import("node:os");
    const { join } = require("node:path") as typeof import("node:path");

    const dir = mkdtempSync(join(tmpdir(), "msout-db-"));
    try {
      const file = new Db(join(dir, "nested", "api.db"));
      const mode = file.get<{ journal_mode: string }>(`PRAGMA journal_mode`);
      expect(mode?.journal_mode.toLowerCase()).toBe("wal");
      file.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("creates a missing parent directory rather than failing to open", () => {
    const { mkdtempSync, rmSync } = require("node:fs") as typeof import("node:fs");
    const { tmpdir } = require("node:os") as typeof import("node:os");
    const { join } = require("node:path") as typeof import("node:path");

    const dir = mkdtempSync(join(tmpdir(), "msout-db-"));
    try {
      const file = new Db(join(dir, "a", "b", "c", "api.db"));
      expect(file.get(`SELECT 1 AS ok`)?.ok).toBe(1);
      file.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  describe("markExportStranded", () => {
    it("marks a running export_state as failed", () => {
      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'exporting', runner_id = NULL,
                         export_state = ? WHERE guid = ?`,
        '{"state":"running","id":"artifact123","notebook":"Notebook"}',
        GUID,
      );

      const changed = db.markExportStranded({
        guid: GUID,
        now: NOW + 1000,
        idleExpiresAt: NOW + 50_000,
      });

      expect(changed).toBe(true);

      const row = db.getSession(GUID)!;
      expect(row.state).toBe("authenticated");
      expect(row.last_activity_at).toBe(NOW + 1000);
      expect(row.idle_expires_at).toBe(NOW + 50_000);
      expect(row.runner_id).toBeNull();

      const parsed = JSON.parse(row.export_state!);
      expect(parsed.state).toBe("failed");
      expect(parsed.error).toBe("the runner was released before this export finished");
      expect(parsed.progress).toBeNull();
      expect(parsed.finishedAt).toBe(NOW + 1000);
      expect(parsed.id).toBe("artifact123");
      expect(parsed.notebook).toBe("Notebook");
    });

    it("marks a queued export_state as failed", () => {
      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'exporting', runner_id = NULL,
                         export_state = ? WHERE guid = ?`,
        '{"state":"queued","id":"artifact123","notebook":"Notebook"}',
        GUID,
      );

      const changed = db.markExportStranded({
        guid: GUID,
        now: NOW + 1000,
        idleExpiresAt: NOW + 50_000,
      });

      expect(changed).toBe(true);

      const row = db.getSession(GUID)!;
      const parsed = JSON.parse(row.export_state!);
      expect(parsed.state).toBe("failed");
      expect(parsed.id).toBe("artifact123");
      expect(parsed.notebook).toBe("Notebook");
    });

    it("leaves partial export_state unchanged (data-loss guard)", () => {
      const partialState = JSON.stringify({
        state: "partial",
        partialReason: "quota",
        id: "artifact123",
        notebook: "Notebook",
        progress: null,
        startedAt: 1234567890,
        finishedAt: 1234567900,
      });

      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'exporting', runner_id = NULL,
                         export_state = ?, artifact_id = 'artifact123'
                       WHERE guid = ?`,
        partialState,
        GUID,
      );

      const changed = db.markExportStranded({
        guid: GUID,
        now: NOW + 1000,
        idleExpiresAt: NOW + 50_000,
      });

      // Should be true because the WHERE clause matched (state=exporting AND runner_id=NULL)
      // but the CASE WHEN didn't change export_state
      expect(changed).toBe(true);

      const row = db.getSession(GUID)!;
      expect(row.state).toBe("authenticated");
      expect(row.export_state).toBe(partialState);
      expect(row.artifact_id).toBe("artifact123");
    });

    it("leaves malformed export_state unchanged AND does not throw", () => {
      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'exporting', runner_id = NULL, export_state = ?
        WHERE guid = ?`,
        "not valid json {",
        GUID,
      );

      // Should not throw
      expect(() =>
        db.markExportStranded({
          guid: GUID,
          now: NOW + 1000,
          idleExpiresAt: NOW + 50_000,
        }),
      ).not.toThrow();

      const row = db.getSession(GUID)!;
      // state is updated to 'authenticated' unconditionally by the WHERE clause
      expect(row.state).toBe("authenticated");
      // export_state unchanged (data-loss guard)
      expect(row.export_state).toBe("not valid json {");
    });

    it("leaves NULL export_state unchanged AND does not throw", () => {
      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'exporting', runner_id = NULL, export_state = NULL
        WHERE guid = ?`,
        GUID,
      );

      expect(() =>
        db.markExportStranded({
          guid: GUID,
          now: NOW + 1000,
          idleExpiresAt: NOW + 50_000,
        }),
      ).not.toThrow();

      const row = db.getSession(GUID)!;
      // state is updated to 'authenticated' unconditionally by the WHERE clause
      expect(row.state).toBe("authenticated");
      expect(row.export_state).toBeNull();
    });

    it("re-running on an already failed row is a no-op (state stays failed)", () => {
      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'exporting', runner_id = NULL,
                         export_state = ? WHERE guid = ?`,
        '{"state":"failed","error":"previous error"}',
        GUID,
      );

      // First run
      db.markExportStranded({
        guid: GUID,
        now: NOW + 1000,
        idleExpiresAt: NOW + 50_000,
      });

      // Second run
      const changed = db.markExportStranded({
        guid: GUID,
        now: NOW + 2000,
        idleExpiresAt: NOW + 60_000,
      });

      // Second call should return false because the WHERE clause doesn't match
      // (export_state.state is 'failed', not 'queued' or 'running')
      expect(changed).toBe(false);

      const row = db.getSession(GUID)!;
      expect(row.last_activity_at).toBe(NOW + 1000);
      expect(row.idle_expires_at).toBe(NOW + 50_000);
    });

    it("a session with a live runner (runner_id non-null) is never touched", () => {
      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'exporting', runner_id = 'slot-1',
                         export_state = ? WHERE guid = ?`,
        '{"state":"running"}',
        GUID,
      );

      const changed = db.markExportStranded({
        guid: GUID,
        now: NOW + 1000,
        idleExpiresAt: NOW + 50_000,
      });

      expect(changed).toBe(false);

      const row = db.getSession(GUID)!;
      expect(row.state).toBe("exporting");
      expect(row.runner_id).toBe("slot-1");
    });

    it("a session not in exporting state is never touched", () => {
      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'authenticated', runner_id = NULL,
                         export_state = ? WHERE guid = ?`,
        '{"state":"running"}',
        GUID,
      );

      const changed = db.markExportStranded({
        guid: GUID,
        now: NOW + 1000,
        idleExpiresAt: NOW + 50_000,
      });

      expect(changed).toBe(false);

      const row = db.getSession(GUID)!;
      expect(row.state).toBe("authenticated");
    });

    // The caller's own `error`, through the same data-loss guard.
    //
    // The sweeper's dead-runner branch names a different cause than the default
    // string does — nothing released that runner, it died — and it is the *only*
    // caller that passes one. Asserted against a `partial` row rather than a
    // `running` one, because the interesting half is what the argument does **not**
    // change: the `ELSE export_state` arm must still leave a finished, downloadable
    // result untouched whatever string it is handed.
    it("takes a caller's error, and still spares a finished export with it", () => {
      const partialState = JSON.stringify({
        state: "partial",
        partialReason: "quota",
        id: "artifact123",
        notebook: "Notebook",
        progress: null,
        startedAt: 1234567890,
        finishedAt: 1234567900,
      });

      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'exporting', runner_id = NULL,
                         export_state = ?, artifact_id = 'artifact123'
                       WHERE guid = ?`,
        partialState,
        GUID,
      );

      const changed = db.markExportStranded({
        guid: GUID,
        now: NOW + 1000,
        idleExpiresAt: NOW + 50_000,
        error: "the runner disappeared before this export finished",
      });

      expect(changed).toBe(true);

      const row = db.getSession(GUID)!;
      expect(row.state).toBe("authenticated");
      expect(row.export_state).toBe(partialState);
      expect(row.artifact_id).toBe("artifact123");
    });

    // And the error string itself reaches the row when the export *was* in flight —
    // otherwise the guard half above would pass against a statement that dropped the
    // argument on the floor.
    it("writes the caller's error into a running export_state", () => {
      db.createSession({
        guid: GUID,
        secretHash: hashSecret("A".repeat(43)),
        csrfKey: generateCsrfKey(),
        now: NOW,
        expiresAt: NOW + 43_200_000,
      });
      db.run(
        `UPDATE sessions SET state = 'exporting', runner_id = NULL,
                         export_state = ? WHERE guid = ?`,
        '{"state":"running","id":"artifact123","notebook":"Notebook"}',
        GUID,
      );

      db.markExportStranded({
        guid: GUID,
        now: NOW + 1000,
        idleExpiresAt: NOW + 50_000,
        error: "the runner disappeared before this export finished",
      });

      const parsed = JSON.parse(db.getSession(GUID)!.export_state!);
      expect(parsed.state).toBe("failed");
      expect(parsed.error).toBe("the runner disappeared before this export finished");
    });
  });
});

/**
 * The writer that makes the export card tell the truth while it runs.
 *
 * ## The bug these exist for
 *
 * `export_state.progress` was written twice — zeroed at queue time, zeroed again
 * at run start — and never again until `completeExport` wrote the final numbers
 * at the *end*. So the card said "0 pages, 0 sections, 0 assets so far" for the
 * whole walk, live and after a refresh, on every notebook.
 *
 * ## Why the assertions are about the **row**
 *
 * The frontend already renders `snapshot.export.progress`, and the SSE stream
 * already carried the counts — so a test that asserted "the event arrived" would
 * pass today and say nothing. What was missing was the write, and the write is
 * only visible here.
 */
describe("updateExportProgress", () => {
  /**
   * A session mid-walk, with the zeros `routes.ts` writes at run start.
   *
   * Takes a guid because two of these tests below seed one row per case and
   * `guid` is the primary key — reusing it would be a UNIQUE violation and an
   * error that says nothing about what is being asserted.
   */
  function seedRunning(state = "running", guid = GUID): void {
    seedSession(guid, { state: "exporting" });
    db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({
        state,
        partialReason: null,
        id: "A".repeat(43),
        notebook: "The Complete Notebook",
        progress: { pages: 0, sections: 0, assets: 0 },
        startedAt: NOW,
        finishedAt: null,
      }),
      guid,
    );
  }

  it("writes the counts and reports one row changed", () => {
    seedRunning();

    const changed = db.updateExportProgress(GUID, { pages: 29, sections: 1, assets: 8 }, 1000);

    expect(changed).toBe(1);
    const parsed = JSON.parse(db.getSession(GUID)!.export_state!);
    expect(parsed.progress).toEqual({ pages: 29, sections: 1, assets: 8 });
  });

  it("stores the counts as an object, not as a JSON string", () => {
    // The whole change is silent without this. `json_set` treats a bound
    // parameter as SQL *text*, so `json_set(s,'$.progress', ?)` with
    // `JSON.stringify(progress)` stores `"{\"pages\":29}"` — a string where the
    // contract says an object. No error, the row looks written, and every read
    // of `.pages` in the frontend is `undefined`, which renders as the very
    // zeros this method exists to replace.
    seedRunning();

    db.updateExportProgress(GUID, { pages: 29, sections: 1, assets: 8 }, 1000);

    const raw = JSON.parse(db.getSession(GUID)!.export_state!) as { progress: unknown };
    expect(typeof raw.progress).toBe("object");
    expect(raw.progress).not.toBeNull();
  });

  it("preserves the rest of export_state, and the rest of the row", () => {
    // `json_set` on one path, not a re-serialisation. A method that rebuilt the
    // object from a partial read would drop `id` — and `id` is what
    // `POST /api/export/abort/:id` matches the session against, so an abort
    // would answer 404 "no such export" for an export that is running.
    seedRunning();
    db.run(
      `UPDATE sessions SET artifact_id = NULL, artifact_partial = 0 WHERE guid = ?`,
      GUID,
    );

    db.updateExportProgress(GUID, { pages: 12, sections: 3, assets: 40 }, 1000);

    const row = db.getSession(GUID)!;
    const parsed = JSON.parse(row.export_state!);
    expect(parsed.state).toBe("running");
    expect(parsed.id).toBe("A".repeat(43));
    expect(parsed.notebook).toBe("The Complete Notebook");
    expect(parsed.startedAt).toBe(NOW);
    expect(parsed.finishedAt).toBeNull();
    expect(parsed.partialReason).toBeNull();
    // And nothing outside the JSON moved either.
    expect(row.artifact_id).toBeNull();
    expect(row.state).toBe("exporting");
  });

  it("writes over a queued export too, not only a running one", () => {
    // The queue write (`routes.ts`) and the run-start write both leave
    // `queued`→`running`, and a frame can land between them. Refusing `queued`
    // would drop the first counts of every export.
    seedRunning("queued");

    expect(db.updateExportProgress(GUID, { pages: 1, sections: 1, assets: 1 }, 1000)).toBe(1);
    expect(JSON.parse(db.getSession(GUID)!.export_state!).progress).toEqual({
      pages: 1,
      sections: 1,
      assets: 1,
    });
  });

  it("refuses a finished export, so a replayed frame cannot move the card backwards", () => {
    // `#pump` reconnects and replays from the last sequence number it saw, so the
    // frame before a dropped connection arrives again — after the terminal. An
    // unguarded write would put the counts back to 12 while the state went to
    // `running` and the download link vanished.
    for (const [index, terminal] of ["done", "partial", "failed"].entries()) {
      const guid = `${index}-${GUID}`;
      seedSession(guid, { state: "authenticated" });
      db.run(
        `UPDATE sessions SET export_state = ? WHERE guid = ?`,
        JSON.stringify({
          state: terminal,
          id: "A".repeat(43),
          notebook: "The Complete Notebook",
          progress: { pages: 29, sections: 1, assets: 8 },
          startedAt: NOW,
          finishedAt: NOW + 1000,
        }),
        guid,
      );

      const changed = db.updateExportProgress(guid, { pages: 3, sections: 1, assets: 1 }, 1000);

      expect(changed, terminal).toBe(0);
      expect(JSON.parse(db.getSession(guid)!.export_state!).progress, terminal).toEqual({
        pages: 29,
        sections: 1,
        assets: 8,
      });
    }
  });

  it("reports 0 for a session that is no longer there", () => {
    seedRunning();
    db.run(`DELETE FROM sessions WHERE guid = ?`, GUID);

    // The change count is the *only* signal the wiring gets that this session's
    // export is over, so a vanished row has to read the same way as a finished
    // one: zero.
    expect(db.updateExportProgress(GUID, { pages: 29, sections: 1, assets: 8 }, 1000)).toBe(0);
  });

  it("writes nothing for a null progress", () => {
    // `null` means "unknown", not "measured zero". Overwriting good counts with
    // it is the one update that makes the card lie backwards, and `routes.ts`
    // nulls `progress` deliberately on abort.
    seedRunning();
    db.updateExportProgress(GUID, { pages: 29, sections: 1, assets: 8 });

    expect(db.updateExportProgress(GUID, null)).toBe(0);
    expect(JSON.parse(db.getSession(GUID)!.export_state!).progress).toEqual({
      pages: 29,
      sections: 1,
      assets: 8,
    });
  });

  it("does not throw on a malformed export_state column", () => {
    // `json_set` throws on malformed JSON, and this is called from the event pump,
    // where a throw tears the stream down and loses every later event for the
    // session. `markExportStranded` hit exactly this and carries `json_valid` for
    // the same reason.
    for (const [index, corrupt] of ["not valid json {", "NULL"].entries()) {
      const guid = `${index + 10}-${GUID}`;
      seedSession(guid, { state: "exporting" });
      db.run(
        `UPDATE sessions SET export_state = ? WHERE guid = ?`,
        corrupt === "NULL" ? null : corrupt,
        guid,
      );

      expect(() =>
        db.updateExportProgress(guid, { pages: 1, sections: 1, assets: 1 }, 1000),
      ).not.toThrow();
      expect(db.updateExportProgress(guid, { pages: 1, sections: 1, assets: 1 }, 1000)).toBe(0);
    }
  });
});

describe("completeExport's failure counts", () => {
  it("persists what was lost, so a partial terminal says what", () => {
    // The walk the user measured, verbatim: 29 pages, 8 assets, **1 page failed**.
    // These three numbers arrived on the runner's terminal frame, decided
    // `partial`, and were then dropped on the floor — so the row said *that*
    // something was lost and nothing about *what*, and the card's only sentence
    // was "the export stopped before it finished", which is false: it finished.
    seedSession(GUID, { state: "exporting" });

    const recorded = db.completeExport({
      guid: GUID,
      artifactId: "A".repeat(43),
      partial: true,
      partialReason: null,
      notebook: "The Complete Notebook",
      progress: { pages: 29, sections: 1, assets: 8 },
      startedAt: NOW,
      finishedAt: NOW + 229_000,
      failedSections: 0,
      failedPages: 1,
      failedGroups: 0,
    });

    expect(recorded).toBe(true);
    const parsed = JSON.parse(db.getSession(GUID)!.export_state!);
    expect(parsed.state).toBe("partial");
    expect(parsed.progress).toEqual({ pages: 29, sections: 1, assets: 8 });
    expect(parsed.failed).toEqual({ pages: 1, sections: 0, groups: 0 });
  });

  it("records measured zeros rather than omitting the field on a clean export", () => {
    // A terminal is the one moment where "zero pages failed" is a *measured* zero
    // rather than an absence, so the field is always present — a client must
    // never have to tell "nothing failed" apart from "nothing was said".
    seedSession(GUID, { state: "exporting" });

    db.completeExport({
      guid: GUID,
      artifactId: "A".repeat(43),
      partial: false,
      partialReason: null,
      notebook: "MS is great",
      progress: { pages: 7, sections: 3, assets: 2 },
      startedAt: NOW,
      finishedAt: NOW + 1000,
      failedSections: 0,
      failedPages: 0,
      failedGroups: 0,
    });

    const parsed = JSON.parse(db.getSession(GUID)!.export_state!);
    expect(parsed.state).toBe("done");
    expect(parsed.failed).toEqual({ pages: 0, sections: 0, groups: 0 });
  });
});