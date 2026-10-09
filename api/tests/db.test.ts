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
  });
});