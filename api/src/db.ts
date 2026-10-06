/**
 * SQLite access.
 *
 * SQLite in WAL mode is the only live source of truth (PLAN-v2 §2.4). Docker
 * labels are recovery and reconciliation metadata only — never the lock — and
 * this module is where that separation is expressed: nothing here reads a
 * container label, and nothing the orchestrator writes can change what these
 * tables say.
 *
 * Uses `node:sqlite`, which is unflagged from Node 22.13.0. That is a deliberate
 * choice over `better-sqlite3`: a native addon means a compilation step and a
 * prebuilt-binary supply chain, in the one component that must not have either.
 * The trade is that the API is experimental and its surface may change between
 * Node releases, which is why `engines` in package.json pins `>=22.13.0` and why
 * every call here goes through the small wrapper below rather than using the
 * DatabaseSync API directly at call sites.
 *
 * The 22.13.0 floor is not 22.5.0, where the module was added: it sat behind
 * --experimental-sqlite until 22.13.0. This file previously claimed 22.5, which
 * would have produced a runtime that could not load its own database driver.
 * Nothing in the test suite could have caught that, because every test runs on a
 * developer's Node rather than on the declared floor — CI's
 * `node -e "require('node:sqlite')"` smoke test did.
 */

import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

/** A runner row, mirroring PLAN-v2 §2.4 exactly. */
export interface RunnerRow {
  id: string;
  container_id: string;
  status: "idle" | "claimed" | "active" | "draining" | "dead";
  health: string;
  last_health_at: number | null;
  session_guid: string | null;
}

/** Session states. A session's state machine is small and closed. */
export type SessionState =
  | "created"
  | "authenticating"
  | "authenticated"
  | "exporting"
  | "erasing"
  | "erased";

/** Auth states, mirroring what mac renders against. */
export type AuthState = "none" | "authenticating" | "valid" | "expired" | "failed";

/** A session row. */
export interface SessionRow {
  guid: string;
  /** sha256 of the session secret, base64url. Never the secret itself. */
  secret_hash: string | null;
  /** Per-session CSRF key, base64url. Destroyed with the session. */
  csrf_key: string | null;
  runner_id: string | null;
  state: SessionState;
  auth_state: AuthState;
  created_at: number;
  expires_at: number;
  idle_expires_at: number | null;
  last_activity_at: number;
  notebook: string | null;
  /** JSON blob for the restore snapshot; see snapshot.ts for its shape. */
  export_state: string | null;
  artifact_id: string | null;
  artifact_partial: number;
}

/** The schema. Written once, idempotently, at open. */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS runners (
  id              TEXT PRIMARY KEY,
  container_id    TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN
                    ('idle','claimed','active','draining','dead')),
  health          TEXT NOT NULL DEFAULT 'unknown',
  last_health_at  INTEGER,
  session_guid    TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  guid             TEXT PRIMARY KEY,
  secret_hash      TEXT,
  csrf_key         TEXT,
  runner_id        TEXT,
  state            TEXT NOT NULL,
  auth_state       TEXT NOT NULL DEFAULT 'none',
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  idle_expires_at  INTEGER,
  last_activity_at INTEGER NOT NULL,
  notebook         TEXT,
  export_state     TEXT,
  artifact_id      TEXT,
  artifact_partial INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS sessions_state ON sessions (state);
CREATE INDEX IF NOT EXISTS runners_status ON runners (status);
CREATE INDEX IF NOT EXISTS runners_session ON runners (session_guid);
`;

/**
 * Db is a thin wrapper over one database handle.
 *
 * Every method is synchronous. That is a deliberate choice: Fastify handlers are
 * async and awaiting a sync call inside them is free, whereas a sync wrapper
 * around an async driver would force the call sites to await anyway. SQLite in
 * WAL mode serialises writes internally and the api is not a write-hot path —
 * the credential path forwards bytes without touching this module at all.
 */
export class Db {
  readonly #db: DatabaseSync;

  constructor(path: string) {
    if (path !== ":memory:") {
      // The directory has to exist before SQLite will create the file, and a
      // missing data directory is a deployment mistake worth a clear error
      // rather than a bare SQLITE_CANTOPEN.
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    }
    this.#db = new DatabaseSync(path);
    this.#db.exec("PRAGMA journal_mode = WAL");
    // NORMAL is the documented WAL companion: durable across process crash,
    // and recoverable from the WAL after an OS crash. FULL would fsync on every
    // commit for a database whose worst case is losing one session row.
    this.#db.exec("PRAGMA synchronous = NORMAL");
    // A session row must never be silently deleted by a connection drop.
    this.#db.exec("PRAGMA foreign_keys = ON");
    // Wait rather than throwing SQLITE_BUSY when a write overlaps a read. The
    // alternative is the caller seeing a spurious failure for a millisecond.
    this.#db.exec("PRAGMA busy_timeout = 5000");
    this.#db.exec(SCHEMA);
  }

  close(): void {
    this.#db.close();
  }

  /**
   * run executes a statement and reports affected row count.
   *
   * The `changes` figure is what the atomic claim checks, so it is returned
   * rather than discarded.
   */
  run(sql: string, ...params: unknown[]): number {
    const result = this.#db.prepare(sql).run(...(params as never[]));
    return Number(result.changes);
  }

  get<T>(sql: string, ...params: unknown[]): T | undefined {
    const row = this.#db.prepare(sql).get(...(params as never[]));
    return row as T | undefined;
  }

  all<T>(sql: string, ...params: unknown[]): T[] {
    return this.#db.prepare(sql).all(...(params as never[])) as T[];
  }

  /**
   * transaction runs fn inside an IMMEDIATE transaction.
   *
   * IMMEDIATE takes the write lock at BEGIN rather than at first write, so two
   * concurrent claims cannot both read "idle" and then both try to write. That
   * race is the whole reason PLAN-v2 §2.4 specifies this block, and DEFERRED
   * would reintroduce it.
   */
  transaction<T>(fn: () => T): T {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      this.#db.exec("COMMIT");
      return out;
    } catch (error) {
      // Roll back on any throw. A failed claim must not leave the write lock
      // held, or every later request deadlocks on it.
      try {
        this.#db.exec("ROLLBACK");
      } catch {
        // A rollback failure means the transaction is already gone. The
        // original error is the one worth surfacing.
      }
      throw error;
    }
  }

  // ---- sessions ---------------------------------------------------------

  /** createSession inserts a new session row. */
  createSession(row: {
    guid: string;
    secretHash: string;
    csrfKey: string;
    now: number;
    expiresAt: number;
  }): void {
    this.run(
      `INSERT INTO sessions
         (guid, secret_hash, csrf_key, runner_id, state, auth_state,
          created_at, expires_at, idle_expires_at, last_activity_at,
          notebook, export_state, artifact_id, artifact_partial)
       VALUES (?, ?, ?, NULL, 'created', 'none', ?, ?, ?, ?, NULL, NULL, NULL, 0)`,
      row.guid,
      row.secretHash,
      row.csrfKey,
      row.now,
      row.expiresAt,
      row.now,
      row.now,
    );
  }

  /** getSession returns a session row by guid. */
  getSession(guid: string): SessionRow | undefined {
    return this.get<SessionRow>(`SELECT * FROM sessions WHERE guid = ?`, guid);
  }

  /** touchSession records activity and optionally extends the idle deadline. */
  touchSession(guid: string, now: number, idleExpiresAt: number | null): void {
    this.run(
      `UPDATE sessions
          SET last_activity_at = ?, idle_expires_at = COALESCE(?, idle_expires_at)
        WHERE guid = ?`,
      now,
      idleExpiresAt,
      guid,
    );
  }

  /**
   * deleteSession removes a session row.
   *
   * Used by the erase state machine and by the boot sweeper for expired rows.
   * The vault directory is *not* touched here — this process cannot reach it,
   * which is the point of the mount split (PLAN-v3 §2.2). The orchestrator
   * destroys the directory; `api` destroys the row, and the erase state machine
   * is what makes those two agree.
   */
  deleteSession(guid: string): number {
    return this.run(`DELETE FROM sessions WHERE guid = ?`, guid);
  }

  /** countActiveSessions counts sessions holding a runner. */
  countActiveSessions(): number {
    const row = this.get<{ n: number }>(
      `SELECT COUNT(*) AS n FROM sessions WHERE runner_id IS NOT NULL`,
    );
    return row?.n ?? 0;
  }

  // ---- runners ----------------------------------------------------------

  /**
   * registerRunner records a pool slot.
   *
   * Called at boot reconciliation and when `api` learns of a container the
   * orchestrator created. The orchestrator is authoritative about containers;
   * this table is authoritative about the binding between a slot and a session,
   * and the two are reconciled against each other (PLAN-v3 §2.1).
   */
  registerRunner(id: string, containerId: string, status: RunnerRow["status"]): void {
    this.run(
      `INSERT INTO runners (id, container_id, status, health, last_health_at, session_guid)
       VALUES (?, ?, ?, 'unknown', NULL, NULL)
       ON CONFLICT (id) DO UPDATE SET container_id = excluded.container_id,
                                      status = excluded.status`,
      id,
      containerId,
      status,
    );
  }

  /** listRunners returns every runner row. */
  listRunners(): RunnerRow[] {
    return this.all<RunnerRow>(`SELECT * FROM runners`);
  }

  /**
   * claimRunner atomically takes one idle runner for a session.
   *
   * The transaction and the `changes() > 0` check are both load-bearing
   * (PLAN-v2 §2.4). The random ordering spreads load so one container stays warm
   * while the rest stay cold, which is also what keeps the pool's memory
   * footprint uneven rather than uniformly wasted.
   *
   * Returns true when a slot was claimed.
   */
  claimRunner(sessionGuid: string): boolean {
    return this.transaction(() => {
      const changes = this.run(
        `UPDATE runners
            SET status = 'claimed', session_guid = ?
          WHERE id = (
            SELECT id FROM runners
            WHERE status = 'idle' AND session_guid IS NULL
            ORDER BY RANDOM()
            LIMIT 1
          )`,
        sessionGuid,
      );
      return changes > 0;
    });
  }

  /** releaseRunner frees a runner slot. */
  releaseRunner(runnerId: string): void {
    this.run(
      `UPDATE runners SET status = 'idle', session_guid = NULL WHERE id = ?`,
      runnerId,
    );
  }

  /** removeRunner deletes a runner row. */
  removeRunner(runnerId: string): number {
    return this.run(`DELETE FROM runners WHERE id = ?`, runnerId);
  }

  /**
   * reconcileRunners is the api's half of boot reconciliation (PLAN-v2 §2.5).
   *
   * The api reconciles *sessions*; the orchestrator reconciles *containers*.
   * Neither trusts the other's view alone. Specifically this function:
   *
   *   - removes runner rows whose container the orchestrator no longer has
   *   - marks sessions whose runner vanished as needing a rebind
   *   - deletes expired session rows
   *   - never resurrects an expired session
   *
   * `liveRunnerIds` is the orchestrator's view, passed in from its pool stats.
   */
  reconcileRunners(liveRunnerIds: ReadonlySet<string>, now: number): void {
    this.transaction(() => {
      for (const row of this.all<RunnerRow>(`SELECT * FROM runners`)) {
        if (liveRunnerIds.has(row.id)) continue;
        this.run(`DELETE FROM runners WHERE id = ?`, row.id);
      }

      // A session whose runner is gone is not dead, it needs a rebind: the vault
      // still holds auth.json, so re-claiming a slot restores the session without
      // a re-login (PLAN-v2 §2.3 step 4).
      //
      // Driven from the *sessions* side rather than from `runners.session_guid`,
      // because that is the direction that is always populated. `runner_id` is
      // set at claim time and survives a restart; `session_guid` on the runner row
      // is a cache of the same binding and a re-registered runner row loses it,
      // so trusting it would leave sessions pinned to a runner that no longer
      // exists — which is exactly the failure this function exists to catch.
      this.run(
        `UPDATE sessions
            SET runner_id = NULL
          WHERE runner_id IS NOT NULL
            AND runner_id NOT IN (SELECT id FROM runners)`,
      );

      // Expired sessions are deleted, never adopted. The `state <> 'erasing'`
      // guard leaves an in-flight erase alone: its own state machine finishes,
      // and deleting the row out from under it would strand the vault.
      this.run(
        `DELETE FROM sessions WHERE expires_at < ? AND state <> 'erasing'`,
        now,
      );
    });
  }
}