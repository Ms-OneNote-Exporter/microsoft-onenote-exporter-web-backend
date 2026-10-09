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
  /**
   * Where this runner is reachable, as the orchestrator's claim reported it.
   *
   * Stored rather than recomputed because the orchestrator owns the name and
   * this api must not derive one. Null on a row written before this column
   * existed, and on a slot claimed by an orchestrator too old to report one —
   * both of which mean "this api cannot call that runner", and neither of which
   * is a reason to guess.
   */
  runner_url: string | null;
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
  /** The account's notebook names as a JSON array, or NULL when never listed. */
  notebooks: string | null;
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
  session_guid    TEXT,
  -- The address the orchestrator reported for this slot. NULL is meaningful: it
  -- means this api cannot call the runner, and see #migrate.
  runner_url      TEXT
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
  -- The account's notebook **names**, as a JSON array, or NULL when never listed.
  --
  -- Distinct from the notebook column above, which is one notebook recorded for an
  -- export. The list lives here because it must survive a status refresh: the api
  -- publishes this field on the REST route AND on the event stream, and a client that
  -- rebuilds its state from the REST route would otherwise be handed an empty list the
  -- moment it looked again. That is not hypothetical - it is what a page reload did.
  --
  -- No backticks in this comment: SCHEMA is a template literal, so one here ends the
  -- string and the statement that follows is a syntax error rather than a comment.
  notebooks        TEXT,
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
    this.#migrate();
  }

  /**
   * #migrate brings an existing database up to the current schema.
   *
   * `CREATE TABLE IF NOT EXISTS` does nothing to a table that already exists, so
   * a column added to SCHEMA is absent from every database created before it —
   * and the failure that produces is a bare `no such column: runner_url` on the
   * first login after a deploy. Each step is therefore a separate `ALTER` guarded
   * by a check, so opening an old database is a no-op and opening a new one gets
   * the column from SCHEMA.
   *
   * Ad hoc rather than a version table because there is one column and no
   * destructive change to make: a schema-version counter would be more machinery
   * than the migrations need, and would be its own thing to get wrong.
   */
  #migrate(): void {
    const columns = this.all<{ name: string }>(`PRAGMA table_info(runners)`).map(
      (row) => row.name,
    );
    if (columns.length > 0 && !columns.includes("runner_url")) {
      this.#db.exec(`ALTER TABLE runners ADD COLUMN runner_url TEXT`);
    }

    const sessionColumns = this.all<{ name: string }>(`PRAGMA table_info(sessions)`).map(
      (row) => row.name,
    );
    if (sessionColumns.length > 0 && !sessionColumns.includes("notebooks")) {
      this.#db.exec(`ALTER TABLE sessions ADD COLUMN notebooks TEXT`);
    }
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

  /**
   * findByArtifact returns the session that owns an artifact id.
   *
   * Used by `/internal/authorize-download`. Deliberately keyed on the opaque
   * artifact id rather than the session guid: PLAN-v3 §5 put the guid out of the
   * download path precisely so it never reaches a proxy's access log, and a
   * lookup that needed it would put it back.
   *
   * Returns undefined for an unknown id, and the caller must treat that exactly
   * like "belongs to somebody else" — see the route for why.
   */
  findByArtifact(artifactId: string): SessionRow | undefined {
    return this.get<SessionRow>(`SELECT * FROM sessions WHERE artifact_id = ?`, artifactId);
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
   * markAuthenticated records that the runner saved a usable auth.json.
   *
   * Called when the runner publishes `login-success`, which it does only after it
   * has written the cookie jar. Before this existed, nothing in the api ever wrote
   * `'valid'`, and the only place that promoted a session to it was
   * `releaseForIdle` — which nulls `runner_id` in the same statement. So
   * `/api/session/notebooks` and `/api/export`, which require `auth_state === 'valid'`
   * **and** a bound runner, could never both be true, and answered 409 forever from a
   * session that had genuinely authenticated.
   *
   * The condition is `authenticating`, not an unconditional write, for two reasons:
   * a session already released and idle must not be dragged back to `authenticating`
   * by a late event, and a session whose auth has already been invalidated as
   * `expired` must not be revived by a straggler. A straggler is a real event — the
   * runner's stream outlives the api's knowledge of it — so the guard is what keeps
   * this from being the bug it replaces.
   *
   * Returns whether a row changed, so a caller can tell "recorded" from "ignored".
   */
  markAuthenticated(guid: string, now: number): boolean {
    return (
      this.run(
        `UPDATE sessions
            SET auth_state = 'valid', state = 'authenticated', last_activity_at = ?
          WHERE guid = ? AND auth_state = 'authenticating'`,
        now,
        guid,
      ) > 0
    );
  }

  /**
   * markAuthFailed records that the runner reported a failed login.
   *
   * Without it a failed login left `auth_state` at `authenticating` until the login
   * TTL swept it, and `releaseForIdle`'s `CASE WHEN auth_state = 'authenticating' THEN
   * 'valid'` then promoted a **failed** login to `valid` on release. That promotion is
   * now unreachable for a failed login precisely because this sets `failed` first.
   */
  markAuthFailed(guid: string, now: number): boolean {
    return (
      this.run(
        `UPDATE sessions
            SET auth_state = 'failed', last_activity_at = ?
          WHERE guid = ? AND auth_state = 'authenticating'`,
        now,
        guid,
      ) > 0
    );
  }

  /**
   * setNotebooks records the account's notebook names on the session.
   *
   * Written when the runner reports a listing, so `GET /api/session/status` is the
   * authority for this field rather than the event stream being the only copy. A
   * client rebuilds its whole state from that route — on load, and on
   * `login-success`, `session-status`, `auth-state` and `snapshot` — so a list that
   * lives only in the stream is a list that disappears on the next refresh, and
   * permanently on a reload.
   *
   * Names are stored, not objects: `POST /api/export` takes a notebook **name**, so a
   * name is the whole of the identity this route needs to carry.
   *
   * Replaces rather than merges. Two listings of one account are the same list, and
   * merging would accumulate duplicates across refreshes.
   */
  setNotebooks(guid: string, names: readonly string[]): void {
    this.run(`UPDATE sessions SET notebooks = ? WHERE guid = ?`, JSON.stringify(names), guid);
  }

  /**
   * markExportStranded resets a session whose runner was released before the
   * export could finish.
   *
   * ## Why this fix was needed
   *
   * Sessions in `state: 'exporting'` with `runner_id IS NULL` are stuck refusing
   * every future export because `POST /api/export` (`routes.ts:860`) checks
   * `export_state.state IN ('queued', 'running')` and answers 409. Without a
   * runner to complete the export, and the sweeper skipping `exporting` sessions
   * to protect them from idle timeouts, the only relief is the 12-hour absolute
   * cap. Two such rows existed on the deployed host.
   *
   * This method is called from the sweeper for sessions that match that pattern:
   * `state === 'exporting' && runner_id === null`. It is atomic so it cannot
   * race `completeExport`, and the WHERE clause protects a live export from
   * being touched.
   *
   * The data loss guard (`ELSE export_state` in the SQL) is load-bearing:
   * session `80837b89` is `export_state.state='partial'` with a real
   * `artifact_id` — a finished, downloadable result whose state is wrongly
   * `exporting`. Overwriting its export_state would destroy the download.
   *
   * ## Why the target state is pinned in SQL, not passed as a parameter
   *
   * Passing `'failed'` in a bind parameter would work, but it risks
   * re-serialising a `running` object from `export_state`, which would leave
   * the route guard still reading `running`. That would be a silent no-op fix.
   * The SQL CASE WHEN pins the replacement to `'failed'` so the guard
   * (`export_state.state IN ('queued', 'running')`) definitely sees the new
   * state.
   *
   * ## Why json_valid guard
   *
   * `json_extract` and `json_set` throw on malformed JSON. The sweep loop has
   * no per-session try/catch; a throw reaches the outer catch in index.ts and
   * abandons every remaining session for that tick. The guard keeps the sweep
   * from failing on corrupted data.
   *
   * Returns true when a row was changed, so a caller can distinguish "reset"
   * from "no-op".
   */
  markExportStranded(input: { readonly guid: string; readonly now: number; readonly idleExpiresAt: number }): boolean {
    return (
      this.run(
        `UPDATE sessions
           SET state = 'authenticated',
               last_activity_at = ?,
               idle_expires_at = ?,
               export_state = CASE
                 WHEN json_valid(export_state)
                  AND json_extract(export_state, '$.state') IN ('queued', 'running')
                   THEN json_set(export_state,
                           '$.state', 'failed',
                           '$.error', ?,
                           '$.progress', NULL,
                           '$.finishedAt', ?)
                 ELSE export_state
               END
         WHERE guid = ? AND state = 'exporting' AND runner_id IS NULL`,
        input.now,
        input.idleExpiresAt,
        "the runner was released before this export finished",
        input.now,
        input.guid,
      ) > 0
    );
  }

  /**
   * completeExport records a finished export: the terminal `export_state`, the
   * artifact that now belongs to the session, and the return to `authenticated`.
   *
   * ## Why this existed at all
   *
   * **There was no writer.** `export_state` was written three times in the whole
   * api — `queued`, `running`, and `failed` when the *start* was refused — and
   * `artifact_id` was written by nothing outside a test's own setup. So a runner
   * that exported a vault to completion, streamed it to staging and announced
   * `export-done` produced no observable change in the database at all: the
   * session stayed `state: "exporting"` with `finishedAt: null` forever, and
   * `artifact.available` stayed false, because both are read from this row.
   *
   * That is the same shape as every other bug in this project one level out. The
   * event was received, the handler ran, the SSE frame reached the browser — and
   * the assertion that mattered was never made, because nothing asserted the
   * *bytes at the far side*: a row on disk.
   *
   * ## Why `state` is reset here, in the same statement
   *
   * Because of the sweeper. `sweep()` skips any session whose `state` is
   * `exporting`, so the runner stays bound for as long as it says so — and before
   * this method, **nothing ever said otherwise**. A completed export therefore
   * pinned its slot until `TTL.absolute` erased the whole session twelve hours
   * later. On the deployed 2-slot pool that is two exports to a permanent
   * lockout: every user refused for the rest of the day.
   *
   * The reset is to `authenticated`, not to a new state, because the session is
   * still signed in and still has its runner. A subsequent export must reuse them.
   *
   * ## Why it is one statement
   *
   * `artifact_id` is what `findByArtifact` matches, and it is what makes
   * `authorize-download` answer. `export_state` is what the snapshot reports. A
   * reader between two statements would see an artifact it could not authorise
   * yet, or a `done` export with no artifact. Both are states the browser would
   * render as broken.
   *
   * Returns whether a row changed, so a caller can distinguish "recorded" from
   * "ignored" — a late `export-done` for a session already erased is expected and
   * must not be logged as a failure.
   */
  completeExport(input: {
    readonly guid: string;
    readonly artifactId: string;
    readonly partial: boolean;
    readonly partialReason: "aborted" | "quota" | "disk" | null;
    readonly notebook: string;
    readonly progress: { pages: number; sections: number; assets: number } | null;
    readonly startedAt: number;
    readonly finishedAt: number;
  }): boolean {
    return (
      this.run(
        `UPDATE sessions
            SET artifact_id = ?,
                artifact_partial = ?,
                state = 'authenticated',
                last_activity_at = ?,
                export_state = ?
          WHERE guid = ?`,
        input.artifactId,
        input.partial ? 1 : 0,
        input.finishedAt,
        JSON.stringify({
          state: input.partial ? "partial" : "done",
          partialReason: input.partialReason,
          error: null,
          id: input.artifactId,
          notebook: input.notebook,
          progress: input.progress,
          startedAt: input.startedAt,
          finishedAt: input.finishedAt,
        }),
        input.guid,
      ) > 0
    );
  }

  /**
   * markExportUnpublishable records an export that finished but produced no artifact.
   *
   * The distinct case this exists for: the **walk succeeded** and the archiving
   * failed. That is not the same as an export that failed, and conflating them
   * would send the user to re-run an hour of work over a disk or permission
   * problem — so the message says what actually happened and that re-exporting is
   * not the remedy.
   *
   * `artifact_id` is left untouched, deliberately. It is NULL here, and writing
   * anything into it would make `artifact.available` true for a download that has
   * nothing behind it: Caddy's authoriser would pass a request for an archive
   * that was never published.
   *
   * `state` is reset for the same reason `completeExport` resets it — the sweeper
   * skips `exporting`, so leaving it would pin this session's slot for the rest of
   * the day on a pool of two.
   */
  markExportUnpublishable(input: {
    readonly guid: string;
    readonly error: string;
    readonly artifactId: string;
    readonly notebook: string;
    readonly partialReason: "aborted" | "quota" | "disk" | null;
    readonly finishedAt: number;
  }): boolean {
    return (
      this.run(
        `UPDATE sessions
            SET state = 'authenticated',
                last_activity_at = ?,
                export_state = ?
          WHERE guid = ?`,
        input.finishedAt,
        JSON.stringify({
          state: "failed",
          partialReason: input.partialReason,
          error: input.error,
          id: input.artifactId,
          notebook: input.notebook,
          progress: null,
          startedAt: null,
          finishedAt: input.finishedAt,
        }),
        input.guid,
      ) > 0
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
   * runnerUrlFor reports where a session's runner is, or null.
   *
   * The single reader of `runners.runner_url`, so there is one place that decides
   * what "no address" means and one SQL join from session to runner rather than
   * a query per call site.
   *
   * Joining through `sessions.runner_id` rather than reading the runner row
   * directly matters for correctness, not tidiness: `sessions.runner_id` is the
   * binding that claim/release maintain atomically, so a lookup that did not use
   * it could report a runner belonging to a different session.
   */
  runnerUrlFor(sessionGuid: string): string | null {
    const row = this.get<{ runner_url: string | null }>(
      `SELECT r.runner_url
         FROM sessions s
         JOIN runners r ON r.id = s.runner_id
        WHERE s.guid = ?`,
      sessionGuid,
    );
    return row?.runner_url ?? null;
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
   * removeStaleRunnerRows deletes idle, unattached rows the orchestrator no longer has.
   *
   * Narrower than `reconcileRunners` on purpose, and the narrowness is the whole
   * design. This runs **every sweep**, so it must never remove a row a session could
   * still be using — and the cheap way to be sure that is not to ask about sessions
   * at all. A row that is `idle` with `session_guid IS NULL` has no container to talk
   * to and no session to break; there is nothing it can be holding open.
   *
   * A row for a slot the orchestrator is creating right now is not in that state: it
   * is `claimed`, or bound. So the race this could otherwise have is the one
   * `claimRunner`'s atomic update already guards.
   *
   * `reconcileRunners` stays the boot-time, whole-pool reconciler — it may null a
   * session's `runner_id`, because at boot both views have just been rebuilt. Doing
   * that on a timer would unbind live sessions.
   *
   * Returns how many rows went, so a caller can log it.
   */
  removeStaleRunnerRows(liveRunnerIds: ReadonlySet<string>): number {
    const stale = this.all<{ id: string }>(`SELECT id FROM runners`).filter(
      (row) => !liveRunnerIds.has(row.id),
    );
    let removed = 0;
    for (const row of stale) {
      removed += this.run(
        `DELETE FROM runners
           WHERE id = ?
             AND status = 'idle'
             AND session_guid IS NULL`,
        row.id,
      );
    }
    return removed;
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