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
   * beginLogin atomically takes the right to submit a credential for a session.
   *
   * ## Why this exists, given there was already a guard on this route
   *
   * `POST /api/session/credential` read `session.auth_state` from a snapshot taken
   * before the request did any work, checked it for `valid` / `authenticating`, and
   * only then claimed a container. **A read is not a lock.** Two submits arriving
   * together were served from the same snapshot, so both read `none`, both passed,
   * and both ran `claimForLogin` — two containers for one session, the second
   * overwriting `sessions.runner_id` so the first was leaked with nothing left
   * pointing at it.
   *
   * The window is not theoretical: the guard is above an `await` that reaches the
   * orchestrator's claim, which is ~57 s of real work (see
   * `CONTAINER_VERB_TIMEOUT_MS`). A user who double-submits, or two tabs, or a
   * retried request, all land inside it.
   *
   * So the check and the write are one statement. SQLite serialises the write, so
   * exactly one caller sees a changed row; the loser is told `false` and answers 409
   * `login-in-progress` without claiming anything.
   *
   * ## Why the accepted states are `none`, `expired` and `failed`
   *
   * Those are the three states a real user reaches when they sign in again, and all
   * three must be able to. `valid` is refused (it is already signed in) and
   * `authenticating` is refused (a submit is already on its way) — both of which the
   * *caller* distinguishes for its message; the claim itself only has to refuse
   * them.
   *
   * Returns whether a row changed: `true` means this caller owns the login, `false`
   * means somebody else already does.
   */
  beginLogin(guid: string, now: number): boolean {
    return (
      this.run(
        `UPDATE sessions
            SET auth_state = 'authenticating', state = 'authenticating',
                last_activity_at = ?
          WHERE guid = ? AND auth_state IN ('none', 'expired', 'failed')`,
        now,
        guid,
      ) > 0
    );
  }

  /**
   * cancelLogin undoes a `beginLogin` that could not finish.
   *
   * ## Why the compensation is needed at all
   *
   * `beginLogin` claims the login *before* the container is claimed, because a
   * container claim is ~57 s and holding an unclaimed session across that is the
   * race this fixes. But it also writes `auth_state = 'authenticating'`, which is a
   * **lie** until the credential is actually handed over — and a claim that then
   * fails (no idle slot, control plane unreachable, a pool that disagrees with the
   * orchestrator) leaves a session answering *"still signing in"* to every route
   * for the whole of `TTL.loginInProgress`, 15 minutes, with nothing in flight.
   *
   * That is the same trap `markExportStranded` and the export route's start-failure
   * path document, one column over: a writer that sets a state nobody will ever
   * clear, on a row the sweeper skips.
   *
   * So every exit from the claim that is not a forwarded credential calls this. It
   * is guarded on `auth_state = 'authenticating'`, so it can only ever undo *this*
   * call: a login that succeeded in the meantime has already moved to `valid`, and
   * this is a no-op against it rather than a rollback of a real session.
   *
   * Not `markAuthFailed`. That records a runner-reported *login failure*, sets
   * `failed`, releases the slot and drives `releaseForAuthFailure`. Nothing failed
   * here — no credential was ever submitted — so none of that applies.
   */
  cancelLogin(guid: string): boolean {
    return (
      this.run(
        `UPDATE sessions
            SET auth_state = 'none', state = 'created'
          WHERE guid = ? AND auth_state = 'authenticating'`,
        guid,
      ) > 0
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
   * beginExport atomically starts an export, or refuses because one is running.
   *
   * ## Why this exists, given there was already a guard on this route
   *
   * §8.1 is "one active export per session", and the route enforced it by reading
   * `session.export_state` out of a snapshot, parsing it, and answering 409 when it
   * said `queued` or `running` — and then, ~40 lines and two awaits later,
   * performing an **unconditional** `UPDATE ... WHERE guid = ?`.
   *
   * That is a read-then-check, and six simultaneous exports all read the same row,
   * all saw no active export, and all wrote one. §8.1 held only as long as nothing
   * overlapped, which is not a property a concurrency limit can have: the limit is
   * six *globally* (§8.1's second half) and nothing bounded the per-session half.
   *
   * The check and the write are now one statement, so SQLite decides which caller
   * wins. The losers get `false` and answer 409 without having queued anything.
   *
   * ## Why `json_valid` and the `IS NULL` term
   *
   * `export_state` is a TEXT column holding JSON, and `json_extract` **throws** on
   * malformed JSON. A throw out of a route handler is a 500, and a corrupt column
   * would have turned "this session may export" into "this session can never
   * export again" — the exact opposite of the old behaviour, which caught the parse
   * error and treated a corrupt column as no export.
   *
   * So `NOT json_valid(export_state)` comes first and lets the row through, which
   * is that same reading, now expressed in SQL. SQLite evaluates `OR` terms
   * left to right and stops at the first true one, so the `json_extract` calls are
   * never reached for a malformed column.
   *
   * `json_extract(es, '$.state') IS NULL` is the other half of the same care:
   * `NULL NOT IN ('queued','running')` is **NULL**, not true, so `{}` — valid JSON
   * with no `state` — would fall through the whole `OR` chain and be treated as
   * "an export is already running". A session that had never exported has exactly
   * that column.
   *
   * ## `state = 'exporting'` is in the SET list, not a separate statement
   *
   * Same reason `completeExport` does its work in one statement: a reader between
   * two writes would see an `exporting` row whose `export_state` still reads the
   * previous export's terminal state, or vice versa, and the snapshot is built from
   * both columns.
   *
   * Returns whether a row changed — `true` means this caller started the export,
   * `false` means one was already in flight (or the session is gone).
   */
  beginExport(guid: string, notebook: string, exportState: string): boolean {
    return (
      this.run(
        `UPDATE sessions
            SET state = 'exporting', notebook = ?, export_state = ?
          WHERE guid = ?
            AND (export_state IS NULL
                 OR NOT json_valid(export_state)
                 OR json_extract(export_state, '$.state') IS NULL
                 OR json_extract(export_state, '$.state') NOT IN ('queued', 'running'))`,
        notebook,
        exportState,
        guid,
      ) > 0
    );
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
   *
   * ## Why `error` is an argument
   *
   * Because the cause is not always this branch's. A session can reach
   * `state: 'exporting'` with a runner it never had — the slot was released before
   * the export began — and it can reach it with a runner that *died under it*, which
   * is a different failure with a different remedy, and one a user staring at a
   * frozen progress card is entitled to be told about in words. The default is the
   * original string, so every existing caller and every existing assertion on the
   * stored `export_state` is byte-identical; only the new caller passes one.
   *
   * The guard is on the SQL either way. `state = 'exporting' AND runner_id IS NULL`
   * is what makes this safe to call twice, and the `ELSE export_state` arm is still
   * the data-loss guard for a session whose export already finished.
   */
  markExportStranded(input: {
    readonly guid: string;
    readonly now: number;
    readonly idleExpiresAt: number;
    readonly error?: string;
  }): boolean {
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
        input.error ?? "the runner was released before this export finished",
        input.now,
        input.guid,
      ) > 0
    );
  }

  /**
   * clearSessionRunner drops a session's binding to a runner slot.
   *
   * ## Why this is its own statement, and why it exists
   *
   * `releaseRunner` frees the `runners` row and **does not** touch
   * `sessions.runner_id`. That is correct for every ordinary release, where the
   * caller's next statement is the one that unbinds the session — but it meant that
   * an api that released a dead runner's slot had *released a slot it still claimed*.
   *
   * `sessions.runner_id` is the api's only statement of which slot a session holds,
   * so a row left pointing at a slot the orchestrator has already given back is a
   * slot the pool will hand to somebody else while this session still believes it
   * owns a runner. On a two-slot pool that is the lockout: `claimRunner` cannot
   * offer a row that is still `active`, so the session that kept its phantom
   * binding is the one that can never get another.
   *
   * It is one statement on purpose. `state` is **not** written here: this says "you
   * hold no slot", not "your session is over". The state reset belongs to
   * `markExportStranded`, which carries the guards — and which requires
   * `runner_id IS NULL` to fire at all, so the two statements have to stay in that
   * order for the repair to happen.
   *
   * ## Why `runnerId` is part of the WHERE clause (F8)
   *
   * The unguarded form was `WHERE guid = ?`, which clears whatever the column
   * holds **at the moment the statement runs** — including a runner bound after
   * the caller's snapshot was taken. That is the dispossession this whole
   * mechanism exists to prevent, arriving through the repair: the sweeper holds a
   * dead-runner's slot id, a claim lands a live one on the same row in the
   * meantime, and the unstick statement takes the live binding away from a session
   * that is using it.
   *
   * Guarding on the exact id makes the write idempotent against a snapshot that
   * has aged: `0` rows changed means "this is no longer the binding I was asked to
   * clear", which is the correct outcome and leaves the newer binding alone.
   *
   * The return value is that change count, so a caller can tell a clear from a
   * no-op — `markExportStranded`'s `runner_id IS NULL` guard is meaningless if the
   * clear silently did not happen.
   */
  clearSessionRunner(guid: string, runnerId: string): number {
    return this.run(
      `UPDATE sessions SET runner_id = NULL WHERE guid = ? AND runner_id = ?`,
      guid,
      runnerId,
    );
  }

  /**
   * updateExportProgress writes an in-flight export's counts-so-far.
   *
   * ## Why this existed at all
   *
   * **The export card read "0 pages, 0 sections, 0 assets so far" for the entire
   * walk.** `export_state.progress` was written twice — zeroed at queue time and
   * zeroed again at run start (`routes.ts`) — and never again until the export
   * finished. `completeExport` wrote the real numbers at the *end*, minutes or
   * hours too late for a card that is asking "how far along is this?".
   *
   * The frontend already rendered the field; nothing behind it was ever fed. The
   * same shape as every other bug in this project one level out: the event
   * arrived, the handler ran, the frame reached the browser, and the assertion
   * that mattered — **what is in the row** — was never made.
   *
   * ## `json_set`, and why the bind is wrapped in `json()`
   *
   * `json_set` treats a bound parameter as a **SQL text value**, not as JSON. So
   * `json_set(s, '$.progress', '{"pages":3}')` stores the *string*
   * `"{\"pages\":3}"`, and the snapshot then carries
   * `progress: "{\"pages\":3}"` — a string where the contract says an object, and
   * a card that renders nothing because every read of `.pages` is undefined. It
   * is silent: no error, and the row looks written.
   *
   * So the object is bound as `JSON.stringify(progress)` — raw objects are not
   * bindable in `node:sqlite` at all — and wrapped in SQLite's `json()` in the
   * SQL, which is the only thing that re-reads it as JSON. Verified rather than
   * assumed; the two spellings differ only in the quotes they leave behind.
   *
   * ## The guard is the one `markExportStranded` already uses
   *
   * `json_valid(export_state)` and `state IN ('queued','running')`. Both halves
   * earn their place:
   *
   *   - The `#pump` replays from the last sequence number it saw, so a **late
   *     frame carrying older counts can arrive after the terminal** — on a
   *     reconnect, a runner rebind, or the ring buffer answering a `since`
   *     below the eviction point. Without the state guard that frame would
   *     rewrite a `done` export as a `running` one, and the card would go
   *     backwards: counts reset to zero, download link gone.
   *   - `json_valid` because `json_set` and `json_extract` both **throw** on
   *     malformed JSON, and this is called from the event pump, where a throw
   *     tears down the stream and loses every later event for the session.
   *
   * ## A null progress writes nothing
   *
   * `null` means "unknown", not "measured zero" — a zero that was never measured
   * is a different fact (see `routes.ts`'s abort path, which nulls it on
   * purpose). Writing `null` over a good set of counts would be the one update
   * that makes the card lie backwards.
   *
   * Returns the **change count**, and that is the whole reason it is a number
   * rather than the `boolean` its two neighbours return: `0` is the observation
   * "this row's export is no longer in flight, or is not there any more", which
   * is exactly the signal the wiring uses to stop coalescing for a session
   * (see `index.ts`). A boolean would have thrown that away.
   */
  updateExportProgress(
    guid: string,
    progress: { pages: number; sections: number; assets: number } | null,
  ): number {
    if (progress === null) return 0;
    return this.run(
      // `json(...)` rather than the bare parameter — see the note above. Without
      // it the counts are stored as a JSON *string* and nothing reads them.
      `UPDATE sessions
          SET export_state = json_set(export_state, '$.progress', json(?))
        WHERE guid = ?
          AND json_valid(export_state)
          AND json_extract(export_state, '$.state') IN ('queued', 'running')`,
      JSON.stringify(progress),
      guid,
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
   *
   * ## Why the failure counts are persisted
   *
   * `failedSections` / `failedPages` / `failedGroups` were carried all the way
   * from the runner's terminal frame, used once to decide `partial` versus
   * `done`, and then **thrown away**. So the walk the user measured — 29 pages, 8
   * assets, **1 page failed** — recorded `state: "partial"` with nothing on the
   * wire that said *what* was partial, and the card's only honest option was the
   * one it shipped with: "the export stopped before it finished", which is false.
   * The walk completed.
   *
   * They are written under `$.failed` as `{pages, sections, groups}` — the same
   * three names the snapshot publishes, because this module and `auth.ts` must
   * not be able to disagree about the spelling of a field neither of them owns.
   *
   * Always written, including as zeros: a terminal is the one moment where "zero
   * pages failed" is a **measured** zero rather than an absence, and a client
   * that had to tell those apart would be guessing.
   *
   * ## Why `export_state` is patched in SQL and not overwritten
   *
   * **The terminal write used to throw away the start of the export.** This method
   * rebuilt the whole object from its own arguments, and the argument it was given
   * for `startedAt` was `finishedAt` — a copy-paste in `export-completion.ts`. So
   * every completed export recorded `"startedAt": <finish>,"finishedAt": <finish>`:
   * a row claiming the walk took zero time, on the live host twice in a row
   * (`"startedAt":1792000690626,"finishedAt":1792000690626`).
   *
   * The real start was never missing. `routes.ts` writes `startedAt: now()` into
   * `export_state` twice — at queue and again at run start — so the value was in the
   * row being overwritten. The fix is therefore **not** to supply a better
   * argument: it is to stop overwriting a field this method does not own.
   *
   * `$.startedAt` is deliberately **absent from the `json_set` argument list**.
   * That omission *is* the fix — `json_set` leaves any path it is not given alone,
   * and adding `'$.startedAt', ?` back would recreate the original bug in a
   * spelling that looks deliberate. Deleting the copy-paste at the call site
   * without this change would have fixed nothing, because `JSON.stringify` wrote
   * whatever it was handed into every field.
   *
   * ### Why one statement and not read-then-write
   *
   * Reading the row to find its `startedAt` and writing it back is the obvious
   * spelling and it is wrong: between the two statements another writer can land,
   * and the row this method returns is then a value nobody ever measured. The
   * patch is computed by SQLite from the row it is updating, inside the same
   * statement that updates it, so there is no window.
   *
   * ### The `ELSE` arm is a fallback, not a second behaviour
   *
   * `json_set` **throws** on malformed JSON, and a throw in the completion path
   * reaches the outer catch in `index.ts` and abandons every remaining session for
   * that tick — so `json_valid` guards the patch, exactly as `markExportStranded`
   * and `updateExportProgress` already do. When the guard fails the row is not
   * well-formed JSON, which means there is no `startedAt` in it to preserve, and
   * this is the one place a fallback is owed: the whole terminal object is written
   * from the arguments, with `startedAt` taken from the caller if it passed one.
   */
  completeExport(input: {
    readonly guid: string;
    readonly artifactId: string;
    readonly partial: boolean;
    readonly partialReason: "aborted" | "quota" | "disk" | null;
    readonly notebook: string;
    readonly progress: { pages: number; sections: number; assets: number } | null;
    /**
     * The ELSE-arm fallback only, for a row whose `export_state` is not valid JSON
     * and therefore holds no start to preserve. Ignored on every ordinary path:
     * a real export's start is the one already in the row.
     */
    readonly startedAt?: number;
    readonly finishedAt: number;
    readonly failedSections: number;
    readonly failedPages: number;
    readonly failedGroups: number;
  }): boolean {
    return (
      this.run(
        `UPDATE sessions
            SET artifact_id = ?,
                artifact_partial = ?,
                state = 'authenticated',
                last_activity_at = ?,
                export_state = CASE
                  WHEN json_valid(export_state)
                   THEN json_set(export_state,
                           '$.state', ?,
                           '$.partialReason', ?,
                           '$.error', NULL,
                           '$.id', ?,
                           '$.notebook', ?,
                           -- \`json(...)\` rather than the bare parameter: a bound
                           -- parameter is a SQL text value, so without it the counts
                           -- are stored as the *string* "{\"pages\":12}" and every
                           -- read of .pages is undefined. Same reason, same spelling
                           -- as \`updateExportProgress\` above.
                           '$.progress', json(?),
                           '$.finishedAt', ?,
                           '$.failed', json(?))
                  ELSE ?
                END
          WHERE guid = ?`,
        input.artifactId,
        input.partial ? 1 : 0,
        input.finishedAt,
        input.partial ? "partial" : "done",
        input.partialReason,
        input.artifactId,
        input.notebook,
        JSON.stringify(input.progress),
        input.finishedAt,
        JSON.stringify({
          pages: input.failedPages,
          sections: input.failedSections,
          groups: input.failedGroups,
        }),
        JSON.stringify({
          state: input.partial ? "partial" : "done",
          partialReason: input.partialReason,
          error: null,
          id: input.artifactId,
          notebook: input.notebook,
          progress: input.progress,
          startedAt: input.startedAt ?? input.finishedAt,
          finishedAt: input.finishedAt,
          failed: {
            pages: input.failedPages,
            sections: input.failedSections,
            groups: input.failedGroups,
          },
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
   *
   * ## Why it patches instead of overwriting
   *
   * Same defect, one line over: this method wrote `startedAt: null` over a start
   * the row already held, and **this is the worse of the two cases**. The walk
   * here *succeeded* — it is the archiving that failed — so the elapsed time is a
   * real, known number the user might reasonably ask about, and erasing it is not
   * an omission so much as a false statement about how long the export took.
   *
   * So the write is the same `json_set` patch `completeExport` uses, preserving
   * `$.startedAt` and touching only the fields this method actually owns. There is
   * no `startedAt` input to fall back on and none is added: an argument the caller
   * would have to invent is exactly what produced the original bug.
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
                export_state = CASE
                  WHEN json_valid(export_state)
                   THEN json_set(export_state,
                           '$.state', ?,
                           '$.partialReason', ?,
                           '$.error', ?,
                           '$.id', ?,
                           '$.notebook', ?,
                           '$.progress', json(?),
                           '$.finishedAt', ?)
                  ELSE ?
                END
          WHERE guid = ?`,
        input.finishedAt,
        "failed",
        input.partialReason,
        input.error,
        input.artifactId,
        input.notebook,
        JSON.stringify(null),
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
   * `exclude` names slots that must not be picked this time. It is what lets a
   * caller that has been **refused** by the orchestrator try a different slot:
   * `ORDER BY RANDOM()` is what keeps the pool's load spread, and it is also
   * what makes a refused slot a coin flip on the next attempt rather than a
   * certainty. The set is per-call and never persisted — it says "not *this*
   * round", not "never", because the disagreement that produced it is repaired
   * by the very re-sync that re-adds the row.
   *
   * Returns true when a slot was claimed.
   */
  claimRunner(sessionGuid: string, exclude?: readonly string[]): boolean {
    // An empty list produces no clause at all, and that is deliberate rather than
    // tidy. SQLite does accept `NOT IN ()` and reads it as the empty set, but
    // PostgreSQL, MySQL and SQL Server all reject it — so a statement that is legal
    // here is not portable, and `Db` hands raw SQL to whichever driver is
    // underneath it. Omitting the clause also keeps the statement byte-identical to
    // the one the first claim attempt always ran, so the common path has nothing new
    // in it.
    //
    // The placeholders are built as `?` rather than by joining the ids, so a slot
    // name is a bound parameter and never reaches the parser. They are positional
    // and sit *after* `session_guid`, so the bindings follow that order too.
    const skipped =
      exclude !== undefined && exclude.length > 0
        ? `\n            AND id NOT IN (${exclude.map(() => "?").join(",")})`
        : "";
    return this.transaction(() => {
      const changes = this.run(
        `UPDATE runners
            SET status = 'claimed', session_guid = ?
          WHERE id = (
            SELECT id FROM runners
            WHERE status = 'idle' AND session_guid IS NULL${skipped}
            ORDER BY RANDOM()
            LIMIT 1
          )`,
        sessionGuid,
        ...(exclude ?? []),
      );
      return changes > 0;
    });
  }

  /**
   * releaseRunner frees a runner slot.
   *
   * ## Why it returns a number (F1)
   *
   * The statement is conditional the moment `expectedSessionGuid` is supplied, and
   * a `void` return cannot tell a caller which branch it took. Callers that have
   * just *released a container* need the difference: `0` means the row was not
   * ours to free — somebody re-bound it between our read and our write — and the
   * honest answer to that is "do not report this release as complete".
   *
   * `expectedSessionGuid` is the dual-reconciler guard (§4.9). Without it the
   * statement is unconditional and byte-identical to what it always was, so every
   * existing caller keeps its behaviour and none of them has to be audited for a
   * guard they did not ask for.
   */
  releaseRunner(runnerId: string, expectedSessionGuid?: string): number {
    return this.run(
      `UPDATE runners SET status = 'idle', session_guid = NULL
         WHERE id = ?${expectedSessionGuid !== undefined ? " AND session_guid = ?" : ""}`,
      ...(expectedSessionGuid !== undefined ? [runnerId, expectedSessionGuid] : [runnerId]),
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