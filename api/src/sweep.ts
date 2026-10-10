/**
 * Pool binding and the background sweepers.
 *
 * PLAN-v2 §2.1–2.3 and §2.5, for the half of the pool that belongs to `api`.
 *
 * The division is deliberate and is the v3 restatement of v2's single
 * reconciler: `api` reconciles **sessions** against SQLite, the orchestrator
 * reconciles **containers** against their labels, and neither trusts the other's
 * view alone. Neither process decides session expiry, because only `api` can see
 * a session row.
 *
 * Two clocks, and they are independent (PLAN-v2 §2.1):
 *
 *   10 min   a GUID created with no login started
 *   15 min   a login in progress
 *   30 min   authenticated and idle
 *
 * The absolute 12-hour cap is separate from both. It is what the plan means by
 * "the session survives 12 hours" — data, artifacts and countdown all persist for
 * 12 hours — while a session that exports in ten minutes releases its runner
 * within minutes. Throughput is bounded by concurrency, not by 12-hour holds.
 */

import type { Db, SessionRow } from "./db.js";
import type { OrchestratorApi, OrchestratorResult, OrchestratorStats } from "./orchestrator-client.js";
import type { SseHub } from "./sse.js";

/** The TTLs from PLAN-v2 §2.1, in milliseconds. */
export const TTL = {
  /** GUID created, no login started. */
  unclaimedSession: 10 * 60 * 1000,
  /** Login in progress — covers an MFA challenge the user walked away from. */
  loginInProgress: 15 * 60 * 1000,
  /** Authenticated and idle. */
  authenticatedIdle: 30 * 60 * 1000,
  /** Absolute session age. */
  absolute: 12 * 60 * 60 * 1000,
} as const;

/**
 * Which kind of binding a claim is performing.
 *
 * Both take an idle slot and bind it to a session; they differ **only** in what they
 * then write about the session's state, and that difference is the whole point.
 */
export type ClaimMode = "login" | "rebind";

/** What every claim entry point answers with. Named once so the two cannot drift. */
export type ClaimResult =
  | { ok: true; runnerId: string; containerId: string; runnerUrl: string | null }
  | {
      ok: false;
      reason: "pool-exhausted" | "orchestrator-unreachable" | "slot-conflict";
      /**
       * Why the pool could not fill, when the orchestrator said.
       *
       * The distinction is between "busy, try shortly" and "cannot start runners
       * at all", and it is the difference between a user waiting and an operator
       * being paged. Found by deploying to a host where every create failed: the
       * api said *every session is busy* for hours while `healthz` said `ok`.
       */
      fillError?: string;
    };

/**
 * claimBindingWrite is the one place a claim decides what it says about the session.
 *
 * ## Why this is a function and not an `if` at the call site
 *
 * Because the two cases differ in exactly one field, and that field is the one the
 * product is judged on. A login is genuinely `authenticating` — a credential is in
 * flight. A rebind is **not**: the vault still holds the `auth.json` that made the
 * session valid, and demoting it to `authenticating` makes `requireAuthenticated`
 * refuse every later route with *"still signing in"* and tells the browser to show
 * the sign-in screen for an account that never stopped being signed in.
 *
 * `auth_state` is written for a login and **omitted** for a rebind, so the column
 * keeps whatever it was. Not "restored afterwards" — a claim that wrote the wrong
 * value and then repaired it has a window in which the wrong value is readable, and
 * the window *is* the bug.
 *
 * The idle deadline differs for the same reason: a rebind is not a 15-minute
 * sign-in window.
 */
function claimBindingWrite(
  mode: ClaimMode,
  guid: string,
  slotId: string,
  now: number,
): [string, ...unknown[]] {
  return mode === "login"
    ? [
        `UPDATE sessions SET runner_id = ?, state = 'authenticating', auth_state = 'authenticating',
                            idle_expires_at = ?, last_activity_at = ?
          WHERE guid = ?`,
        slotId,
        now + TTL.loginInProgress,
        now,
        guid,
      ]
    : [
        // `state` only. `auth_state` is not in the SET list at all, so a rebind
        // cannot demote a valid session whatever it was called with.
        `UPDATE sessions SET runner_id = ?, state = 'authenticated',
                            idle_expires_at = ?, last_activity_at = ?
          WHERE guid = ?`,
        slotId,
        now + TTL.authenticatedIdle,
        now,
        guid,
      ];
}

/** Why a session was reaped. Recorded so the log line is diagnosable. */
export type ReapReason =
  | "unclaimed-expired"
  | "login-expired"
  | "idle-expired"
  | "absolute-cap-reached";

/**
 * What one sweep did.
 *
 * Mutable so `sweep` can accumulate into it; the fields are readonly to callers
 * because a report is a record, not something to be edited after the fact.
 */
export interface SweepReport {
  /** Sessions deleted because their absolute cap was reached. */
  absoluteExpired: number;
  /** Runners released because their session went idle past its TTL. */
  idleReleased: number;
  /** Sessions with no login started, deleted past 10 minutes. */
  unclaimedExpired: number;
  /** Logins in progress past 15 minutes, aborted. */
  loginExpired: number;
  /** Sessions left for the erase machine because they were mid-erase. */
  skippedErasing: number;
  /**
   * Exports whose runner was **kept** despite the session's idle deadline having passed.
   *
   * Counted rather than merely skipped, because "a session went idle" and "an export is
   * still running" look identical from the outside and were being conflated. A non-zero
   * value here is the sweeper declining to do something destructive, and it is the number
   * to look at when an export is slow.
   */
  exportsHeld: number;
  /**
   * Exports whose runner was released before they finished, and whose state was reset.
   *
   * A session in `state: 'exporting'` with `runner_id IS NULL` is stranded: the runner
   * that would have completed the export is gone, and the sweeper skips `exporting`
   * sessions to protect them from idle timeouts. This leaves them refusing every future
   * export until the 12-hour absolute cap. The fix resets their state to `'authenticated'`
   * and marks `export_state` as `'failed'` with the error string
   * `"the runner was released before this export finished"`.
   */
  exportsStranded: number;
  /**
   * Runners released because the session's login was refused.
   *
   * Counted because 'a session went idle' and 'a login was rejected' look identical from
   * outside and were being conflated — the slot was bound for the rest of a 15-minute
   * window instead of one sweep interval.
   */
  authFailedReleased: number;
  /**
   * Slots released because the orchestrator held them for a session that is gone.
   *
   * The §0.9.10 lockout, counted: an orphan-bound slot counts toward `poolSize`, so
   * one of them makes the pool look full, nothing is created, and every login 409s.
   * Recovery was an orchestrator restart. A non-zero value here means this sweep
   * broke that cycle, and every entry is a slot somebody could have been waiting for.
   */
  orphanSlotsReleased: number;
  /**
   * Rows cleaned because they named a session that no longer exists, for a slot no
   * `/release` was made about.
   *
   * The api's own half of the same leak, and the one an ordinary erase produced:
   * `runErase` removed the container and deleted the session row while leaving a
   * `runners` row behind it, still `active`, still bound to the erased GUID.
   * Observed live: three such rows against an empty `sessions` table.
   */
  phantomRowsCleaned: number;
}

/** Options for the sweeper. */
export interface SweeperOptions {
  readonly db: Db;
  readonly orchestrator: OrchestratorApi;
  readonly sse: SseHub;
  readonly log?: SweeperLog;
  readonly now?: () => number;
}

/** The log surface the sweeper uses. Narrow on purpose. */
export interface SweeperLog {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
}

/**
 * idleExpiresAt computes a session's idle deadline from its state.
 *
 * Null means "no idle deadline applies" — an export in flight has none, because
 * §2.1 says an export gets no idle kill and only the absolute cap applies.
 */
export function idleExpiresAt(session: SessionRow, now: number): number | null {
  switch (session.state) {
    case "created":
      // 10 minutes from creation. Not from last activity: the point is that a
      // GUID nobody acted on stops costing a slot.
      return session.created_at + TTL.unclaimedSession;
    case "authenticating":
      return session.last_activity_at + TTL.loginInProgress;
    case "authenticated":
      return session.last_activity_at + TTL.authenticatedIdle;
    case "exporting":
      // §2.1: "Export running — no idle kill; absolute 12h cap applies."
      return null;
    case "erasing":
    case "erased":
      return null;
  }
}

/**
 * PoolBinder owns the binding between a session and a runner slot.
 *
 * The atomic claim is in SQLite, not here: `db.claimRunner` takes the write lock
 * at BEGIN IMMEDIATE and returns whether a row changed. That is the lock
 * (PLAN-v2 §2.4), and doing it in two places would be doing it in the wrong one.
 * What this type adds is the orchestrator call that turns a claimed slot into a
 * running container, and the compensation when that call fails.
 */
/**
 * CLAIM_ATTEMPTS bounds how many slots one login may try.
 *
 * Each attempt costs a container create at most, and a conflict costs none — the
 * orchestrator refuses before doing work — so three is cheap. The number that matters
 * is that it is finite: a peer this process cannot agree with should produce an error a
 * human can see, not a request that never returns.
 */
const CLAIM_ATTEMPTS = 3;

export class PoolBinder {
  readonly #db: Db;
  readonly #orchestrator: OrchestratorApi;
  readonly #log: SweeperLog;
  readonly #now: () => number;

  constructor(options: SweeperOptions) {
    this.#db = options.db;
    this.#orchestrator = options.orchestrator;
    this.#log = options.log ?? { info: () => {}, warn: () => {} };
    this.#now = options.now ?? (() => Date.now());
  }

  /**
   * claimForLogin binds an idle runner to a session.
   *
   * Order matters and is not interchangeable:
   *
   *   1. SQLite claim — cheap, transactional, and if it fails the pool is full and
   *      nothing has changed.
   *   2. Orchestrator claim — expensive, creates a container, and if it fails the
   *      slot has to be released or it leaks.
   *
   * Doing it the other way round would create a container for a session that
   * cannot be given one, and a container is the expensive thing to leak.
   */
  async claimForLogin(
    session: SessionRow,
  ): Promise<ClaimResult> {
    return this.#claimWithRetries(session, "login");
  }

  /**
   * claimForRebind binds a runner to a session that is **already signed in**.
   *
   * ## Why this is not `claimForLogin`
   *
   * `claimForLogin` writes `auth_state = 'authenticating'` and `state = 'authenticating'`,
   * because at that point a credential is genuinely on its way and the session is not
   * yet signed in. For a rebind that would be a **lie**: the vault still holds the
   * `auth.json` that made the session valid, and nothing about re-binding a container
   * changes it.
   *
   * Observed, had this been reused as-is: a user who exported once, waited out the
   * 30-minute idle release, and clicked export again would have had their valid
   * session demoted to `authenticating` — so `requireAuthenticated` would refuse
   * every subsequent route with *"still signing in; the service is not ready yet"*,
   * and the browser would be told to show the sign-in screen for an account that was
   * signed in the whole time.
   *
   * That is bug #21's shape exactly: a field made to distinguish two states, and a
   * writer that puts the wrong one there.
   *
   * So this writes `state = 'authenticated'` and **leaves `auth_state` untouched**.
   * The idle deadline is the authenticated one, not the login one: this is not a
   * 15-minute sign-in window.
   */
  async claimForRebind(session: SessionRow): Promise<ClaimResult> {
    return this.#claimWithRetries(session, "rebind");
  }

  /**
   * #claimWithRetries is the bounded-conflict loop both entry points share.
   *
   * Kept as one function so the retry policy and its reasoning cannot drift between
   * a login and a rebind — they are the same problem, and the drift between them
   * would be invisible until one of them failed where the other worked.
   */
  async #claimWithRetries(session: SessionRow, mode: ClaimMode): Promise<ClaimResult> {
    // Retried a bounded number of times, and only for a **conflict** — the one
    // outcome that a different row can fix.
    //
    // The point is that this process and the orchestrator keep durable, independent
    // records of the same pool, and they can drift: the orchestrator renumbers or
    // removes a slot, and the SQLite row outlives it. A single attempt turns that drift
    // into a failed login for the user, every time, with no self-correction. Retrying
    // after dropping the offending row makes the drift self-healing at the moment it is
    // observed, which is the only point at which the offending row is known.
    //
    // Bounded because an unbounded loop against a disagreeing peer is a way to hang a
    // request. Three is enough to clear the drift seen in practice (a pool renumbered
    // across a restart) and short enough that a genuine disagreement surfaces as an
    // error rather than a timeout.
    for (let attempt = 1; ; attempt++) {
      const result = await this.#claimOnce(session, mode);
      if (result.ok) return result;
      if (result.reason !== "slot-conflict") return result;
      if (attempt >= CLAIM_ATTEMPTS) {
        this.#log.warn("every claimed slot was refused; giving up on this session", {
          session: session.guid,
          attempts: attempt,
        });
        return result;
      }
      // Before retrying, ask the orchestrator what the pool actually is. The row that
      // was just dropped was this process's only evidence about membership, and
      // without re-learning, `claimRunner` can only pick from what is left — which, if
      // the drift removed every row, is nothing.
      const stats = await this.#orchestrator.stats();
      if (!stats.ok || stats.value.slotIds === undefined) {
        // No membership to learn from. Retrying would only re-pick the same rows.
        return result;
      }
      const learned = syncPool(this.#db, stats.value.slotIds);
      if (learned.added > 0) {
        this.#log.info("pool slots re-learned after a refused claim", {
          session: session.guid,
          added: learned.added,
          total: learned.total,
          attempt,
        });
      }
    }
  }

  /**
   * claimOnce makes one full pass: take a SQLite row, then ask the orchestrator for
   * that slot. The retry policy lives in `claimForLogin`.
   */
  async #claimOnce(session: SessionRow, mode: ClaimMode): Promise<ClaimResult> {
    const now = this.#now();

    if (!this.#db.claimRunner(session.guid)) {
      // Pool exhaustion. §2.6: the caller shows the earliest of
      // (idle_expires_at, expires_at) minus now, or says plainly that every
      // session is busy rather than showing a countdown that will not move.
      //
      // The orchestrator is asked *why* before answering, because "busy" and
      // "cannot fill at all" are different advice and only one of them clears by
      // waiting. Found by deploying to a host where every container create failed:
      // the api said *every session is busy* for as long as the pool stayed empty,
      // while `/healthz` said `ok` and every CI job passed.
      const stats = await this.#orchestrator.stats();

      // A failed SQLite claim has two very different causes, and they need
      // different answers:
      //
      //   - the pool is genuinely full → `pool-exhausted`, retry shortly
      //   - **the api does not know the pool exists** → also `pool-exhausted`,
      //     which is why this was so hard to see
      //
      // `syncPool` at boot is not enough, because the orchestrator fills its pool
      // *after* it starts and nothing orders the api behind it. Found by
      // deploying: the api booted at 15:17:52, saw `size: 0`, inserted no rows,
      // and from the moment the orchestrator filled `slot-1` at 15:35:54 onward
      // every login answered *every session is busy* while `/stats` said
      // `size: 1`.
      //
      // So when the claim fails, learn the membership the orchestrator actually
      // reports and try once more. This costs nothing on the happy path — the
      // `stats` call was already being made — and it closes the window a
      // 30-second sweep interval would otherwise leave open.
      if (stats.ok && stats.value.slotIds !== undefined) {
        const learned = syncPool(this.#db, stats.value.slotIds);
        if (learned.added > 0) {
          this.#log.info("pool slots learned at claim time", {
            session: session.guid,
            added: learned.added,
            total: learned.total,
          });
          if (this.#db.claimRunner(session.guid)) {
            // Fall through to the rest of the claim on the success path below.
            return this.#finishClaim(session, now, mode);
          }
        }
      }

      const fillError =
        stats.ok && typeof stats.value.fillError === "string" ? stats.value.fillError : undefined;
      if (fillError !== undefined) {
        // `warn`, not `error`, and `SweeperLog` has no `error` — which is the right
        // shape here. The binder retries every sweep, so this is not a dead end;
        // it is a condition an operator must fix. Widening the interface to add
        // `error` would blur "the sweeper gave up" with "look at this".
        this.#log.warn("pool cannot fill", {
          session: session.guid,
          cause: fillError,
        });
        return { ok: false, reason: "pool-exhausted", fillError };
      }
      this.#log.info("pool exhausted", { session: session.guid });
      return { ok: false, reason: "pool-exhausted" };
    }

    return this.#finishClaim(session, now, mode);
  }

  /**
   * #finishClaim turns an already-claimed SQLite row into a running container.
   *
   * Split out of `claimForLogin` because the claim can now be reached twice: once
   * on the first attempt and once after learning the pool's membership. Both
   * paths must be identical from here — the row is claimed, so everything that
   * follows assumes exactly that.
   */
  async #finishClaim(
    session: SessionRow,
    now: number,
    mode: ClaimMode,
  ): Promise<ClaimResult> {
    const claimed = this.#db.get<{ id: string }>(
      `SELECT id FROM runners WHERE session_guid = ?`,
      session.guid,
    );
    if (claimed === undefined) {
      // Unreachable: claimRunner returned true, so a row changed. Made loud
      // rather than assumed, because the alternative is a session that believes
      // it has a runner it does not.
      this.#log.warn("claim reported success but no runner row is bound", {
        session: session.guid,
      });
      return { ok: false, reason: "orchestrator-unreachable" };
    }

    // The slot is **named**, not left to the orchestrator's own random pick.
    //
    // `claimRunner` claimed a SQLite row, and that row's id *is* the slot identity
    // this process will hand back on `release`. If the orchestrator then chose a
    // different slot, that transaction was locking a row nobody releases — and the
    // mismatch is invisible until a release 409s against a slot with no container,
    // while the slot that does have the container leaks.
    const result = await this.#orchestrator.claim(
      session.guid,
      new Date(session.expires_at),
      claimed.id,
    );

    if (!result.ok) {
      // A **conflict** means the slot named is not usable: either the orchestrator has
      // never heard of it, or it holds it for someone else. Both say the same thing
      // about this process's row — it describes a slot that is not available — so the
      // row is *removed* rather than released, and another attempt is made.
      //
      // Release would leave the row `idle` and claimable, and the next `claimRunner`
      // picks by `ORDER BY RANDOM()`, so the stale row would be offered again and again
      // while the orchestrator kept refusing it. Observed on a live host: `api` held
      // `slot-2` with `runner_url = http://msout-runner-slot-2:3100` while the
      // orchestrator reported `size: 1, slotIds: ["slot-1"]`, so the login could not
      // start at all. Every attempt burned a session against the same bad row.
      //
      // Removing the row is what the orchestrator's answer means: it does not have this
      // slot, so this process should stop offering it. `syncPool` puts back the ones
      // that do exist.
      if (result.error.kind === "conflict") {
        this.#db.removeRunner(claimed.id);
        this.#log.warn("orchestrator refused the claimed slot; row dropped", {
          session: session.guid,
          runner: claimed.id,
          error: result.error.kind as string,
        });
        return { ok: false, reason: "slot-conflict" };
      }

      // Compensate. A slot claimed in SQLite but never given a container is a
      // slot that never becomes available again — the pool shrinks by one per
      // failed call and nothing would notice.
      this.#db.releaseRunner(claimed.id);
      this.#log.warn("orchestrator claim failed, slot released", {
        session: session.guid,
        runner: claimed.id,
        error: result.error.kind as string,
        // The cause is the whole diagnosis and it used to be dropped here.
        //
        // `error: "unreachable"` was all this line carried while the client was
        // aborting at 15 s, so a claim that had died mid-provision and a claim that
        // had never found the orchestrator were the same log line. The number that
        // explained the whole incident — a budget shorter than the work — was
        // inside the `cause` and was thrown away.
        //
        // Only `unreachable` carries one. Built conditionally rather than with an
        // explicit `undefined`, because `exactOptionalPropertyTypes` treats
        // `cause: undefined` as a different value from an absent key, and "the
        // failure named no cause" must stay distinguishable from "the cause is
        // empty".
        ...(result.error.kind === "unreachable" ? { cause: result.error.cause } : {}),
      });
      return { ok: false, reason: "orchestrator-unreachable" };
    }

    // The orchestrator returns its own container id and the address of the runner
    // it created; both are recorded so boot reconciliation has something to
    // compare against, and so the adapter can reach the container without
    // deriving a name the orchestrator owns.
    //
    // An absent `runnerUrl` is stored as NULL rather than filled in from
    // `slotId`. That is the whole reason the field is in the claim response
    // instead of being built here, and the NULL is what makes the difference
    // visible: the session gets a runner it cannot call, which reports itself,
    // rather than a 401 from a guessed hostname.
    // **The orchestrator's answer is what gets recorded, not `claimed.id`.**
    //
    // Naming the slot makes them agree, and recording the answer means they agree
    // *even when they do not* — an orchestrator that has not shipped the field picks
    // its own slot, and recording that is correct while recording our guess would not
    // be. The disagreement is then visible as a row whose id differs from
    // `sessions.runner_id`, rather than as a silent mis-binding.
    //
    // `slotId` is absent only from an orchestrator too old to report it, which is a
    // rolling-deploy state and not a defect — see ClaimResponse.
    const slotId = result.value.slotId ?? claimed.id;
    if (slotId !== claimed.id) {
      // The two disagree, so the bookkeeping is put right in both directions.
      //
      // The wrongly-claimed row goes back to idle: nothing is bound to it, and a row
      // stuck in `claimed` is capacity the pool believes it has lost.
      //
      // And the slot actually in use is **claimed for this session**. Leaving that to
      // one-sided updates was a hole in the first version of this fix: `claimRunner` had
      // set `session_guid` on the *claimed* row, so the row now holding the container
      // stayed idle and unclaimed — and the pool would have handed it to a second
      // session while this one was still using it. Both writes, or the pool does not
      // know which slot it has given away.
      this.#db.run(
        `UPDATE runners SET session_guid = NULL, status = 'idle' WHERE id = ?`,
        claimed.id,
      );
      this.#db.run(
        `UPDATE runners SET session_guid = ?, status = 'claimed' WHERE id = ?`,
        session.guid,
        slotId,
      );
      this.#log.warn("orchestrator used a different slot than the one claimed", {
        session: session.guid,
        claimed: claimed.id,
        used: slotId,
      });
    }

    this.#db.run(
      `UPDATE runners
          SET container_id = ?, runner_url = ?, status = 'active', health = 'unknown'
        WHERE id = ?`,
      result.value.containerId,
      result.value.runnerUrl ?? null,
      slotId,
    );
    this.#db.run(...claimBindingWrite(mode, session.guid, slotId, now));

    this.#log.info("runner claimed", {
      session: session.guid,
      runner: slotId,
      container: result.value.containerId,
      // Which kind of claim, because the two write different state and an operator
      // reading "runner claimed" cannot otherwise tell a sign-in from a rebind.
      mode,
      // Logged rather than assumed: an absent address means every subsequent
      // runner call fails, and the warning belongs next to the claim that
      // caused it rather than in the log of a later login attempt.
      ...(result.value.runnerUrl === undefined ? { runnerUrl: "absent" } : {}),
    });
    return {
      ok: true,
      runnerId: slotId,
      containerId: result.value.containerId,
      runnerUrl: result.value.runnerUrl ?? null,
    };
  }

  /**
   * releaseForIdle returns a runner without ending the session.
   *
   * §2.3 step 3→4: "Idle TTL hit → container removed or recycled, session row
   * retained. Activity again → new runner claimed, same session volume remounted,
   * so auth.json, notebook cache and artifacts are all still there."
   *
   * The session row is deliberately kept. Deleting it would log the user out
   * every time their runner idles, which is the opposite of what the TTL is for.
   */
  async releaseForIdle(session: SessionRow): Promise<boolean> {
    if (session.runner_id === null) return false;

    const released = await this.#orchestrator.release(session.runner_id);
    if (!released.ok && released.error.kind !== "conflict") {
      // The slot stays bound in SQLite, so the next sweep tries again. Better
      // than releasing it here: a container that still exists must not be
      // forgotten, or reconciliation will not find it.
      this.#log.warn("orchestrator release failed, slot retained for retry", {
        session: session.guid,
        runner: session.runner_id,
        error: released.error.kind,
      });
      return false;
    }

    this.#db.releaseRunner(session.runner_id);
    this.#db.run(
      `UPDATE sessions SET runner_id = NULL, state = 'authenticated',
                          auth_state = CASE WHEN auth_state = 'authenticating' THEN 'valid' ELSE auth_state END,
                          idle_expires_at = ?
        WHERE guid = ?`,
      this.#now() + TTL.authenticatedIdle,
      session.guid,
    );
    this.#log.info("runner released, session retained", {
      session: session.guid,
      runner: session.runner_id,
    });
    return true;
  }

  /**
   * releaseForAuthFailure returns a runner after a login failure.
   *
   * A failed login with `auth_state = 'failed'` never produced a usable session:
   * the vault's `auth.json` was refuted, and the container was a Chromium process
   * that should not be kept warm for it. The container is destroyed rather than
   * recycled (`Pool.Release` destroys it) — correct here: the vault's auth.json
   * just failed and the container is a Chromium process that should not be kept
   * warm for it. The session volume is untouched, so the row is retained and a
   * retry can rebind.
   *
   * ## Why this is not a copy of `releaseForIdle`
   *
   * That method's full UPDATE also writes `state='authenticated'` and arms a
   * 30-minute `idle_expires_at`, which beside `auth_state='failed'` would
   * report a signed-in-looking snapshot for a refused login. This method only
   * nulls `runner_id` and leaves `state` and `auth_state` exactly as
   * `markAuthFailed` wrote them — deliberately the smallest delta, so nothing
   * downstream (including the `failed`→`expired` transition at +15min, tracked
   * as issue #49) moves as a side effect of fixing this.
   *
   * ## Why the release was late, not missing, before this fix
   *
   * `markAuthFailed` records the failure at once but nothing freed the slot, so
   * a mistyped password held it for the full 15-minute `TTL.loginInProgress` —
   * a quarter-hour of lockout on the deployed 2-slot pool, from one typo. The
   * existing login-expiry branch above does eventually release it 15 minutes
   * later, because it is guarded on `state` (which `markAuthFailed` does not
   * change) rather than on `auth_state`. So the release was **late, not
   * missing** — and this fix simply makes it immediate.
   */
  async releaseForAuthFailure(session: SessionRow): Promise<boolean> {
    if (session.runner_id === null) return false;
    const released = await this.#orchestrator.release(session.runner_id);
    if (!released.ok && released.error.kind !== "conflict") {
      this.#log.warn("release after a failed login failed, slot retained for retry", {
        session: session.guid,
        runner: session.runner_id,
        error: released.error.kind,
      });
      return false;
    }
    this.#db.releaseRunner(session.runner_id);
    this.#db.run(`UPDATE sessions SET runner_id = NULL WHERE guid = ?`, session.guid);
    this.#log.info("runner released after a failed login", {
      session: session.guid,
      runner: session.runner_id,
    });
    return true;
  }

  /**
   * releaseForAbsence returns a runner for a session that is going away.
   *
   * Distinct from `releaseForIdle`: the session row goes too, so the vault has to
   * be erased rather than kept for a rebind. The erase machine does the deletion;
   * this only returns the slot.
   */
  async releaseForAbsence(session: SessionRow): Promise<boolean> {
    if (session.runner_id === null) return false;
    const released = await this.#orchestrator.release(session.runner_id);
    if (!released.ok && released.error.kind !== "conflict") {
      this.#log.warn("release during session teardown failed, retained for retry", {
        session: session.guid,
        runner: session.runner_id,
        error: released.error.kind,
      });
      return false;
    }
    this.#db.releaseRunner(session.runner_id);
    return true;
  }
}

/**
 * sweep applies every TTL once.
 *
 * **Called on a timer only.** `index.ts` installs the 30 s interval and nothing
 * else: the first tick lands at about t+30s, and boot calls `reconcile`, not this.
 * The docstring used to claim "and at boot", which was true of neither — and the
 * difference is load-bearing now, because `reclaimOrphanBindings` is the only
 * thing that heals a slot adopted bound at a cold start, so how soon after a
 * restart the pool is usable again deserves an honest answer.
 *
 * Each rule is independent and a failure in one is logged and the rest continue,
 * because the cost of a skipped cleanup is lower than the cost of a sweeper that
 * stops.
 */
export async function sweep(options: SweeperOptions, binder: PoolBinder): Promise<SweepReport> {
  const { db, sse } = options;
  const log = options.log ?? { info: () => {}, warn: () => {} };
  const now = options.now?.() ?? Date.now();

  const report: SweepReport = {
    absoluteExpired: 0,
    idleReleased: 0,
    unclaimedExpired: 0,
    loginExpired: 0,
    skippedErasing: 0,
    exportsHeld: 0,
    exportsStranded: 0,
    authFailedReleased: 0,
    orphanSlotsReleased: 0,
    phantomRowsCleaned: 0,
  };

  // Learn the pool's current membership, not just its size.
  //
  // `syncPool` used to run once, at boot. That is a latent outage whenever the
  // orchestrator's pool is not yet full when the api starts — which is the
  // normal case, because the orchestrator fills asynchronously after its own
  // start and the api is not ordered behind it. Found by deploying: the api
  // started at 15:17:52, saw `size: 0`, and inserted no rows; the orchestrator
  // filled `slot-1` at 15:35:54. From then on `claimRunner` found nothing idle and
  // every login 503'd with *every session is busy* while `/stats` said `size: 1`
  // and `/healthz` said `ok`.
  //
  // The symptom is uniquely bad: a pool-exhausted 503 is exactly what a *full*
  // pool looks like, so the evidence points at demand rather than at the api
  // never having been told the pool existed.
  //
  // `syncPool` upserts and never removes, so running it against a pool that has
  // shrunk leaves rows behind — which is what §2.5's reconciler is for, and it
  // means a slot released mid-session is not deleted out from under it.
  const stats = await options.orchestrator.stats();
  if (stats.ok && stats.value.slotIds !== undefined) {
    const pool = syncPool(db, stats.value.slotIds);
    if (pool.added > 0) {
      log.info("pool slots learned", { added: pool.added, total: pool.total });
    }

    // **Prune the rows the orchestrator does not have.** `syncPool` only ever adds,
    // and #47 taught that the reconciler — which does prune — runs **at boot only**.
    // So between boots the two views drift again: the sweeper learns whatever `/stats`
    // reports, and a slot the orchestrator has since renumbered or dropped stays in
    // this table for ever.
    //
    // Observed on the deployed host with the api up for an hour: the orchestrator
    // reported `slotIds: ["slot-36","slot-38"]` and this table held
    // `slot-36, slot-38, slot-39`. `claimRunner` picks by `ORDER BY RANDOM()`, so
    // roughly one login in three offered `slot-39`, was refused with a 409, and the
    // user saw `the service's view of its runner pool is out of date` — the exact
    // symptom #47 was merged to remove, back again inside an hour.
    //
    // ## Why this is narrower than the boot reconciler
    //
    // `reconcileRunners` deletes rows *and* nulls the `runner_id` of any session
    // pointing at one — correct at boot, where both views are freshly rebuilt. Doing
    // that every thirty seconds would unbind a session whose runner is merely being
    // re-provisioned, and the previous author declined to prune here for exactly that
    // reason (see the comment above).
    //
    // So this only removes rows that **cannot** be anybody's runner: `idle`, with no
    // session attached. A row in that state has no container to talk to and no
    // session to break, so removing it cannot strand anything — and a slot being
    // created right now is not idle-with-no-session, it is claimed or claiming.
    const pruned = db.removeStaleRunnerRows(new Set(stats.value.slotIds));
    if (pruned > 0) {
      log.info("runner rows for slots the orchestrator no longer has, removed", {
        removed: pruned,
        live: stats.value.slotIds.length,
      });
    }
  }

  // Every session, because each TTL depends on a different field.
  const sessions = db.all<SessionRow>(`SELECT * FROM sessions`);

  for (const session of sessions) {
    // An erase in progress is the erase machine's business. §11 owns it, and a
    // sweeper deleting the row mid-machine would strand the vault — the machine
    // stops, and nothing records that it was meant to finish.
    if (session.state === "erasing") {
      report.skippedErasing++;
      continue;
    }

    // The absolute cap first, because it subsumes the others: an expired session
    // is gone regardless of what else is true of it.
    if (session.expires_at <= now) {
      await binder.releaseForAbsence(session);
      db.deleteSession(session.guid);
      sse.emit(session.guid, "session-status", { state: "expired" });
      sse.drop(session.guid);
      report.absoluteExpired++;
      log.info("session expired at the absolute cap", { session: session.guid });
      continue;
    }

    // A session with no login started holds nothing. §2.1: 10 minutes.
    if (session.state === "created" && session.created_at + TTL.unclaimedSession <= now) {
      await binder.releaseForAbsence(session);
      db.deleteSession(session.guid);
      sse.drop(session.guid);
      report.unclaimedExpired++;
      log.info("session expired without a login", { session: session.guid });
      continue;
    }

    // A login that never finished — an MFA prompt the user walked away from, or
    // a Microsoft interstitial that never resolved. 15 minutes.
    if (session.state === "authenticating" && session.last_activity_at + TTL.loginInProgress <= now) {
      // The runner is released rather than killed outright, so a user returning
      // within the session's remaining life keeps their vault. What changes is
      // auth_state: their auth.json may be half-written, and the next login
      // should not trust it.
      await binder.releaseForIdle(session);
      db.run(`UPDATE sessions SET auth_state = 'expired' WHERE guid = ?`, session.guid);
      sse.emit(session.guid, "challenge-expired", {});
      sse.emit(session.guid, "auth-state", { state: "expired" });
      report.loginExpired++;
      log.info("login expired", { session: session.guid });
      continue;
    }

    // **An export whose runner is already gone is stranded, not in flight.**
    //
    // The branch below holds a running export's runner. This one is the opposite case,
    // and it is checked first because the branch below `continue`s past everything.
    //
    // `state: 'exporting'` with `runner_id IS NULL` means the container that was to
    // finish this export is gone, and nothing else will ever finish it: the runner is
    // the only writer of `export-done`/`export-partial`, and there is no runner. The
    // row then sits wrong in two places at once, and both are load-bearing:
    //
    //   - `export_state` still says `queued`/`running`, so `POST /api/export` refuses
    //     every future export with `an export is already running` (routes.ts:860) —
    //     including for a notebook the user never started an export on.
    //   - `state` is still `exporting`, so *this* sweeper skips the session, and its
    //     idle deadline never applies.
    //
    // Observed on the deployed host: two sessions in exactly this shape, refusing all
    // exports, no log line and no event to explain why, until `TTL.absolute` erased
    // them up to 12 hours later.
    //
    // Proven rather than inferred: `tests/stranded-export.test.ts` drives the real
    // route handler seeded with a real stranded row's `export_state` and asserts the
    // 409, then runs a sweep tick and asserts it is gone. Removing this branch turns
    // it red.
    //
    // Only the runner-less case is repaired. A runner row that still exists while its
    // container is gone is deliberately **not** handled here: `runner_id` is only ever
    // nulled by `reconcileRunners`, which runs at boot, so this branch covers the
    // post-boot subclass and nothing wider. Widening it to "not in the live slot set"
    // was rejected — see the comment at the prune above, on a claimed slot being
    // legitimately absent from `/stats` mid-re-provision.
    if (session.state === "exporting" && session.runner_id === null) {
      // `markExportStranded` carries the guard in SQL, not only here, so it cannot be
      // raced by `completeExport` or pointed at a live export by a future caller. Its
      // `ELSE` branch is the data-loss guard: a stranded session whose export already
      // *finished* — `80837b89` on the deployed host is `partial` with a real
      // `artifact_id`, i.e. a working download — keeps its `export_state` and
      // `artifact_id` byte-for-byte, and only its `state` is repaired.
      const changed = db.markExportStranded({
        guid: session.guid,
        now,
        idleExpiresAt: now + TTL.authenticatedIdle,
      });
      if (changed) {
        report.exportsStranded++;
        log.warn("stranded export reset; its runner was already gone", {
          session: session.guid,
        });
        // An event, because the frontend is SSE-only and the one writer that would
        // have ended the progress card is exactly what is missing. `session-status` is
        // the right name: the client treats it as "re-read the snapshot"
        // (App.tsx:293). Not `export-aborted`, which renders as "Export stopped
        // early" — a user-action framing that is false here, and the same pushback
        // routes.ts:1152 records for a quota or disk abort.
        sse.emit(session.guid, "session-status", { state: "authenticated" });
      }
      continue;
    }

    // **A running export is not an idle session.**
    //
    // This guard is what stands between a long export and having its runner taken away
    // underneath it, and it is checked explicitly because the field it used to rely on
    // cannot do the job. That version was:
    //
    //     // …only when the idle deadline has been set — an export in flight has none.
    //     if (session.idle_expires_at !== null && session.idle_expires_at <= now) { … }
    //
    // It assumed an exporting session has no `idle_expires_at`. It does, and always has:
    // `touchSession` writes `idle_expires_at = COALESCE(?, idle_expires_at)`, so passing
    // null **cannot clear it** — a deadline set once survives for the session's whole
    // life. So a session that had been idle before starting an export carried a deadline
    // straight through it, and 30 minutes later the sweeper released the runner mid-run.
    //
    // Observed on the deployed host: an export accepted at 13:20 was still `running` at
    // 13:39, its container had been replaced, and the slot had been claimed by another
    // session. The export was not slow; it was dispossessed.
    //
    // An export produces no HTTP traffic for minutes — that is what it is — so idleness
    // is the *expected* state of one, and cannot be evidence that nobody wants it.
    //
    // The backstop is not lost: `TTL.absolute` still erases the session, and the runner's
    // own export timeout ends the work. This only stops the pool reclaiming a slot that
    // is in use.
    if (session.state === "exporting") {
      report.exportsHeld++;
      log.info("export in flight; holding its runner", {
        session: session.guid,
        idleExpiredAgo: now - (session.idle_expires_at ?? now),
      });
      continue;
    }

    // Idle, and only when a deadline was set at all.
    if (session.idle_expires_at !== null && session.idle_expires_at <= now) {
      if (await binder.releaseForIdle(session)) {
        report.idleReleased++;
      }
    }

    // A login that failed is over, and the slot is worth more to somebody else.
    //
    // The login-expiry branch above is guarded on `state`, which `markAuthFailed` does
    // not change — so without this the slot sits bound for the rest of the 15-minute
    // window, which on the deployed two-slot pool is a quarter-hour of lockout for
    // everyone from one mistyped password.
    if (session.auth_state === "failed" && session.runner_id !== null) {
      if (await binder.releaseForAuthFailure(session)) {
        report.authFailedReleased++;
      }
      continue;
    }
  }

  // After the loop, never inside it. A session row deleted *by this very tick* — the
  // absolute cap, or the ten-minute rule, each of which can leave a runner row
  // behind pointing at a session that no longer exists — is the shape this is here
  // to reclaim, and running it after the loop catches it in the same tick rather
  // than making the next one responsible for cleaning up after this one.
  const orphans = await reclaimOrphanBindings(db, options.orchestrator, log, stats);
  report.orphanSlotsReleased += orphans.released;
  report.phantomRowsCleaned += orphans.cleaned;

  return report;
}

/**
 * reclaimOrphanBindings returns a slot bound to a session that no longer exists.
 *
 * ## The leak
 *
 * Two records describe the same fact and neither had a reconciler. The
 * orchestrator's `runners`-equivalent is a slot in `StateBound`; this process's is
 * a `runners` row with a `session_guid`. Either can outlive the session it names:
 *
 *   - **B — the orchestrator's view.** A slot stays bound until something releases
 *     it. `EnsurePool` counts *slots*, so an orphan-bound slot is capacity the pool
 *     believes it has and never refills. Observed on the deployed host: two such
 *     slots on a pool of two, every login 409ing, and recovery was an orchestrator
 *     restart — which is the one thing an operator is told not to do.
 *   - **A — this process's own rows.** `runErase` removes the container and deletes
 *     the session row, and used to leave the `runners` row `active` and bound to the
 *     erased GUID. Observed live: three such rows, `sessions` empty.
 *
 * Both are reclaimed here, every sweep, through the **existing signed `/release`
 * verb**. No new verb, no new authority: the api stays the session authority
 * (ARCHITECTURE §4.9) and merely asks the orchestrator to give a slot back.
 *
 * ## One liveness predicate for both
 *
 * **live = a `sessions` row exists and it is not `erasing`.** One predicate on
 * purpose — two spellings of "is this session alive" is how the two halves drift,
 * and then a third shape is missed.
 *
 * `erasing` is the half that is easy to get backwards. Such a row is *not* dead: it
 * belongs to the erase machine, and the machine's own `/remove` is what takes that
 * slot, not this sweep — §11 owns an `erasing` row, exactly as the loop above
 * does. So a session that has entered `erasing` **keeps** its slot here, and the
 * only binding this function acts on is one whose session has no row at all.
 *
 * The plan states this both ways — `live = exists AND state <> 'erasing'`, and, in
 * its risk table, that an `erasing` slot is "excluded from *dead*". The second is
 * the one that decides here: read literally the first would make an `erasing` row
 * the most reclaimable case of all, which is two owners of one teardown, with the
 * loser being whichever started second.
 *
 * ## Why there is no age threshold
 *
 * Deliberately absent. "How long may a slot stay bound" would need a second clock,
 * a number, and an answer for the session that legitimately sits bound for its
 * whole twelve hours. Liveness needs no number, and it survives a restart of either
 * process — which a timeout does not.
 *
 * ## Ordering dependencies, so this cannot be silently moved
 *
 *   - **It runs after the session loop**, so a row deleted this tick is caught this
 *     tick. See the call site.
 *   - **`syncPool` ran earlier in the same sweep**, under the same `stats.ok &&
 *     slotIds !== undefined` guard. So a `runners` row exists for **every** slot the
 *     orchestrator reports — including one this process adopted at boot and never
 *     claimed, which is exactly the §0.9.10 shape: an orphan whose row has to exist
 *     before its binding can be cleaned. Release → clean is never a clean with
 *     nothing to clean.
 */
async function reclaimOrphanBindings(
  db: Db,
  orchestrator: OrchestratorApi,
  log: SweeperLog,
  stats: StatsResult,
): Promise<{ released: number; cleaned: number }> {
  // Nothing to work from. A failed `/stats` is **not** "no slots are bound": it is
  // "we do not know", and the whole point of this function is that it acts on a
  // *known* disagreement. An orchestrator outage must not turn a full pool into a
  // release storm — nor, at the other end, strand a slot that was about to be freed.
  if (!stats.ok) return { released: 0, cleaned: 0 };

  let released = 0;
  let cleaned = 0;

  // ---- B: the orchestrator's view ---------------------------------------
  //
  // Read from the snapshot only. No `/stats` here — the value `sweep` already took
  // is this tick's view, and a second call would be a second opinion taken after
  // the session loop rather than before it.
  //
  // **Two passes, deliberately.** The first only *detects*; the second re-reads and
  // acts. Collapsing them into one loop would make the re-check below unreachable —
  // nothing would happen between a check and its own `/release` — and the check that
  // cannot fail is not a check. What sits between them is every earlier entry's
  // round trip, which is the whole window.
  const orphans: { slotId: string; guid: string }[] = [];
  for (const [slotId, guid] of Object.entries(stats.value.boundSessions ?? {})) {
    if (!sessionOwnsSlot(db, guid)) orphans.push({ slotId, guid });
  }

  for (const { slotId, guid } of orphans) {
    // **Re-check immediately before acting**, with a fresh read rather than the one
    // above — which was taken before the earlier entries' `/release` calls, each of
    // them a round trip. A session that has appeared in that window owns its slot:
    // either a live one, or one the erase machine is part-way through and whose
    // `/remove` is already in flight. The window is small and the cost of being
    // wrong is a live session dispossessed, which is the one failure this must
    // never have — so the cheap answer is to re-read and ask again rather than trust
    // a value computed before an `await`.
    if (sessionOwnsSlot(db, guid)) {
      log.warn("a bound slot stopped looking orphaned mid-sweep; leaving it alone", {
        slot: slotId,
        session: guid,
      });
      continue;
    }

    const result = await orchestrator.release(slotId);
    if (!result.ok && result.error.kind !== "conflict") {
      // Retain the row. A container that may still exist must not be forgotten:
      // forgetting it is how a slot ends up with no record on either side, and the
      // next tick will ask again.
      log.warn("orphan slot could not be released; retained for the next sweep", {
        slot: slotId,
        session: guid,
        error: result.error.kind,
      });
      continue;
    }
    // A `conflict` is success. It means the slot is already gone or already
    // unbound — precisely the state this branch wanted — and tolerating it is what
    // `releaseForIdle` already does, so the two do not disagree about what a 409
    // means.
    released++;
    // `releaseRunner`, not `removeRunner`: the orchestrator's slot is a pool
    // *position*, not a container, and the row is what makes the next `claimRunner`
    // able to find it. Removing the row would delete the slot from this process's
    // view of the pool, and `syncPool` would only put it back on a later tick.
    db.releaseRunner(slotId);
    log.warn("released a slot bound to a session that no longer exists", {
      slot: slotId,
      session: guid,
    });
  }

  // ---- A: this process's own rows ---------------------------------------
  //
  // Gated on `slotIds !== undefined` — the second half of the same
  // `stats.ok && slotIds !== undefined` condition `syncPool` uses above, the first
  // half being the early return. Not a formality: while this process cannot say
  // which slots exist, cleaning a row for a slot the orchestrator may still be
  // holding would release a live runner's bookkeeping under a container that keeps
  // running.
  if (stats.value.slotIds !== undefined) {
    // The predicate of detection B, expressed in SQL so it can run over every row
    // at once. `NOT EXISTS` with **no state filter**, which is not an oversight: a
    // row naming a session that exists but is `erasing` is an owner, not an orphan,
    // and the erase machine is the thing that frees it. `EXISTS` alone is what makes
    // a mid-erase row survive this branch — the same exclusion the read above
    // makes, so the two halves cannot disagree about which sessions are dead.
    const phantom = db.all<{ id: string; session_guid: string }>(
      `SELECT id, session_guid FROM runners
        WHERE session_guid IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM sessions s WHERE s.guid = runners.session_guid
          )`,
    );
    for (const row of phantom) {
      // No `/release` for these. The orchestrator does not report the slot as
      // bound — in the erase-shaped leak it has already removed it — so a release
      // would be asking about a slot it has answered about and told us nothing
      // about. The row is the whole of the damage, and it is this process's own.
      db.releaseRunner(row.id);
      cleaned++;
      log.warn("cleared a runner row bound to a session that no longer exists", {
        slot: row.id,
        session: row.session_guid,
      });
    }
  }

  // The two counters are deliberately disjoint.
  //
  // `released` counts slots taken back from the orchestrator; `cleaned` counts rows
  // that were phantoms in their own right. Detection B's `releaseRunner` is not
  // counted a second time: in the §0.9.10 shape the row it cleans was created
  // seconds earlier by `syncPool` in this same tick, and calling that a phantom row
  // would inflate the number an operator reads as "how much leaked".
  return { released, cleaned };
}

/**
 * sessionOwnsSlot is the one definition of "this session still holds that slot".
 *
 * `state` is read rather than only existence checked so the reader can see *why*
 * the row is here: a session in `erasing` is mid-teardown, its slot is still
 * physically running, and the erase machine's `/remove` is the thing that takes it.
 * Any row counts as an owner. A session with no row at all is the only binding the
 * sweeper may reclaim, because only then is there nothing left to lose.
 */
function sessionOwnsSlot(db: Db, guid: string): boolean {
  return db.get<{ state: string }>(`SELECT state FROM sessions WHERE guid = ?`, guid) !== undefined;
}

/**
 * syncPool makes the `runners` table agree with the orchestrator's slot list.
 *
 * Why this exists, because it is not obvious: `runners` starts empty, and
 * `claimRunner` only ever *moves* a row from idle to claimed. Nothing inserts.
 * So without this the pool is permanently empty, `claimForLogin` always returns
 * `pool-exhausted`, and every login 503s — a failure that presents as "the pool is
 * busy" rather than as "the api was never seeded".
 *
 * The slot ids must be the orchestrator's, because `release` and `recycle` take a
 * `slotId` and `sessions.runner_id` holds this table's id. An id invented here
 * would be released against a slot that does not exist, and the orchestrator would
 * answer 409 for a call that should have succeeded.
 *
 * Note what is *not* taken: container ids. §2.1 restricts the api from holding
 * container identities it cannot verify, and a slot id is not that — it is a name
 * the api has to know anyway to release anything at all.
 *
 * Upserts rather than clearing the table first, so a boot that overlaps a live
 * claim cannot free a slot somebody is using.
 */
export function syncPool(
  db: Db,
  slotIds: readonly string[],
): { added: number; total: number } {
  let added = 0;
  for (const id of slotIds) {
    if (db.get<{ id: string }>(`SELECT id FROM runners WHERE id = ?`, id) === undefined) {
      db.registerRunner(id, "", "idle");
      added++;
    }
  }
  return { added, total: db.all(`SELECT id FROM runners`).length };
}

/**
 * reconcile is the api's half of boot reconciliation (PLAN-v2 §2.5).
 *
 * Takes the orchestrator's view of the pool and reconciles the session table
 * against it. The orchestrator does the same for containers, in its own process,
 * from its own view. Neither trusts the other alone — which is the v3 restatement
 * of v2's single reconciler.
 *
 * `stats` is null when the orchestrator is unreachable, and that is not treated as
 * "no runners exist". Assuming an empty pool would delete every runner row and
 * every session binding on a transient network failure.
 */
export async function reconcile(options: SweeperOptions): Promise<{
  reconciled: boolean;
  runnerCount: number;
  note: string;
}> {
  const { db } = options;
  const log = options.log ?? { info: () => {}, warn: () => {} };
  const now = options.now?.() ?? Date.now();

  const stats: StatsResult = await options.orchestrator.stats();

  if (!stats.ok) {
    // Not fatal, and specifically not "the pool is empty". Assuming an empty pool
    // would delete every runner row and every session binding on a transient
    // network failure.
    log.warn("orchestrator unreachable at boot, reconciliation partial", {
      error: stats.error.kind,
    });

    // Expired *session* rows are still deleted. They are this process's own
    // state and need no corroboration — §2.5's rule is that an expired session is
    // never resurrected, and that holds whether or not the orchestrator answered.
    db.reconcileRunners(new Set(db.all<{ id: string }>(`SELECT id FROM runners`).map((r) => r.id)), now);

    return {
      reconciled: false,
      runnerCount: db.all(`SELECT id FROM runners`).length,
      note: "orchestrator unreachable; pool left as-is, expired sessions removed",
    };
  }

  // The orchestrator reports counts, not identities — deliberately, since the
  // api needs "how many runners exist" to reconcile counts and has no business
  // holding container ids it cannot verify. A count mismatch is logged rather
  // than acted on, because acting on it would destroy state on the orchestrator's
  // say-so alone.
  const rows = db.all<{ id: string }>(`SELECT id FROM runners`);
  if (rows.length !== stats.value.size) {
    log.warn("pool size disagrees with the orchestrator", {
      api: rows.length,
      orchestrator: stats.value.size,
    });
  }

  // **Which ids count as live.** This was the api's own rows, which made the
  // reconciler a no-op that could never delete anything: every row it was asked to
  // check was, by construction, in the set it was given.
  //
  // The consequence accumulated silently. `syncPool` upserts and never removes, and
  // the orchestrator renumbers its slots across restarts, so the api's `runners`
  // table grew a phantom row for every slot the orchestrator had ever used. On the
  // live host it held **39 rows against 4 real slots**.
  //
  // `claimRunner` picks an idle row by `ORDER BY RANDOM()`, so roughly nine times
  // in ten it offered a slot the orchestrator had never heard of, got a 409, and
  // the user saw:
  //
  //     409 the service's view of its runner pool is out of date
  //
  // Which is correct — that process's view genuinely was out of date — and
  // unfixable from the user's side. The recovery was a restart, which is the one
  // thing the bug report had already told them not to do.
  //
  // `slotIds` is optional on `OrchestratorStats` because an api can briefly talk
  // to an orchestrator predating the field. In that case there is nothing to
  // reconcile against, and **deleting on a count alone is not the answer** — that
  // is what the comment above refuses to do, and it is right: a wrong count would
  // destroy every session binding. So the fallback keeps the old, safe behaviour.
  const liveSlotIds = stats.value.slotIds;
  if (liveSlotIds === undefined) {
    log.warn("orchestrator reported no slot ids; runner rows left unreconciled", {
      runnerCount: rows.length,
    });
    db.reconcileRunners(new Set(rows.map((r) => r.id)), now);
    return {
      reconciled: false,
      runnerCount: rows.length,
      note: "orchestrator reported no slot ids; only expired sessions removed",
    };
  }

  // Slots the orchestrator has are learned into the table first, so the reconciler
  // below compares like with like rather than deleting a slot it has not yet seen.
  const learned = syncPool(db, liveSlotIds);

  // Expired session rows go; expired *containers* are the orchestrator's business.
  db.reconcileRunners(new Set(liveSlotIds), now);

  const remaining = db.all<{ id: string }>(`SELECT id FROM runners`).length;
  if (learned.added > 0 || remaining !== rows.length) {
    log.info("runner rows reconciled against the orchestrator's slots", {
      before: rows.length,
      after: remaining,
      learned: learned.added,
    });
  }

  return {
    reconciled: true,
    runnerCount: remaining,
    note: "reconciled against the orchestrator's slot ids",
  };
}

/** The result of a stats call, used by the boot reconciler. */
type StatsResult = OrchestratorResult<OrchestratorStats>;