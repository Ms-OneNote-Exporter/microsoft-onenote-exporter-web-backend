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
import { pendingErase } from "./erase.js";
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
 * How long an in-flight export may go without publishing **any** frame — including
 * the runner's 15 s heartbeat re-publish — before it is treated as stuck.
 *
 * Derived from the heartbeat cadence rather than from section length: the heartbeat
 * keeps `progressAt` fresh every 15 s for any live walk, so a threshold of 5
 * minutes is ~20 missed heartbeats. That tolerates a reconnect/backoff window
 * (max ~30 s) without false-positiving a live export, and it is independent of
 * how long a single section takes — which is the unknown the issue withheld the
 * number over. See issue #70.
 */
export const EXPORT_STUCK_THRESHOLD_MS = 5 * 60 * 1000;

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
      reason: "pool-exhausted" | "orchestrator-unreachable" | "slot-conflict" | "slot-expiring";
      /**
       * Why the pool could not fill, when the orchestrator said.
       *
       * The distinction is between "busy, try shortly" and "cannot start runners
       * at all", and it is the difference between a user waiting and an operator
       * being paged. Found by deploying to a host where every create failed: the
       * api said *every session is busy* for hours while `healthz` said `ok`.
       */
      fillError?: string;
      /**
       * Whether another attempt could succeed, for callers that branch on it.
       *
       * Only the floor refusal sets it: `slot-expiring` means this slot was a bad
       * draw, and a later attempt draws another one — which is what separates it
       * from `slot-conflict`, where the two processes disagree about the pool and
       * no number of retries converges.
       */
      retryable?: boolean;
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
  /** Sessions stuck mid-erase, found by pendingErase. */
  pendingErases: number;
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
   * Exports ended because their runner's container died, and whose state was reset.
   *
   * Distinct from `exportsStranded` above, which is the same repair for a session
   * that had **no** runner row: this one had a runner id and a `runners` row, both
   * intact, both naming a slot whose container the orchestrator had seen die. That
   * is the shape nothing could see — the api skips `exporting` sessions to protect
   * live ones, and the api's own records were all consistent and all wrong.
   *
   * Counted because the two are different repairs for different failures, and an
   * operator reading "one stranded export" would look for the other one: a row with
   * no `runner_id` is a bookkeeping gap this sweep closed itself, while a row that
   * pointed at a dead container is a runner that exited mid-walk.
   */
  exportsRunnerDied: number;
  /**
   * Exports ended because their runner's slot was **reclaimed to idle** while they
   * were still running, and whose state was reset.
   *
   * The third shape, and the one nothing could see. `exportsStranded` is a session
   * with no runner row; `exportsRunnerDied` is one whose runner's container died —
   * both have the api's records agreeing with each other and with a slot the
   * orchestrator can still name. Here the api's records also agree with each other
   * (`runner_id` set, `runners` row `active`, state `exporting`) and the slot is
   * *idle*: a boot TTL-replace cleared the orchestrator's `SessionGUID` and dropped
   * the binding, so the export was never going to finish. Because `exporting`
   * sessions are skipped to protect live ones, the row sat there refusing every
   * future export with a 409 until the 12-hour absolute cap.
   *
   * Counted separately because each is a different repair for a different failure,
   * and an operator seeing "one stranded export" must know which of the three to look
   * for: this one is a *slot the pool still has*, which is why it was invisible —
   * nothing was missing, one thing was simply no longer true.
   */
  exportsDispossessed: number;
  /**
   * Exports ended because their runner was **alive but stopped progressing**, and whose
   * state was reset.
   *
   * Tier 2 of the export-state class. The other three shapes (`exportsStranded`,
   * `exportsRunnerDied`, `exportsDispossessed`) all have a container that is gone or a
   * slot that is unbound. This one has a runner that answers `/healthz` and is still
   * bound to the session, but has stopped publishing any frame — heartbeat included —
   * for longer than `EXPORT_STUCK_THRESHOLD_MS`. A hung walk, or the PR #67 residual.
   *
   * Counted separately because the evidence is different (staleness of a persisted
   * `progressAt`, not container death or slot unbinding), and an operator seeing
   * "one stranded export" must know whether the runner is alive.
   */
  exportsStuck: number;
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
    default:
      return null;
  }
}

/**
 * The pool state names `Stats.byState` is keyed by.
 *
 * A transcription of the Go constants in `orchestrator/internal/pool/pool.go`
 * (`StateVacant`, `StateStarting`, `StateIdle`, `StateBound`, `StateDraining`,
 * `StateDead`) and not a vocabulary of our own: the orchestrator owns that naming,
 * and the api reads it. `pool_test.go`'s `TestStatsByStateKeysAreKnownStateNames`
 * is the far end of this contract — a seventh state there turns that test red, and
 * the fix is to add the name here in the same PR. Crossed already: `/stats` has
 * always carried `byState`, and nothing is added to the wire by reading it.
 */
export const POOL_STATE_NAMES: ReadonlySet<string> = new Set([
  "vacant",
  "starting",
  "idle",
  "bound",
  "draining",
  "dead",
]);

/**
 * poolBindsNobody asks whether `/stats` says no slot in the pool is bound.
 *
 * **`true` = positive evidence nothing is bound by anyone. `undefined` = cannot
 * ask.** Three-valued on purpose: "nobody is bound" is a repair the sweeper is
 * allowed to act on, "I do not know" is not, and a two-valued signature would have
 * to pick one of them — which is precisely how a stranded export waits out the
 * 12-hour cap.
 *
 * **Why the absence of the `bound` key is an answer.** `Stats` builds `byState` with
 * `byState[string(s.State)]++` over *every* slot (`pool.go:430`), so a state with zero
 * slots contributes **no key at all** — not a `0`. That is a property of that counting
 * loop, not of Go's JSON encoding: the map carries no `omitempty`, so an empty map
 * would still marshal as `"byState": {}`, and what is absent is the *key inside* it.
 * So:
 *
 *     no `bound` key  ⟺  no slot is StateBound  ⟺  no slot is bound to any session
 *
 * which is the same fact branch C derives from `boundSessions` — from a count rather
 * than a key set, and available in exactly the case the key set goes missing, because
 * `boundSessions` is `omitempty` and an all-idle pool marshals without it. That is
 * the whole of this change: D6 (a session `exporting` while every slot is idle, never
 * repaired, 409ing every future export) was the absence of `boundSessions` being read
 * as *cannot ask* when it in fact had a positive answer sitting in the same response.
 *
 * **Why the vocabulary check, and why it refuses rather than defaults.** A bare
 * `byState.bound ?? 0` is safe *only* because the key is absent exactly when the
 * count is zero. The day the orchestrator renames `bound` — to `attached`, to
 * `in-use` — that `?? 0` reads "I do not use that word" as "nothing is bound", and
 * the sweeper dispossesses every live export on the pool. So an unrecognised name is
 * `undefined`, not a default: a refusal, which is the one answer that cannot strand
 * work. The cost is a named state is needed to trust a pool; the price of guessing
 * wrong is a user's export cancelled mid-walk.
 */
export function poolBindsNobody(
  byState: Record<string, number> | undefined,
): boolean | undefined {
  if (byState === undefined) return undefined;
  // One unknown name disqualifies the whole reading, because the unknown word may be
  // the one that used to mean `bound` — and "the thing I am looking for is not in
  // this response" has to mean *cannot ask* rather than *nothing is bound*.
  for (const name of Object.keys(byState)) {
    if (!POOL_STATE_NAMES.has(name)) return undefined;
  }
  return (byState.bound ?? 0) === 0;
}

/**
 * poolIdleCount returns the count of idle slots, or `undefined` if the vocabulary
 * is unknown.
 *
 * **The same vocabulary refusal as `poolBindsNobody`.** An unfamiliar state name
 * yields `undefined`, not a fabricated zero — the reason `poolBindsNobody` gives:
 * an unrecognised word may be the one that used to mean "bound" — and "the thing I
 * am looking for is not in this response" has to mean *cannot ask* rather than
 * *nothing is bound*. The same argument protects "idle".
 */
export function poolIdleCount(
  byState: Record<string, number> | undefined,
): number | undefined {
  if (byState === undefined) return undefined;
  for (const name of Object.keys(byState)) {
    if (!POOL_STATE_NAMES.has(name)) return undefined;
  }
  return byState.idle ?? 0;
}

/**
 * poolClaimable returns the claimable slots from the orchestrator's response, or
 * `undefined` if the response does not say enough.
 *
 * **The same vocabulary refusal as `poolBindsNobody`.** An unfamiliar state name
 * yields `undefined`, not a fabricated count — the reason `poolBindsNobody` gives:
 * an unrecognised word may be the one that used to mean "bound" — and "the thing I
 * am looking for is not in this response" has to mean *cannot ask* rather than
 * *nothing is bound*.
 *
 * **Two ways to know.** The orchestrator may report:
 *
 *   - a non-empty `claimableSlotIds` list — the exact set, known precisely
 *   - `byState.idle` without `claimableSlotIds` — an upper bound on the set, which
 *     is all that can be known without the ids
 *
 * A caller that receives `undefined` from this function falls back to the old
 * behaviour: draw from the membership set and let the orchestrator refuse the ones
 * it cannot serve. A rolling deploy of an orchestrator that predates the field
 * leaves the api in that mode, and a rolling deploy of an api that predates it
 * ignores the field.
 */
export function poolClaimable(
  byState: Record<string, number> | undefined,
  claimableSlotIds: readonly string[] | undefined,
): ReadonlySet<string> | undefined {
  if (claimableSlotIds !== undefined) return new Set(claimableSlotIds);
  // No ids: the orchestrator does not report them. The count still does.
  const idle = poolIdleCount(byState);
  if (idle === undefined) return undefined; // cannot ask
  if (idle > 0) return undefined; // some are claimable; which ones is unknown
  return new Set<string>(); // none are claimable
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

/**
 * The minimum remaining budget a slot must have to be claimed for login.
 *
 * A claim creates a container and takes ~57s worst case — a 10 s SIGTERM grace to stop
 * the idle runner, ~2 s to create and start its replacement, and a 45 s healthcheck
 * wait. A slot with less than this much budget left will be recycled mid-login, and
 * the user gets a sign-in that dies on its own.
 *
 * Deliberately conservative: 60 s is a fifth of the 5-minute `RunnerTTL`, so this only
 * fires on slots that are genuinely about to expire, and the gap absorbs the age the
 * snapshot was stale by while the claim was in flight.
 */
const CLAIM_FLOOR_SECONDS = 60;

export class PoolBinder {
  readonly #db: Db;
  readonly #orchestrator: OrchestratorApi;
  readonly #log: SweeperLog;
  readonly #now: () => number;

  /**
   * The pool as the orchestrator last described it: its membership, and the
   * subset of it a `/claim` would accept.
   *
   * `undefined` means "the orchestrator has not said" — the rolling-deploy case,
   * and the case where the last `/stats` failed. It is never read as "none".
   */
  #pool: { membership: ReadonlySet<string>; claimable: ReadonlySet<string> | undefined } | undefined;

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
    //
    // **Slots the orchestrator has refused, kept out of the retries.**
    //
    // Dropping the offending row is not enough on its own, because the retry's own
    // re-sync puts it straight back: `/stats` still lists the slot, so `syncPool`
    // re-registers the row, and the next `claimRunner` draws from a pool that
    // contains it again. With `ORDER BY RANDOM()` the retry is then a coin flip
    // against the row just refused — on a two-slot pool, `(1/2)³ = 12.5%`, so seven
    // of every eight sign-ins fail on a disagreement a single other row could have
    // fixed. Each refusal is recorded here so the *next* attempt cannot re-draw it,
    // which turns "spin" into "walk the pool".
    //
    // One set for the whole loop, not one per attempt: a second refusal must narrow
    // the draw further, or the retry could bounce between two bad rows.
    const excluded = new Set<string>();
    for (let attempt = 1; ; attempt++) {
      const now = this.#now();
      const result = await this.#claimOnce(session, mode, excluded, now);
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
      //
      // Re-learning re-adds the refused slot, and `excluded` is what keeps that from
      // mattering: the row comes back, but the next draw cannot be it. `syncPool` is
      // unchanged, deliberately — it reports the orchestrator's membership, and
      // membership is exactly the thing that is correct here. The pool snapshot is
      // also updated so `#notClaimable()` has the latest view.
      const stats = await this.#orchestrator.stats();
      if (stats.ok && stats.value.slotIds !== undefined) {
        const learned = syncPool(this.#db, stats.value.slotIds);
        const membership = new Set<string>(stats.value.slotIds);
        const claimable = poolClaimable(stats.value.byState, stats.value.claimableSlotIds);
        this.#pool = { membership, claimable };
        if (learned.added > 0) {
          this.#log.info("pool slots re-learned after a refused claim", {
            session: session.guid,
            added: learned.added,
            total: learned.total,
            attempt,
          });
        }
        // Recompute `skip` now that the pool snapshot has been refreshed, so
        // the re-learning's claim excludes the newly-learned non-claimable slots.
        // Do NOT claim here. The re-learning branch's job is to update the membership
        // (so syncPool puts refused rows back) and the pool snapshot (so #notClaimable()
        // has the latest view). The actual draw happens in #claimOnce on the next
        // iteration, which excludes the refused slots via `excluded` and the
        // non-claimable ones via #notClaimable(). Claiming here would short-circuit
        // the retry loop and skip the "giving up" path.
      }
    }
  }

  /**
   * claimOnce makes one full pass: take a SQLite row, then ask the orchestrator for
   * that slot. The retry policy lives in `claimForLogin`.
   *
   * `excluded` is passed to both claims below, not just the first. The second one
   * runs after a re-sync has put the refused row back, so it is the claim most at
   * risk of re-drawing it — omitting it would leave the retry able to repeat the
   * exact failure it exists to recover from. It is carried as a `Set` rather than a
   * list because it accumulates across attempts, and only `#finishClaim`'s conflict
   * branch writes to it.
   */
  async #claimOnce(
    session: SessionRow,
    mode: ClaimMode,
    excluded: Set<string>,
    now: number,
  ): Promise<ClaimResult> {
    // The exclusion list is the union of the per-session refusal set (`excluded`) and
    // the pool view (`#notClaimable()`). `drawEmptiedByExclusions` sees only
    // `excluded`, so it never reports "every slot was refused" for a pool whose
    // claimable set is smaller than its membership.
    //
    // Recomputed here, not passed in, so it is always fresh: the pool snapshot may
    // have been updated between the moment the caller computed it and this call.
    const skip: readonly string[] = [...excluded, ...this.#notClaimable()];

    // One log line per draw, so the mechanism is observable on the deployed host.
    const notClaimable = this.#notClaimable();
    this.#log.info("claim: slots the orchestrator will not serve", {
      session: session.guid,
      notClaimable: notClaimable.length,
    });

    if (!this.#db.claimRunner(session.guid, skip)) {
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
          if (this.#db.claimRunner(session.guid, skip)) {
            // Fall through to the rest of the claim on the success path below.
            return this.#finishClaim(session, now, mode, excluded);
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

      // **A draw emptied by its own exclusions is not an exhausted pool.**
      //
      // This is the one place the exclusion set can change the answer rather than
      // only the pick, and it has to: excluding a refused slot makes the draw fail
      // for a reason that has nothing to do with anybody else using the pool. When
      // every slot the orchestrator names has been refused, reporting `pool-exhausted`
      // tells the user to wait for capacity that cannot admit them — the same
      // misreading the conflict branch exists to prevent, one step further from its
      // cause. So the refusal is reported as the refusal it is.
      if (drawEmptiedByExclusions(stats, excluded)) {
        this.#log.warn("every slot the orchestrator names has been refused", {
          session: session.guid,
          excluded: excluded.size,
        });
        return { ok: false, reason: "slot-conflict" };
      }

      this.#log.info("pool exhausted", { session: session.guid });
      return { ok: false, reason: "pool-exhausted" };
    }

    return this.#finishClaim(session, now, mode, excluded);
  }

  /**
   * #finishClaim turns an already-claimed SQLite row into a running container.
   *
   * Split out of `claimForLogin` because the claim can now be reached twice: once
   * on the first attempt and once after learning the pool's membership. Both
   * paths must be identical from here — the row is claimed, so everything that
   * follows assumes exactly that.
   *
   * `excluded` is where the set is written, and only in the conflict branch below.
   */
  async #finishClaim(
    session: SessionRow,
    now: number,
    mode: ClaimMode,
    excluded: Set<string>,
  ): Promise<ClaimResult> {
    // **The row `claimRunner` just drew, and `status = 'claimed'` is what makes it
    // that row rather than another one.**
    //
    // This used to read `WHERE session_guid = ?` alone, which assumed one row per
    // session. #93 broke the assumption: a re-login claims a *second* slot while the
    // previous one is still bound, and the stale release runs afterwards. For that
    // window **two** `runners` rows carry the same `session_guid` — the stale one,
    // left `active` by the last claim, and the one `claimRunner` has just moved to
    // `claimed`.
    //
    // Unguarded, this could hand back the stale row. The orchestrator then answers
    // with *that* slot, `claimBindingWrite` writes it, and the caller believes the
    // claim took a fresh container — while the session is still pointed at the one it
    // was about to release. The release then matches its own guard, tears down the
    // container the credential is being forwarded to, and leaves a signed-in-looking
    // session with no runner at all.
    //
    // `claimRunner` sets `status = 'claimed'` and nothing else does until this
    // method's own writes below, so the predicate is exactly "the draw this request
    // made". The claim failure path already treats a missing row as unreachable
    // rather than assuming it, and that check is kept.
    const claimed = this.#db.get<{ id: string }>(
      `SELECT id FROM runners WHERE session_guid = ? AND status = 'claimed'`,
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
      //
      // **And the slot is recorded as refused for the rest of this session's retry.**
      // Dropping the row alone does not survive the retry: `/stats` still lists the
      // slot, `syncPool` re-registers it, and `ORDER BY RANDOM()` can draw it straight
      // back. The row being gone between attempts and the row being *offered* again are
      // different facts, and only the second one makes progress — so the refusal is
      // remembered here, where it is observed, rather than left to be re-derived by
      // another lottery.
      //
      // **Only `conflict` writes to the set.** The floor refusal further down is also a
      // "no", but it means the opposite: that slot is valid and merely not ready yet.
      // Excluding it would shrink the pool this loop still has to draw from, and on a
      // small pool it would turn a recoverable bad draw into `pool-exhausted`.
      if (result.error.kind === "conflict") {
        this.#db.removeRunner(claimed.id);
        excluded.add(claimed.id);
        this.#log.warn("orchestrator refused the claimed slot; row dropped", {
          session: session.guid,
          runner: claimed.id,
          error: result.error.kind as string,
          // How many slots this loop can no longer offer, so a pool that is entirely
          // bad reads as an exhausted draw rather than as a mysterious retry.
          excluded: excluded.size,
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

    // **The floor check, after the claim rather than before it.**
    //
    // A container about to be recycled is not something this process can see: it
    // holds no container identity (§2.1), and the age lives on the orchestrator's
    // side of the boundary. So the question — "does this slot have enough budget left
    // to finish a login?" — is asked of `/stats`, keyed by the slot id `claimRunner`
    // just handed over. `slotRemainingSec` is the orchestrator's arithmetic over its
    // own `Slot.CreatedAt` and its own `RunnerTTL`, which is the only place both
    // facts exist.
    //
    // **After**, because before the claim there is no slot to ask about: the slot is
    // chosen by `claimRunner`, and the choice is `ORDER BY RANDOM()` over this
    // process's rows. A pre-claim check would either reject every login or pick a
    // different slot from the one that gets claimed — and a claim is the expensive,
    // disruptive thing to do, so it is not done speculatively.
    //
    // **Fail-open, twice over.** A failed `/stats` is "we do not know", and an absent
    // `slotRemainingSec` is "this orchestrator does not say" — the rolling-deploy
    // state. Neither is evidence of a floor breach, and treating either as one would
    // make a metrics field an availability dependency that fails hardest exactly when
    // the orchestrator is least reachable. Both proceed, which is today's behaviour.
    //
    // The number is a snapshot, and it is stale by up to the claim's own ~57 s by the
    // time this reads it. The floor is conservative for that reason: 60 s against a
    // 300 s budget, so the worst case is spending the margin rather than overshooting
    // it — and overshooting is the failure this exists to prevent.
    const stats = await this.#orchestrator.stats();
    if (stats.ok && stats.value.slotRemainingSec !== undefined) {
      const remaining = stats.value.slotRemainingSec[slotId];
      // `!== undefined` rather than a falsy test: a slot missing from the map has no
      // container yet, which is not the same claim as one with no budget left.
      if (remaining !== undefined && remaining < CLAIM_FLOOR_SECONDS) {
        // Give the slot back, **both halves**: the orchestrator's binding — which is
        // what holds the container that is about to expire — and this process's row.
        //
        // Both, because `releaseRunner` alone leaves the orchestrator holding a slot
        // this process no longer offers. That is exactly the divergence the
        // `slot-conflict` path exists to repair: the row gets claimed again, the
        // orchestrator answers `already bound`, and a perfectly healthy pool refuses
        // logins with "the service's view of its runner pool is out of date".
        //
        // A `conflict` is success, on the same terms as the three releases in
        // `releaseFor*`: the slot is already gone or already unbound, which is the
        // state this branch wanted.
        const released = await this.#orchestrator.release(slotId);
        this.#db.releaseRunner(slotId);
        this.#log.warn("claimed slot is about to expire; released instead of bound", {
          session: session.guid,
          slot: slotId,
          remainingSec: remaining,
          // Only when the orchestrator could not be told, which is the case an
          // operator has to look at: the container is still running and still aging,
          // and the two sides disagree about who holds it. The sweeper's orphan
          // branch is what reconciles that; this only records that it happened.
          ...(released.ok || released.error.kind === "conflict"
            ? {}
            : { error: released.error.kind }),
        });
        // Retryable, and for a reason a caller can act on: this was a bad draw from
        // the pool, not a broken pool. The session's own row was never written —
        // `claimBindingWrite` below did not run — so it is still `created` and the
        // next attempt draws another slot.
        //
        // Deliberately **not** added to `excluded`, though a later caller will retry:
        // this slot was released on both sides and is `idle` again, so it is a
        // legitimate claim candidate once its container has been replaced. Excluding
        // it would treat "not ready yet" as "does not exist", and on a small pool
        // would shrink the retry's draw by one for no reason at all.
        return { ok: false, reason: "slot-expiring", retryable: true };
      }
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
   *
   * ## Why the session UPDATE is guarded on `runner_id` (§4.9)
   *
   * Every release here works from a **snapshot**: `sweep` reads all sessions at
   * the top of the tick and walks that list, with an `/release` round trip — tens
   * of milliseconds, and up to ~57 s of container teardown — between deciding to
   * release and writing the row. In that window a re-login can land a *live*
   * binding on the same row.
   *
   * `WHERE guid = ?` alone would then clear that live binding: a session that has
   * just been handed a working container loses it, and the pool hands the slot to
   * somebody else. The symptom is a login that reports success and then answers
   * `no runner` for the rest of its life.
   *
   * `AND runner_id = ?` makes the write idempotent against an aged snapshot. `0`
   * rows changed means "this is no longer the binding I was asked to release",
   * which is the correct answer — and the row it would have clobbered stays.
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
        WHERE guid = ? AND runner_id = ?`,
      this.#now() + TTL.authenticatedIdle,
      session.guid,
      session.runner_id,
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
   *
   * ## Why the session UPDATE is guarded on `runner_id` (§4.9)
   *
   * Same reason as `releaseForIdle`, and the window is wider here rather than
   * narrower: the snapshot is the tick's `SELECT * FROM sessions`, the `/release`
   * is a round trip, and between them a user who was shown the sign-in form can
   * submit a credential — which claims a fresh container and rewrites
   * `runner_id`. An unguarded `WHERE guid = ?` would then erase that fresh
   * binding, leaving a container running, a slot held by the orchestrator, and a
   * session that reports no runner.
   *
   * `AND runner_id = ?` bounds the write to the binding this snapshot actually
   * observed. A `0` is not a failure to report: it means somebody else already
   * took this session forward, and the newest binding is the right one to keep.
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
    this.#db.run(
      `UPDATE sessions SET runner_id = NULL WHERE guid = ? AND runner_id = ?`,
      session.guid,
      session.runner_id,
    );
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

  /**
   * releaseForDeadRunner gives back a slot whose runner the orchestrator has seen die.
   *
   * The same verb and the same tolerance as the three above — a `conflict` means the
   * slot is already gone or unbound, which is precisely the state this caller wanted,
   * so it is success — but it is **not** a copy of any of them: it writes nothing to
   * the session row.
   *
   * ## Why the session row is left alone
   *
   * Every caller above owns the session's fate and writes it here. This one does not.
   * The caller is the sweep's dead-runner branch, and its job is two more statements
   * in a fixed order: `clearSessionRunner` (which unsticks the slot from this
   * session) and then `markExportStranded` (which resets the state, behind a
   * `state = 'exporting'` guard). Writing `state = 'authenticated'` from here would
   * consume that guard before it was ever tested, so the second statement would
   * change nothing and the repair would fail silently — leaving the session
   * refusing every future export, which is the defect the branch exists to remove.
   *
   * `releaseRunner` **is** called, and it is what keeps the slot claimable: the
   * orchestrator's slot is a pool position, and a `runners` row left `active` is
   * invisible to `claimRunner`'s `WHERE status = 'idle' AND session_guid IS NULL`.
   * So without it this repair would end the wedged export and wedge the slot
   * instead — the same outage, one field over.
   */
  async releaseForDeadRunner(session: SessionRow): Promise<boolean> {
    if (session.runner_id === null) return false;
    const released = await this.#orchestrator.release(session.runner_id);
    if (!released.ok && released.error.kind !== "conflict") {
      // Retain everything. The caller's `continue` is what makes that stick: clearing
      // the row after a release that may not have happened orphans the slot — freed
      // on neither side, and re-claimable by whoever gets there next.
      this.#log.warn("release of a dead runner's slot failed, retained for the next sweep", {
        session: session.guid,
        runner: session.runner_id,
        error: released.error.kind,
      });
      return false;
    }
    this.#db.releaseRunner(session.runner_id);
    return true;
  }

  /**
   * releaseStaleRunner gives back the container a session was on **before** this
   * login, once it has been handed a fresh one.
   *
   * ## Why this exists (#93)
   *
   * A session whose first login failed still has `runner_id` set — nothing clears
   * it until the sweeper's auth-failed branch, up to 30 seconds later — and the
   * credential route used to skip `claimForLogin` entirely whenever `runner_id`
   * was non-null. So the retry handed the password to the container the *failed*
   * attempt ran in: a Chromium process whose cookie jar was just refuted, whose
   * state is unknown to this process, and whose own state machine may already be
   * unwinding.
   *
   * The slot-budget floor (§2.1) is checked on claim too, and skipping the claim
   * skipped that as well — so a retry could land on a container seconds from
   * being recycled, and the sign-in would die on its own with nothing in the log.
   *
   * ## Claim first, release second. The order is the safety property.
   *
   * Releasing first and then claiming has a window in which the session holds
   * **no** container: if the claim then fails — pool exhausted, orchestrator
   * unreachable, slot conflict — the user has been left worse off than before,
   * because the working binding that was there a moment ago is gone and nothing
   * replaced it. Claiming first means the old container is only ever released once
   * a better one is confirmed, and a failed claim leaves the old one exactly where
   * it was.
   *
   * The reverse window is harmless by construction: between the claim and this
   * release the session points at the new container, so the stale one is
   * unreferenced and leaking nothing that `runner_id` can reach.
   *
   * ## Why the session UPDATE comes before the orchestrator call, and is guarded
   *
   * Two separate reasons, and they are why this is not a `releaseForIdle` with a
   * different name.
   *
   * **Order.** The guarded UPDATE is what removes this session's reference to the
   * container, and doing it before the round trip means the worst case of a failed
   * `/release` is a container the orchestrator still holds — repaired by the
   * sweeper's orphan branch — rather than a slot bound in SQLite to a container
   * that has been destroyed.
   *
   * **The guard (§4.9).** `WHERE guid = ? AND runner_id = ?` cannot dispossess a
   * session. In the route's normal path the claim has *already* overwritten
   * `runner_id` with the new slot, so this statement changes nothing — which is
   * precisely the correct outcome, and the reason a `0` is not treated as "stop".
   * The unguarded form would be a live session's new binding cleared by a stale
   * snapshot, which is the one failure no reconciler can repair.
   *
   * `releaseRunner` is guarded too, on the same principle and for the same reason:
   * the `runners` row's `session_guid` is the other half of this binding, and an
   * unconditional clear would free a slot a *new* claim had since taken.
   *
   * ## Returns
   *
   * `false` only when the orchestrator could not be told, and only after it has
   * logged. The caller is on a login's critical path and has already done the part
   * that matters — the new container exists and the credential is on its way — so
   * this is a logged leak bounded by the idle-time reclaim, not a failed login.
   */
  async releaseStaleRunner(guid: string, staleRunnerId: string): Promise<boolean> {
    // **Guarded, and its change count is deliberately not an early return.**
    //
    // After a successful claim this is normally `0` rows: `claimBindingWrite` has
    // already pointed the session at the new slot. `0` therefore means "there is
    // nothing here to unbind", not "there is nothing to release" — and treating it
    // as the latter would skip the `/release` on every single call, which is the
    // exact leak this method exists to close. The guard is here to stop this write
    // *disposing* of a newer binding, which it does whether or not it changed a row.
    const unbound = this.#db.run(
      `UPDATE sessions SET runner_id = NULL WHERE guid = ? AND runner_id = ?`,
      guid,
      staleRunnerId,
    );

    const released = await this.#orchestrator.release(staleRunnerId);
    if (!released.ok && released.error.kind !== "conflict") {
      // The row is already unbound above and the container may still be running, so
      // this half is left to the sweeper's orphan branch — which is the only thing
      // that can see it, because nothing here points at it any more. Logging it is
      // what makes that recoverable rather than silent.
      this.#log.warn("stale runner could not be released; left to the sweeper", {
        session: guid,
        runner: staleRunnerId,
        error: released.error.kind,
      });
      return false;
    }

    const freed = this.#db.releaseRunner(staleRunnerId, guid);
    this.#log.info("stale runner released after a fresh claim", {
      session: guid,
      runner: staleRunnerId,
      reason: "stale-runner",
      // Both halves of the write, because "it logged the release" and "the row was
      // actually freed" are different facts and only the second one keeps the slot
      // claimable.
      unbound: unbound > 0,
      freed: freed > 0,
    });
    return true;
  }

  /**
   * poolUpdate stores the pool snapshot from the orchestrator's response.
   *
   * This is the one place where the pool snapshot can be set from outside the
   * PoolBinder: at boot, before any claim has been made (index.ts calls it from
   * the boot reconciliation), and from the sweep tick (sweep.ts). The first claim
   * then has an up-to-date view of the claimable set.
   */
  poolUpdate(stats: OrchestratorStats): void {
    if (stats.slotIds === undefined) return;
    const membership = new Set<string>(stats.slotIds);
    const claimable = poolClaimable(stats.byState, stats.claimableSlotIds);
    this.#pool = { membership, claimable };
  }

  /**
   * #notClaimable returns the slots the orchestrator will not serve right now.
   *
   * The orchestrator reports its membership (`slotIds`) and its claimable set
   * (`claimableSlotIds`). The slots it will not serve are membership minus the
   * claimable set — which is exactly the slots it knows about that are not idle.
   *
   * **When the orchestrator does not report the claimable set** (rolling deploy of
   * an orchestrator that predates the field), this falls back to returning an empty
   * list — the old behaviour, with no regression.
   */
  #notClaimable(): readonly string[] {
    const pool = this.#pool;
    if (pool === undefined || pool.claimable === undefined) return [];
    const out: string[] = [];
    for (const id of pool.membership) {
      if (!pool.claimable.has(id)) out.push(id);
    }
    return out;
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
    pendingErases: 0,
    exportsHeld: 0,
    exportsStranded: 0,
    exportsRunnerDied: 0,
    exportsDispossessed: 0,
  exportsStuck: 0,
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
  // **Update the pool snapshot for the claim code path.** The claim path's ` PoolBinder`
  // learns from both this tick (the rolling-deploy case) and its own failure branch
  // (a slot was refused), so the hot path gains no extra round trip and a stale
  // snapshot is corrected by the first failed attempt.
  //
  // The membership is `slotIds`, and the claimable set is whatever `claimableSlotIds`
  // says — or `undefined` if the orchestrator does not report it.
  if (stats.ok && stats.value.slotIds !== undefined) {
    binder.poolUpdate(stats.value);
  }
  // **Which slots the orchestrator has seen lose their runner**, taken from the
  // snapshot this tick already has rather than from a second `/stats`. One opinion
  // per tick: a second call would be a second opinion taken after the session loop,
  // and this branch's whole safety argument rests on the list matching the state the
  // loop is walking.
  //
  // `stats.ok` first, then the field. A failed `/stats` is "we do not know", never
  // "none are dead" — treating an orchestrator outage as a clean bill of health is
  // how a reachable-but-wrong reading becomes a silent one. And `deadSlots === undefined`
  // is the rolling deploy: an orchestrator that predates the field reports nothing,
  // which is read as `[]`.
  const deadSlots =
    stats.ok && stats.value.deadSlots !== undefined ? stats.value.deadSlots : [];
  // Same two-part guard as `deadSlots`, and the same reason for both halves: a failed
  // `/stats` is "we do not know", never "nothing is bound" — treating an orchestrator
  // outage as a clean bill of health would strand every live export on the pool.
  //
  // The difference is the fallback. `deadSlots` falls back to `[]` because "no dead
  // slots" is the safe default when nothing is reported. `boundSessions` falls back to
  // `undefined` because its consumer asks a question only an answer can answer: is
  // this session's slot *absent* from the set? Absent on a healthy pool and absent
  // because the field was never reported look identical from here, so the guard must
  // refuse to ask rather than guess `{}` — see the branch C comment.
  const boundSessions =
    stats.ok && stats.value.boundSessions !== undefined ? stats.value.boundSessions : undefined;
  // **The same question asked of the same snapshot, one clause lower.** `boundSessions`
  // is an *absence* as evidence: this session's slot is missing as a key, which only
  // works while some other slot happens to be bound — `Stats` leaves the map nil
  // otherwise and `omitempty` drops the key, so an all-idle pool (the ordinary state of
  // a pool nobody is using, and the body the deployed host actually sends) answers
  // nothing. `byState` answers the same question from a *count*, on the same response,
  // with a tri-state answer instead of a bare presence — see `poolBindsNobody`.
  //
  // `stats.ok` first, same reason as the two above: an unreachable orchestrator is "we
  // do not know", never "nothing is bound". And the vocabulary refusal lives inside the
  // helper, so an orchestrator that renamed a state yields `undefined` rather than a
  // fabricated zero.
  const nothingBound = stats.ok ? poolBindsNobody(stats.value.byState) : undefined;
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
      // Best-effort: remove the session's vault directory. Logged on success (because
      // the orchestrator's audit line carries no guid), never thrown (the sweep's
      // tick must not fail).
      try {
        await options.orchestrator.deleteSessionDir(session.guid);
        log.info("session directory deleted", { session: session.guid });
      } catch (error) {
        // A failed deletion is logged, so it shows up in the sweep log, but the
        // sweep tick must not fail. The sweeper's retry record will re-try.
        log.warn("session directory deletion failed, left to next sweep", {
          session: session.guid,
          error: String(error),
        });
      }
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
      // Best-effort: remove the session's vault directory. Logged on success (because
      // the orchestrator's audit line carries no guid), never thrown (the sweep's
      // tick must not fail).
      try {
        await options.orchestrator.deleteSessionDir(session.guid);
        log.info("session directory deleted", { session: session.guid });
      } catch (error) {
        log.warn("session directory deletion failed, left to next sweep", {
          session: session.guid,
          error: String(error),
        });
      }
      db.deleteSession(session.guid);
      sse.emit(session.guid, "session-status", { state: "expired" });
      sse.drop(session.guid);
      report.unclaimedExpired++;
      log.info("session expired without a login", { session: session.guid });
      continue;
    }

    // A login that never finished — an MFA prompt the user walked away from, or
    // a Microsoft interstitial that never resolved. 15 minutes.
    //
    // **Guarded on `auth_state` as well as `state`, and that second term is the fix.**
    //
    // `markAuthFailed` writes `auth_state = 'failed'` and deliberately leaves `state`
    // at `authenticating` — the login is still the session's current phase, so a retry
    // from the sign-in screen is not a new session. But the login is no longer *in
    // progress*: it finished, and Microsoft refused the password. So `state` alone
    // matched both shapes, and 15 minutes after a typo this branch fired, overwrote
    // `auth_state` with `expired`, and emitted `challenge-expired` — telling the user
    // their MFA window closed when the truth was that their password was wrong.
    //
    // Both terms must say `authenticating` for a login to still be in flight. A
    // refused one falls through to the auth-failed branch at the bottom, which
    // releases the slot at once and leaves `auth_state = 'failed'` standing.
    if (
      session.state === "authenticating" &&
      session.auth_state === "authenticating" &&
      session.last_activity_at + TTL.loginInProgress <= now
    ) {
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

    // **An export whose runner died under it is stranded too — and this sweep could
    // not see it.**
    //
    // The branch above repairs a session with no runner at all. This one repairs the
    // shape that branch cannot reach: the session has a `runner_id`, a `runners` row
    // says that slot is bound, and both records are *true* — of a container that no
    // longer exists. The runner is the only writer of `export-done` /
    // `export-partial`, so there is no one left to finish the walk, and yet:
    //
    //   - `export_state` still says `queued`/`running`, so `POST /api/export` refuses
    //     every future export with a 409.
    //   - `state` is still `exporting`, so the hold branch below skips the session
    //     and its idle deadline never applies.
    //
    // Up to 12 hours, from one container that exited. Only the orchestrator holds the
    // Engine and can see it; only this process holds the session rows and can act on
    // it. `deadSlots` is the whole conversation between them, and it is deliberately
    // narrow evidence: a slot the orchestrator says lost its container, named by
    // slot id rather than by a container identity this process is not allowed to
    // hold (§2.1).
    //
    // Placed **between** the stranded branch and the export hold. Before the hold, or
    // the hold `continue`s past it and the session keeps its 409; after the stranded
    // branch would read as a widening of that one, which this is not — that branch's
    // `runner_id IS NULL` is deliberate and its own comment says so.
    if (
      session.state === "exporting" &&
      session.runner_id !== null &&
      deadSlots.includes(session.runner_id)
    ) {
      // Order is the whole repair. The slot goes first: `clearSessionRunner` is what
      // `markExportStranded`'s `runner_id IS NULL` guard tests, so without it the
      // second statement is a no-op and nothing changes — and, worse, the api keeps
      // claiming a slot the orchestrator has handed back, which on a two-slot pool is
      // the lockout one field over.
      //
      // The runner id is passed rather than left implicit so the clear is guarded on
      // it: this tick's snapshot is minutes old, and a re-login that landed a *live*
      // binding in the meantime must not be unsticked by a repair for a dead
      // container. A guarded no-op is correct here — the new binding is the truth.
      if (!(await binder.releaseForDeadRunner(session))) {
        // Any release failure that is not a conflict. **Continue with the row intact.**
        // Clearing it anyway would orphan the slot: not released on the orchestrator's
        // side, not bound on this one, and the next claimable session to arrive takes
        // a container somebody is still using.
        continue;
      }
      db.clearSessionRunner(session.guid, session.runner_id);
      const changed = db.markExportStranded({
        guid: session.guid,
        now,
        idleExpiresAt: now + TTL.authenticatedIdle,
        // The user's own cause, not this branch's. The default string says the runner
        // was *released*; nothing released it. It was killed, and the card the browser
        // is showing is frozen on a walk that can never be resumed.
        error: "the runner disappeared before this export finished",
      });
      if (changed) {
        report.exportsRunnerDied++;
        log.warn("export reset; its runner's container died", {
          session: session.guid,
          slot: session.runner_id,
        });
        // Same event as the branch above and for the same reason: the frontend is
        // SSE-only, and the one writer that would have ended the progress card is
        // precisely what died. `session-status` tells the client to re-read the
        // snapshot (App.tsx:293).
        sse.emit(session.guid, "session-status", { state: "authenticated" });
      }
      continue;
    }
    // **Branch C — the slot was reclaimed to idle while the session still exports.**
    //
    // The third shape, and the only one where the api's records are all consistent
    // and all wrong. A boot TTL-replace (or any orchestrator restart) drops a bound
    // slot's orchestrator-side `SessionGUID`, so the slot reports `idle`: `runner_id`
    // is still set here, the `runners` row is still `active`, and the export was never
    // going to finish. Branch A cannot reach it (`runner_id` is not null); branch B
    // cannot reach it (an idle slot is not in `deadSlots`, which is bound-only). So
    // without this the export-hold below pins the session for the 12-hour cap, and
    // `POST /api/export` answers `409 an export is already running` for every notebook
    // the user has not tried yet.
    //
    // **The signal is an absence, which is why each guard below is load-bearing.**
    // `boundSessions` names every slot the orchestrator currently binds, so this
    // session's slot missing as a *key* is positive evidence it is unbound by everyone
    // — idle, vacant, being recreated, or gone. Reading an absent *field* that way
    // would be the opposite of true, hence:
    //
    //   - `boundSessions !== undefined` — an absent field means we cannot *ask* **of
    //     that field**. It is a rolling deploy (this api ahead of the orchestrator) or an
    //     all-idle pool (`omitempty` drops the key, and `Stats()` leaves the map nil).
    //     Fails open to "cannot ask", exactly as `deadSlots` does above.
    //     This is the guard that matters: without it an absent field reads as "no slot
    //     is bound" and strands every live export on the pool.
    //   - `!(runner_id in boundSessions)` — **absent**, not "bound to another guid". A
    //     slot bound to a *different* session is a key that IS present, so it stands
    //     down and the post-loop orphan reconciler owns it: that shape is pool drift,
    //     and stranding it here could dispossess the session actually using the slot.
    //   - `!deadSlots.includes(...)` — **redundant, and deliberately so.** Branch B
    //     above matches the same prefix and `continue`s, so a session that reaches here
    //     cannot be in `deadSlots`; dropping this clause changes no behaviour today
    //     (verified — the suite stays green without it). It is kept because the two
    //     branches' contract is that they own *disjoint* shapes, and that is a property
    //     of this predicate rather than of the order of two `if`s above it. Reordering
    //     the branches without this clause would let C act on a dead slot with the wrong
    //     message and no `/release`; with it, C stands down and B repairs.
    //
    // **D6 is closed, and the `else` arm below is how.** When `boundSessions` is absent
    // the old predicate stood down unconditionally, which left a session `exporting`
    // while *every* slot was idle unrepaired for the whole 12-hour cap — 409ing every
    // future `POST /api/export` — because that is precisely the pool shape in which
    // `Stats` leaves the map nil. So the fallback asks the same question of the same
    // response in a form that survives an empty pool:
    //
    //   boundSessions !== undefined  ?  !(runner_id in boundSessions)
    //                                 :  nothingBound === true
    //
    // The arms are ordered, not interchangeable. **`boundSessions` still wins whenever
    // it is present**, byte for byte: it names *which* slot is unbound rather than how
    // many are bound, so it is strictly the better evidence and the only one that can
    // stand C down for a slot bound to a different session. Every pre-existing branch-C
    // test therefore still runs through the untouched arm, and there is no rolling-
    // deploy window in which behaviour differs for a pool that is not all-idle.
    //
    // `nothingBound` is a fallback for *cannot ask*, not a replacement for *no answer*.
    // It is `undefined` — and so the whole condition false — when `/stats` failed, when
    // `byState` itself is missing, and when the response names a state this api does not
    // know (`poolBindsNobody`). Those three are the same failure: reading a shape we
    // cannot interpret as "nothing is bound", which would dispose of live exports
    // mid-walk. The safe direction is deliberate in both halves — no false positive on a
    // live export, at the cost of a strand surviving one more tick when we cannot ask.
    if (
      session.state === "exporting" &&
      session.runner_id !== null &&
      !deadSlots.includes(session.runner_id) &&
      (boundSessions !== undefined
        ? !(session.runner_id in boundSessions)
        : nothingBound === true)
    ) {
      // **Order is the whole repair**, for the same reason it is in branch B:
      // `releaseRunner` frees the `runners` row and does *not* touch
      // `sessions.runner_id`, and `markExportStranded` tests `runner_id IS NULL`. Skip
      // the unbind and the third statement is a no-op — the row is untouched and the
      // cap still wins, while the api goes on claiming a slot the pool has handed back.
      //
      // **No `/release`.** The orchestrator side is already unbound (`StateIdle`), so
      // releasing would destroy a *healthy* idle container and transiently shrink the
      // pool to fix a row that only this process can see. Branch B needs its release
      // because the container is gone and something must be torn down; nothing is here.
      db.releaseRunner(session.runner_id);
      // Guarded on the id this snapshot named, so a newer live claim that landed in
      // the window is not dispossessed by a stale one (F8).
      db.clearSessionRunner(session.guid, session.runner_id);
      const changed = db.markExportStranded({
        guid: session.guid,
        now,
        idleExpiresAt: now + TTL.authenticatedIdle,
        // The user's own cause, not branch B's. Nothing died and nothing released it:
        // the slot was quietly taken back, and the card the browser is showing is
        // frozen on a walk that can never be resumed.
        error: "the runner's slot was reclaimed before this export finished",
      });
      if (changed) {
        report.exportsDispossessed++;
        log.warn("export slot reclaimed while the session still exported; export reset", {
          session: session.guid,
          slot: session.runner_id,
        });
        // Same event as branches A and B for the same reason: the frontend is
        // SSE-only, and the one writer that would have ended the progress card is the
        // thing that went away. `session-status` tells the client to re-read the
        // snapshot (App.tsx:293).
        sse.emit(session.guid, "session-status", { state: "authenticated" });
      }
      continue;
    }

    // **Tier 2 — a runner that is alive but stopped progressing.**
    //
    // Branches A/B/C above all need a container that is gone or a slot that is
    // unbound. This one is the remaining shape: the runner answers `/healthz`,
    // the slot is still bound to this session, and yet the walk has stopped
    // publishing — including its 15 s heartbeat re-publish — for longer than
    // `EXPORT_STUCK_THRESHOLD_MS`. A hung walk, or the PR #67 residual throw.
    //
    // The signal is staleness of a persisted `progressAt`, which is bumped on
    // every received frame (counts or heartbeat). It is independent of section
    // length because the heartbeat keeps it fresh for any live walk, so the
    // threshold is a multiple of the heartbeat cadence rather than a guess at
    // how long a section takes. See issue #70.
    //
    // **Guards, each load-bearing:**
    //   - `runner_id !== null` and the slot present in `boundSessions` (or we
    //     cannot confirm it is still ours) — stands down on an all-idle pool
    //     and on a rolling deploy, the same shape branch C does.
    //   - `!deadSlots.includes(...)` — branch B owns dead containers.
    //   - `progressAt` present and parseable — an old row without it stands
    //     down rather than stranding a live export.
    if (
      session.state === "exporting" &&
      session.runner_id !== null &&
      !deadSlots.includes(session.runner_id) &&
      boundSessions !== undefined &&
      session.runner_id in boundSessions
    ) {
      let progressAt: number | null = null;
      if (session.export_state !== null) {
        try {
          const parsed = JSON.parse(session.export_state) as { progressAt?: unknown };
          if (typeof parsed.progressAt === "number" && Number.isFinite(parsed.progressAt)) {
            progressAt = parsed.progressAt;
          }
        } catch {
          progressAt = null;
        }
      }
      if (progressAt !== null && now - progressAt > EXPORT_STUCK_THRESHOLD_MS) {
        if (!(await binder.releaseForDeadRunner(session))) {
          continue;
        }
        db.clearSessionRunner(session.guid, session.runner_id);
        const changed = db.markExportStranded({
          guid: session.guid,
          now,
          idleExpiresAt: now + TTL.authenticatedIdle,
          error: "the export stopped making progress",
        });
        if (changed) {
          report.exportsStuck++;
          log.warn("export reset; its runner stopped progressing", {
            session: session.guid,
            slot: session.runner_id,
            staleMs: now - progressAt,
          });
          sse.emit(session.guid, "session-status", { state: "authenticated" });
        }
        continue;
      }
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
    // The login-expiry branch above no longer reaches a failed login — it now requires
    // `auth_state = 'authenticating'` as well as `state = 'authenticating'` (issue #49) —
    // so this branch is the only thing that frees the slot, and it runs on the very next
    // tick instead of up to 15 minutes later. On the deployed two-slot pool that delay
    // was a quarter-hour of lockout for everyone from one mistyped password.
    //
    // It is placed after the idle branch rather than before it, so an expired deadline
    // on a session this branch is about to release is handled as idle and the failed
    // login is left alone; `releaseForIdle` leaves `auth_state = 'failed'` untouched and
    // its `state = 'authenticated'` is the one write here worth watching (asserted in
    // `tests/sweep.test.ts`).
    if (session.auth_state === "failed" && session.runner_id !== null) {
      if (await binder.releaseForAuthFailure(session)) {
        report.authFailedReleased++;
      }
      continue;
    }
  }

  // Pending erases: sessions stuck mid-machine. Alert so operators know.
  try {
    const pending = pendingErase(db);
    report.pendingErases = pending.length;
    if (pending.length > 0) {
      log.warn("pending erases found", {
        count: pending.length,
        guids: pending.map((s) => s.guid),
      });
    }
  } catch (error) {
    log.warn("pendingErase check failed", { error: String(error) });
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
    //
    // **Deliberately unguarded — no `expectedSessionGuid` (F6).** Every other
    // release on this path guards its row write against a snapshot that has aged,
    // because a newer claim must not be dispossessed by an older reader. Guarding
    // *here* makes the guard a no-op in exactly the case the reconciler exists to
    // repair: the whole detection is "`runners.session_guid` names a session with
    // **no row**", so `runners.session_guid = ?` is false for every row this branch
    // acts on, `changes` is always `0`, and a divergent binding the sweeper spent a
    // whole `/release` call on would be left in place forever.
    //
    // The disposal this guard protects against is not reachable here either: the
    // liveness re-check above re-reads the session immediately before the release,
    // and a slot the orchestrator still reports bound for a guid with no row cannot
    // have been claimed by a live session in between.
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
      //
      // **Unguarded for the same reason as the call above (F6).** The `NOT EXISTS`
      // this row was selected by is precisely a `session_guid` with no matching
      // session, so `AND session_guid = ?` could only ever be false — the guard
      // would be a statement that changes nothing on every row it is asked about,
      // and a phantom row would be re-reported as a phantom on every tick for ever.
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

/** The result of a stats call, used by the boot reconciler and by the claim path. */
type StatsResult = OrchestratorResult<OrchestratorStats>;

/**
 * drawEmptiedByExclusions reports whether the only reason a claim found nothing to
 * take is that this session has already been refused every slot the orchestrator
 * names.
 *
 * It exists to keep the exclusion set honest about *why* a draw came back empty.
 * Without it, narrowing the draw turns an unreconcilable disagreement into
 * `pool-exhausted` — "every session is busy, try shortly" for a pool nobody is
 * using, which is the same wrong answer the conflict branch was written to stop
 * giving, reached by a different road.
 *
 * Narrower than `excluded.size > 0`, and the two conditions that carry the weight are
 * each a case that would be misreported without them:
 *
 *   - **an empty `slotIds`** is a pool with no slots at all. That is exhaustion, and
 *     the two sides agree about it perfectly well.
 *   - **a named slot that was not refused** is capacity this session has not tried.
 *     The claim failing says other sessions are holding it, and "busy, retry shortly"
 *     is the true advice.
 *
 * An unreachable orchestrator says nothing at all about the pool, so it cannot support
 * a claim that the two views disagree either.
 */
function drawEmptiedByExclusions(stats: StatsResult, excluded: ReadonlySet<string>): boolean {
  // Stated rather than left to `every`: nothing refused means nothing excluded.
  if (excluded.size === 0) return false;
  const named = stats.ok ? stats.value.slotIds : undefined;
  if (named === undefined || named.length === 0) return false;
  return named.every((id) => excluded.has(id));
}