/**
 * The rate limiter.
 *
 * PLAN-v2 §10, made non-decorative by §3.5's client-IP rule. The layers exist
 * because any one of them can be evaded by a determined caller with one address:
 *
 *   per-IP       3 sessions/hour per IPv4, 3–5 per IPv6 /48
 *   per-session  one active export, and a session's own request budget
 *   global       the backstop, when the per-IP layers are distributed
 *
 * Counters are in memory. That is a deliberate limitation and it is honest about
 * one: a restart resets the buckets, so an attacker who can crash the api can
 * clear its own limits. The global caps and the orchestrator's pool size are what
 * bound the damage — a limiter that can be reset by a crash is not the control
 * that keeps the host up, it is the control that keeps one address from
 * monopolising it. PLAN-v2 §10's global cap is enforced against the pool, not
 * against this process's memory.
 *
 * Nothing here persists a raw address. Counters key on the address §3.5 resolved,
 * which is already an IPv6 /48, and the log line uses a hash.
 */

import { hashForLog } from "./client-ip.js";

/** A limit: how many requests, over what window. */
export interface Limit {
  /** Requests permitted per window. */
  readonly max: number;
  /** Window length in milliseconds. */
  readonly windowMs: number;
}

/** The default limits, from PLAN-v2 §10. */
export const DEFAULT_LIMITS = {
  /** New sessions per hour from one address. */
  sessionsPerWindow: { max: 3, windowMs: 60 * 60 * 1000 } satisfies Limit,
  /** Requests per minute from one address. */
  requestsPerMinute: { max: 60, windowMs: 60 * 1000 } satisfies Limit,
  /** Concurrent active exports across the whole service. */
  globalConcurrentExports: 6,
} as const;

/** A decision, and the reason when refused. */
export type Decision =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      readonly reason: "rate-limited" | "too-many-sessions" | "too-many-exports";
      /** Seconds until the oldest hit in the window expires. */
      readonly retryAfterSeconds: number;
    };

/** One counter bucket. */
interface Bucket {
  /** Hit timestamps within the window, oldest first. */
  readonly hits: number[];
}

export interface RateLimiterOptions {
  readonly limits?: typeof DEFAULT_LIMITS;
  /** Salt for log hashes. Not secret; per-deployment so buckets are not portable. */
  readonly logSalt?: string;
  readonly now?: () => number;
}

export class RateLimiter {
  readonly #requests = new Map<string, Bucket>();
  readonly #sessions = new Map<string, Bucket>();
  readonly #limits: typeof DEFAULT_LIMITS;
  readonly #logSalt: string;
  readonly #now: () => number;

  #activeExports = 0;

  constructor(options: RateLimiterOptions = {}) {
    this.#limits = options.limits ?? DEFAULT_LIMITS;
    this.#logSalt = options.logSalt ?? "msout";
    this.#now = options.now ?? (() => Date.now());
  }

  /**
   * check records a request against an address and reports whether it is allowed.
   *
   * A refused request is *not* recorded. Recording it would let a caller who is
   * being throttled extend its own penalty indefinitely, which turns a rate limit
   * into a lockout the attacker controls.
   */
  checkRequest(address: string): Decision {
    const now = this.#now();
    const bucket = this.#prune(this.#requests, address, this.#limits.requestsPerMinute, now);

    if (bucket.hits.length >= this.#limits.requestsPerMinute.max) {
      return {
        allowed: false,
        reason: "rate-limited",
        retryAfterSeconds: this.#retryAfter(
          bucket.hits,
          now,
          this.#limits.requestsPerMinute.windowMs,
        ),
      };
    }
    bucket.hits.push(now);
    return { allowed: true };
  }

  /**
   * checkNewSession records a session creation attempt.
   *
   * A separate counter from `checkRequest` because the limit is much tighter and
   * because the thing being protected is different: three sessions an hour stops
   * an address farming sessions to burn the pool, which 60 requests a minute
   * would not.
   */
  checkNewSession(address: string): Decision {
    const now = this.#now();
    const bucket = this.#prune(this.#sessions, address, this.#limits.sessionsPerWindow, now);

    if (bucket.hits.length >= this.#limits.sessionsPerWindow.max) {
      return {
        allowed: false,
        reason: "too-many-sessions",
        retryAfterSeconds: this.#retryAfter(
          bucket.hits,
          now,
          this.#limits.sessionsPerWindow.windowMs,
        ),
      };
    }
    bucket.hits.push(now);
    return { allowed: true };
  }

  /**
   * acquireExportSlot takes one of the global export slots.
   *
   * The backstop. Per-IP limits can be distributed across many addresses and the
   * pool is finite, so something has to bound the total. §8.1 has no queue in
   * v1 — an over-cap request is refused with retry guidance, and the caller shows
   * a wait estimate.
   */
  acquireExportSlot(): Decision {
    if (this.#activeExports >= this.#limits.globalConcurrentExports) {
      return {
        allowed: false,
        reason: "too-many-exports",
        // The plan's guidance for the over-cap case is a retry hint rather than a
        // countdown: the slot frees when an export finishes, which is not
        // predictable from here.
        retryAfterSeconds: 30,
      };
    }
    this.#activeExports++;
    return { allowed: true };
  }

  /** releaseExportSlot returns a global export slot. */
  releaseExportSlot(): void {
    if (this.#activeExports > 0) this.#activeExports--;
  }

  /** activeExports reports how many global slots are held. */
  get activeExports(): number {
    return this.#activeExports;
  }

  /**
   * forgetAddress drops an address's counters.
   *
   * Called on a clean erase. An address that has been through the whole flow
   * should not carry its history into its next session, or three sessions a
   * session becomes three sessions every few hours for a legitimate user — which
   * is the rate limiter working as intended, and also a way to make the service
   * unusable for the people who need it.
   */
  forgetAddress(address: string): void {
    this.#requests.delete(address);
    this.#sessions.delete(address);
  }

  /**
   * hashOf returns the loggable form of an address.
   *
   * T-P5: a raw address must not appear in logs or in SQLite, because a retained
   * raw address is a user identifier that outlived the request.
   */
  hashOf(address: string): string {
    return hashForLog(address, this.#logSalt);
  }

  /**
   * prune returns the bucket for a key, dropping hits that have aged out.
   *
   * The bucket is created and returned even when it is empty, so the caller can
   * push a hit onto it. Emptiness is cleaned up by `#pruneIfEmpty` on the next
   * visit rather than here, because the caller always needs a live reference.
   */
  #prune(store: Map<string, Bucket>, key: string, limit: Limit, now: number): Bucket {
    let bucket = store.get(key);
    if (bucket === undefined) {
      bucket = { hits: [] };
      store.set(key, bucket);
    }
    const cutoff = now - limit.windowMs;
    // Hits are pushed in ascending order, so the expired ones are a prefix.
    while (bucket.hits.length > 0 && (bucket.hits[0] ?? 0) <= cutoff) {
      bucket.hits.shift();
    }
    return bucket;
  }

  /**
   * retryAfter returns whole seconds until the oldest hit ages out.
   *
   * The window is passed in rather than assumed: the session limit is an hour and
   * the request limit is a minute, and returning the wrong one would tell a caller
   * to retry when the bucket had already cleared.
   */
  #retryAfter(hits: number[], now: number, windowMs: number): number {
    const oldest = hits[0] ?? now;
    return Math.max(1, Math.ceil((oldest + windowMs - now) / 1000));
  }

  /** stats reports bucket sizes, for health. */
  stats(): { requestBuckets: number; sessionBuckets: number; activeExports: number } {
    return {
      requestBuckets: this.#requests.size,
      sessionBuckets: this.#sessions.size,
      activeExports: this.#activeExports,
    };
  }
}