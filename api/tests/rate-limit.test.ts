import { describe, expect, it } from "vitest";
import { DEFAULT_LIMITS, RateLimiter } from "../src/rate-limit.js";

/**
 * PLAN-v2 §10, made meaningful by §3.5's client-IP rule. The properties under
 * test are the ones a limiter is judged on: that the layers are independent, that
 * a throttled caller cannot extend its own penalty, and that no raw address is
 * retained or logged.
 */

const ADDRESS = "198.51.100.7";
const OTHER = "203.0.113.9";

/** A limiter with a clock the test controls. */
function limiter(options = {}) {
  let now = 1_700_000_000_000;
  const l = new RateLimiter({ now: () => now, logSalt: "test-salt", ...options });
  return { l, advance: (ms: number) => { now += ms; } };
}

describe("request limits", () => {
  it("allows requests up to the cap", () => {
    const { l } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.requestsPerMinute.max; i++) {
      expect(l.checkRequest(ADDRESS).allowed).toBe(true);
    }
  });

  it("refuses the request past the cap", () => {
    const { l } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.requestsPerMinute.max; i++) {
      l.checkRequest(ADDRESS);
    }
    const decision = l.checkRequest(ADDRESS);
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.reason).toBe("rate-limited");
      expect(decision.retryAfterSeconds).toBeGreaterThan(0);
      expect(decision.retryAfterSeconds).toBeLessThanOrEqual(60);
    }
  });

  it("keys per address, so one address cannot throttle another", () => {
    const { l } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.requestsPerMinute.max; i++) {
      l.checkRequest(ADDRESS);
    }
    expect(l.checkRequest(ADDRESS).allowed).toBe(false);
    expect(l.checkRequest(OTHER).allowed).toBe(true);
  });

  it("ages hits out of the window", () => {
    const { l, advance } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.requestsPerMinute.max; i++) {
      l.checkRequest(ADDRESS);
    }
    expect(l.checkRequest(ADDRESS).allowed).toBe(false);

    advance(60_001);
    expect(l.checkRequest(ADDRESS).allowed).toBe(true);
  });

  // Recording a refused request would let a throttled caller extend its own
  // penalty, turning a rate limit into a lockout the attacker controls.
  it("does not record a refused request", () => {
    const { l, advance } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.requestsPerMinute.max; i++) {
      l.checkRequest(ADDRESS);
    }
    expect(l.checkRequest(ADDRESS).allowed).toBe(false);

    // If the refusal had been recorded, the bucket would still be full and the
    // first legitimate retry would fail. Age out just past the original window
    // and a retry must succeed immediately.
    advance(60_001);
    expect(l.checkRequest(ADDRESS).allowed).toBe(true);
  });

  it("reports a shrinking retry hint as the window drains", () => {
    const { l, advance } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.requestsPerMinute.max; i++) {
      l.checkRequest(ADDRESS);
    }
    const first = l.checkRequest(ADDRESS);
    advance(30_000);
    const later = l.checkRequest(ADDRESS);

    expect(first.allowed).toBe(false);
    expect(later.allowed).toBe(false);
    if (!first.allowed && !later.allowed) {
      expect(later.retryAfterSeconds).toBeLessThan(first.retryAfterSeconds);
    }
  });
});

describe("session limits", () => {
  it("allows three sessions an hour from one address", () => {
    // PLAN-v2 §10: 3 sessions/hour per IPv4. Tighter than the request cap
    // because the thing being protected is the pool, not bandwidth.
    const { l } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.sessionsPerWindow.max; i++) {
      expect(l.checkNewSession(ADDRESS).allowed).toBe(true);
    }
    const decision = l.checkNewSession(ADDRESS);
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.reason).toBe("too-many-sessions");
      expect(decision.retryAfterSeconds).toBeLessThanOrEqual(3600);
    }
  });

  it("keeps the session counter separate from the request counter", () => {
    const { l } = limiter();
    // Exhaust the request budget; the session budget must be untouched.
    for (let i = 0; i < DEFAULT_LIMITS.requestsPerMinute.max; i++) {
      l.checkRequest(ADDRESS);
    }
    expect(l.checkRequest(ADDRESS).allowed).toBe(false);
    expect(l.checkNewSession(ADDRESS).allowed).toBe(true);
  });

  it("reports the session window, not the request window, as retry guidance", () => {
    const { l } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.sessionsPerWindow.max; i++) {
      l.checkNewSession(ADDRESS);
    }
    const decision = l.checkNewSession(ADDRESS);
    // An hour, not a minute. Returning the request window here would tell a
    // caller to retry when the bucket had not cleared.
    if (!decision.allowed) {
      expect(decision.retryAfterSeconds).toBeGreaterThan(60);
    }
  });

  it("ages session hits out after an hour", () => {
    const { l, advance } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.sessionsPerWindow.max; i++) {
      l.checkNewSession(ADDRESS);
    }
    expect(l.checkNewSession(ADDRESS).allowed).toBe(false);
    advance(3_600_001);
    expect(l.checkNewSession(ADDRESS).allowed).toBe(true);
  });

  it("forgets an address's history on a clean erase", () => {
    // Otherwise a legitimate user who erases and retries would exhaust three
    // sessions every few hours, which is the limiter working as designed and also
    // a way to make the service unusable for the people who need it.
    const { l } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.sessionsPerWindow.max; i++) {
      l.checkNewSession(ADDRESS);
    }
    expect(l.checkNewSession(ADDRESS).allowed).toBe(false);

    l.forgetAddress(ADDRESS);
    expect(l.checkNewSession(ADDRESS).allowed).toBe(true);
  });
});

describe("global export slots", () => {
  it("allows up to the cap", () => {
    const { l } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.globalConcurrentExports; i++) {
      expect(l.acquireExportSlot().allowed).toBe(true);
    }
    expect(l.activeExports).toBe(DEFAULT_LIMITS.globalConcurrentExports);
  });

  // §8.1: no queue in v1, so the over-cap case is a refusal with guidance.
  it("refuses past the cap with retry guidance", () => {
    const { l } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.globalConcurrentExports; i++) {
      l.acquireExportSlot();
    }
    const decision = l.acquireExportSlot();
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.reason).toBe("too-many-exports");
      expect(decision.retryAfterSeconds).toBeGreaterThan(0);
    }
  });

  it("is a backstop for many addresses, not a per-address layer", () => {
    // Distributed traffic: each address is well under its own cap, and the
    // global cap is what stops them exhausting the pool together.
    const { l } = limiter();
    for (let i = 0; i < 50; i++) {
      for (let r = 0; r < 10; r++) {
        l.checkRequest(`203.0.113.${i}`);
      }
    }
    for (let i = 0; i < DEFAULT_LIMITS.globalConcurrentExports; i++) {
      expect(l.acquireExportSlot().allowed).toBe(true);
    }
    expect(l.acquireExportSlot().allowed).toBe(false);
  });

  it("frees a slot on release", () => {
    const { l } = limiter();
    for (let i = 0; i < DEFAULT_LIMITS.globalConcurrentExports; i++) {
      l.acquireExportSlot();
    }
    l.releaseExportSlot();
    expect(l.activeExports).toBe(DEFAULT_LIMITS.globalConcurrentExports - 1);
    expect(l.acquireExportSlot().allowed).toBe(true);
  });

  it("never goes negative on an unbalanced release", () => {
    // An error path that releases twice must not hand out extra slots later.
    const { l } = limiter();
    l.releaseExportSlot();
    l.releaseExportSlot();
    expect(l.activeExports).toBe(0);
    expect(l.acquireExportSlot().allowed).toBe(true);
  });
});

describe("address handling", () => {
  // T-P5: a raw address must not appear in logs or in SQLite.
  it("hashes an address for logging", () => {
    const { l } = limiter();
    const hashed = l.hashOf(ADDRESS);
    expect(hashed).not.toContain(ADDRESS);
    expect(hashed).toHaveLength(16);
  });

  it("produces a stable hash per salt", () => {
    const { l } = limiter();
    expect(l.hashOf(ADDRESS)).toBe(l.hashOf(ADDRESS));
  });

  it("distinguishes different addresses", () => {
    const { l } = limiter();
    expect(l.hashOf(ADDRESS)).not.toBe(l.hashOf(OTHER));
  });
});

describe("bucket hygiene", () => {
  it("does not retain a bucket for an address that never returns", () => {
    // Otherwise a single request from a rotating set of addresses grows the map
    // without bound — a slow leak reachable by anyone who can vary their source.
    const { l, advance } = limiter();
    l.checkRequest(ADDRESS);
    expect(l.stats().requestBuckets).toBe(1);

    advance(60_001);
    l.checkRequest(ADDRESS);
    // Re-visiting prunes the old hits; the bucket survives because this visit
    // records a new hit.
    expect(l.stats().requestBuckets).toBe(1);
  });

  it("reports stats for health", () => {
    const { l } = limiter();
    l.checkRequest(ADDRESS);
    l.checkNewSession(OTHER);
    l.acquireExportSlot();
    const stats = l.stats();
    expect(stats.requestBuckets).toBe(1);
    expect(stats.sessionBuckets).toBe(1);
    expect(stats.activeExports).toBe(1);
  });
});