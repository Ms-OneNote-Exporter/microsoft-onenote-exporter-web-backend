/**
 * The configured per-hour session cap must reach the limiter.
 *
 * ## Why this file exists separately
 *
 * `sessionsPerHour` is read from the environment by `config.ts` and consumed by
 * `index.ts`. Those are two files, and nothing between them asserted anything —
 * which is §1's shape exactly: the value is *set*, the handler *runs*, and the
 * limiter carries on enforcing the number that was compiled into it.
 *
 * So the assertion here is deliberately **behavioural**. It does not read
 * `config.sessionsPerHour` and compare it to something; it builds the limiter the
 * way `index.ts` does and counts refusals, because the only thing that matters is
 * which attempt is turned away.
 *
 * The number that matters is the boundary: the **42nd** attempt is refused and
 * the 43rd never gets there. A test asserting `expect(cfg.sessionsPerHour).toBe(42)`
 * would pass with the wiring deleted.
 */

import { describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { RateLimiter, DEFAULT_LIMITS, buildRateLimiter } from "../src/rate-limit.js";

/**
 * The environment `config.test.ts` uses, minus the parts these tests do not vary.
 *
 * Re-declared rather than imported because that suite's `baseEnv` is not exported,
 * and a test that reaches into another file's private fixture is how two suites
 * start disagreeing about what a valid environment is.
 */
function baseEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    ALLOWED_ORIGINS: "https://app.example.com",
    CSRF_KEY: "x".repeat(43),
    ORCHESTRATOR_URL: "http://orchestrator:9100",
    ORCHESTRATOR_HMAC_SECRET: "y".repeat(43),
    RUNNER_TOKEN: "runner-token-for-tests",
    PUBLIC_ORIGIN: "https://one-backend.example.com",
    ...overrides,
  } as NodeJS.ProcessEnv;
}

/**
 * Builds the limiter through `buildRateLimiter` — the same function `index.ts`
 * calls.
 *
 * The first version of this file spelled the wiring out inline instead, and a
 * revert of `index.ts`'s own call site left every test here **green**. That is
 * the finding worth keeping: a test fixture that reimplements the wiring tests
 * the fixture, and §0.6.4 is what that costs.
 *
 * ## What this still does not cover
 *
 * That `index.ts` calls `buildRateLimiter(config)` at all. One call site, checked
 * by the type checker for the argument's shape and by this file for the
 * behaviour behind it; nothing observes the call itself. Closing that would mean
 * booting the app and posting real sessions, which needs an orchestrator stub
 * this change does not otherwise need. Recorded rather than claimed.
 */
function limiterFor(env: Record<string, string>): RateLimiter {
  return buildRateLimiter(loadConfig(baseEnv(env)));
}

/**
 * Counts how many session creations are allowed before the first refusal.
 *
 * A fixed clock, so the window never rolls over mid-test — `Date.now()` would let
 * this pass or fail depending on the minute it ran in, which is a coin flip
 * wearing a test's clothes.
 */
function allowedBeforeRefusal(limiter: RateLimiter, address: string): number {
  let allowed = 0;
  for (let attempt = 1; attempt <= 200; attempt += 1) {
    if (!limiter.checkNewSession(address).allowed) return allowed;
    allowed = attempt;
  }
  return allowed;
}

describe("the configured session cap is the one the limiter enforces", () => {
  it("refuses on the committed default when nothing is configured", () => {
    expect(allowedBeforeRefusal(limiterFor({}), "198.51.100.7")).toBe(
      DEFAULT_LIMITS.sessionsPerWindow.max,
    );
  });

  it("allows 42 and refuses the 43rd when the deployment raises it", () => {
    const limiter = limiterFor({ RATE_LIMIT_SESSIONS_PER_HOUR: "42" });
    expect(allowedBeforeRefusal(limiter, "198.51.100.7")).toBe(42);

    // The boundary stated explicitly, because "42 allowed" and "the 43rd is
    // refused" are different claims and only the second one is the control.
    expect(limiter.checkNewSession("198.51.100.7")).toMatchObject({
      allowed: false,
      reason: "too-many-sessions",
    });
  });

  it("keeps the per-minute request cap at its default when only the session cap moves", () => {
    // The other two limits are deliberately not configurable, because they are
    // not the knob a deployment raises: one bounds a single client's request rate
    // and the other bounds the whole service whatever the address count. If a
    // future change makes them follow this variable, the service loses its
    // backstop and this test is the thing that says so.
    const limiter = limiterFor({ RATE_LIMIT_SESSIONS_PER_HOUR: "42" });
    let refused = 0;
    for (let i = 0; i < DEFAULT_LIMITS.requestsPerMinute.max + 1; i += 1) {
      if (!limiter.checkRequest("198.51.100.7").allowed) {
        refused = i + 1;
        break;
      }
    }
    expect(refused).toBe(DEFAULT_LIMITS.requestsPerMinute.max + 1);
  });

  it("still buckets per address, so a raise is not a single global allowance", () => {
    // The half of bug #37 this knob could have reintroduced: if raising the cap
    // had collapsed the buckets, every caller on the internet would be sharing
    // 42 an hour — a fourteen-fold larger blast radius than the default, and a
    // quieter failure because nothing would report it.
    const limiter = limiterFor({ RATE_LIMIT_SESSIONS_PER_HOUR: "42" });
    expect(allowedBeforeRefusal(limiter, "198.51.100.7")).toBe(42);

    // A different address has its own bucket and is unaffected by the first.
    expect(limiter.checkNewSession("198.51.100.8").allowed).toBe(true);
    expect(limiter.checkNewSession("198.51.100.8").allowed).toBe(true);
  });
});