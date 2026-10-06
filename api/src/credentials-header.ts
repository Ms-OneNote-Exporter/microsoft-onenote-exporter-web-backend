/**
 * The header carrying the Microsoft account on the credential route.
 *
 * Its own module because both `server.ts` and `routes.ts` need it, and `server.ts`
 * already imports `routes.ts` — declaring it in routes and importing it back would
 * be a cycle. Small and boring is the right shape for a constant whose only job is
 * to be spelled the same way in two places.
 */

/** The header name. Lower-case: HTTP header names are case-insensitive and the
 *  preflight allowlist compares lower-case. */
export const ACCOUNT_HEADER = "x-microsoft-account";

/**
 * A cap on the account, generously above any real address or UPN.
 *
 * Bounded because it crosses into the runner and into container logs there; an
 * unbounded header is an unbounded thing to log. 320 is the longest address RFC
 * 5321 permits, and a UPN is shorter.
 */
export const MAX_ACCOUNT_CHARS = 320;
