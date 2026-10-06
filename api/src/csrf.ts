/**
 * Cross-origin enforcement: the Origin allowlist and the CSRF token check.
 *
 * PLAN-v3 §3.3 makes both load-bearing for the first time, because the frontend
 * is a different origin and the session cookie is therefore `SameSite=None` and
 * sent on cross-site requests. Four independent layers, each of which alone
 * blocks classic CSRF:
 *
 *   1. `X-CSRF-Token` on every non-GET. A custom header is not CORS-safelisted,
 *      so the browser must preflight, and a preflight only succeeds for an
 *      allowlisted origin. A non-allowlisted origin therefore cannot cause the
 *      browser to transmit a state-changing body *at all*.
 *   2. The Origin allowlist, checked server-side on every non-GET. Independent of
 *      layer 1, so it still protects a future route that forgets the header.
 *   3. Content-Type pinning on mutating routes — except the credential route,
 *      which deliberately accepts whatever is sent, because pinning a content
 *      type on a body this service refuses to parse is theatre.
 *   4. Cookie attributes (`__Host-`, Secure, HttpOnly, SameSite=None, Path=/).
 *
 * CORS is not an access control. It constrains browsers, not curl. Everything
 * here is a browser-shaped mitigation; every authorisation decision lives in the
 * handlers, and the api stays fully usable with no frontend deployed at all
 * (T-C7).
 */

import { csrfTokensMatch } from "./session.js";

/** Cookie names. The session cookie's prefix is load-bearing; see cookies.ts. */
export const SESSION_COOKIE = "__Host-msout";
export const CSRF_COOKIE = "msout_csrf";

/** The header carrying the CSRF token. */
export const CSRF_HEADER = "x-csrf-token";

/** Why a cross-origin check failed. */
export type CrossOriginFailure =
  | "origin-not-allowed"
  | "csrf-missing"
  | "csrf-mismatch";

/** The result of checking one non-GET request. */
export type CrossOriginCheck =
  | { readonly ok: true; readonly allowedOrigin: string | null }
  | { readonly ok: false; readonly failure: CrossOriginFailure };

/**
 * isOriginAllowed reports whether an Origin header value is in the allowlist.
 *
 * Exact match against the configured set, never a prefix or suffix comparison
 * and never a reflection. Reflection would allowlist every origin at once and
 * make layer 1 decorative — the preflight only stops a *non-allowlisted* origin,
 * so an allowlist that reflects everything stops nothing.
 *
 * A request with no Origin header returns true: it is not a browser cross-origin
 * request, and the alternative is to break curl, the health check and the
 * orchestrator's own calls. CORS is not the access control, so this is not a
 * hole — the CSRF token is still required, and a browser always sends Origin on
 * a cross-origin request.
 */
export function isOriginAllowed(
  origin: string | undefined,
  allowed: ReadonlySet<string>,
): boolean {
  if (origin === undefined || origin === "") return true;
  return allowed.has(origin);
}

/**
 * corsHeaders returns the response headers for a request.
 *
 * `ACAO` is emitted only for an allowlisted origin, and
 * `Access-Control-Allow-Credentials: true` only alongside that same non-wildcard
 * ACAO. `Vary: Origin` is always set, because a cache that served one origin's
 * ACAO to another would turn the allowlist into a suggestion.
 *
 * Returning an empty object for a foreign origin is the important case: the
 * header must be *absent*, not empty and not `null`.
 */
export function corsHeaders(
  origin: string | undefined,
  allowed: ReadonlySet<string>,
  requestHeaders?: readonly string[],
  maxAgeSeconds?: number,
): Record<string, string> {
  const out: Record<string, string> = { vary: "Origin" };
  if (origin === undefined || !allowed.has(origin)) {
    // Foreign origin: no ACAO, no ACAC. A `null` or empty ACAO would be
    // syntactically present and some caches treat it as a match.
    return out;
  }

  out["access-control-allow-origin"] = origin;
  out["access-control-allow-credentials"] = "true";
  if (requestHeaders && requestHeaders.length > 0) {
    out["access-control-allow-headers"] = requestHeaders.join(", ");
  }
  out["access-control-allow-methods"] = "GET, POST, OPTIONS";
  if (maxAgeSeconds !== undefined) {
    out["access-control-max-age"] = String(maxAgeSeconds);
  }
  return out;
}

/**
 * checkNonGetRequest applies layers 1 and 2 of PLAN-v3 §3.3.
 *
 * Origin first, then the token. The order matters for the failure modes: a
 * foreign origin gets a 403 whether or not it knows how to compute a token,
 * and doing the cheap exact-match check before the HMAC comparison keeps the
 * expensive path off requests that are going to be rejected anyway.
 *
 * `presentedToken` is the raw header value. It is compared with a
 * constant-time equality inside `csrfTokensMatch`; nothing here trims or
 * normalises it first, because a token that needed normalising would be a token
 * the client is not sending correctly.
 */
export function checkNonGetRequest(input: {
  origin: string | undefined;
  presentedToken: string | undefined;
  allowed: ReadonlySet<string>;
  csrfKey: string;
  sessionId: string;
  /** Injected so the constant-time comparison can be substituted in tests. */
  tokensMatch?: (presented: string, key: string, id: string) => boolean;
}): CrossOriginCheck {
  const allowedOrigin =
    input.origin !== undefined && input.allowed.has(input.origin)
      ? input.origin
      : null;

  if (!isOriginAllowed(input.origin, input.allowed)) {
    return { ok: false, failure: "origin-not-allowed" };
  }
  if (input.presentedToken === undefined || input.presentedToken === "") {
    return { ok: false, failure: "csrf-missing" };
  }

  // Imported lazily to keep csrf.ts free of a circular import on session.ts.
  // The default is the real constant-time comparison; the seam exists so a test
  // can assert the *call* happens without re-deriving a token.
  const match = input.tokensMatch ?? csrfTokensMatch;
  if (!match(input.presentedToken, input.csrfKey, input.sessionId)) {
    return { ok: false, failure: "csrf-mismatch" };
  }
  return { ok: true, allowedOrigin };
}

/** The headers a preflight response carries. */
export function preflightHeaders(
  origin: string | undefined,
  allowed: ReadonlySet<string>,
  requestHeaders: readonly string[],
): Record<string, string> {
  return corsHeaders(origin, allowed, requestHeaders, 600);
}