/**
 * Cookies.
 *
 * PLAN-v3 §3.3 layer 4, and §4. The attribute set is not incidental:
 *
 *   `__Host-`  the prefix forbids a `Domain` attribute, so a compromised sibling
 *              subdomain cannot shadow the cookie and read the session. This is
 *              why the session cookie is named `__Host-msout` rather than
 *              something readable.
 *   Secure      required by the prefix; TLS only.
 *   HttpOnly    the secret must be unreachable from JavaScript, which is what
 *              makes a frontend compromise yield no session secret (§4, T3).
 *   SameSite=None  required, not chosen. The frontend is a different origin and
 *              therefore cross-site, and `Lax` cookies are not sent on cross-site
 *              fetch — the app would break, and the tempting "fix" is to move to
 *              `None` without noticing the CSRF implication. That is precisely
 *              the failure §3.3 exists to prevent, which is why the CSRF header
 *              check is not optional here.
 *   Path=/      required by the prefix.
 *
 * There is deliberately no second, readable cookie.
 *
 * The obvious way to hand a CSRF token to JavaScript is a non-HttpOnly cookie the
 * page reads with `document.cookie`. That works when the page and the API share
 * an origin. They do not — the frontend is Component A and this is Component B,
 * on a different host (§1.1). A cookie set here is scoped to *this* host with no
 * `Domain`, so the frontend's `document.cookie` never returns it, and every
 * mutating route would 403 with a token nobody can read. mac found this during
 * review; §3.3's "delivered in a readable cookie" is a single-origin assumption
 * that the split invalidated.
 *
 * The token is returned in the response *body* instead, from the two responses
 * the frontend already reads: `POST /api/session` at creation and
 * `GET /api/session/status` on every mount, which is what §7.5's restore flow
 * calls anyway. That is safe because a cross-origin reader is blocked by CORS —
 * `corsHeaders` emits ACAO only for an allowlisted origin, so an attacker page can
 * cause the request (the `SameSite=None` cookie rides along) but cannot read the
 * response. It carries no authority on its own: without the `HttpOnly` session
 * cookie it is worth nothing.
 *
 * So the split costs a cookie and gains one fewer thing to reason about — no
 * `Domain` scope, no sibling-subdomain readability question, and no question
 * about whether the two origins share a registrable domain at all.
 */

import { SESSION_COOKIE } from "./csrf.js";

/** Cookie attributes, as a name/value pair plus flags. */
export interface CookieSpec {
  readonly name: string;
  readonly value: string;
  readonly httpOnly: boolean;
  readonly secure: boolean;
  readonly sameSite: "None" | "Lax" | "Strict";
  readonly path: string;
  /** Absolute expiry in seconds-since-epoch, or null for a session cookie. */
  readonly expires: number | null;
  /** Max-Age in seconds, or null. */
  readonly maxAge: number | null;
}

/**
 * sessionCookie returns the spec for the session cookie.
 *
 * `maxAgeSeconds` is the absolute session cap (12 h by default), which is also
 * the session's own TTL — the browser dropping the cookie and the server
 * expiring the row are the same deadline, so a stale tab cannot present a
 * cookie the server will honour past it.
 */
export function sessionCookie(value: string, maxAgeSeconds: number): CookieSpec {
  return {
    name: SESSION_COOKIE,
    value,
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    expires: null,
    maxAge: maxAgeSeconds,
  };
}

/**
 * expiredSessionCookie returns a spec that deletes the session cookie.
 *
 * PLAN-v3 T7 and §11: erase must invalidate the server row **and** expire the
 * cookie, or a stale tab keeps a live-looking session. Both orders have to work,
 * including when the row is already gone — so this function takes no session
 * state and cannot fail.
 *
 * `Max-Age=0` and a past `Expires` are both emitted, because a browser that
 * ignores one of them will honour the other.
 *
 * There is no CSRF counterpart: the token lives in the frontend's memory and in
 * response bodies, never in a cookie, so there is nothing to expire. The token
 * stops validating the moment the row is gone, because the per-session key it is
 * derived from is destroyed with it.
 */
export function expiredSessionCookie(): CookieSpec {
  return {
    name: SESSION_COOKIE,
    value: "",
    httpOnly: true,
    secure: true,
    sameSite: "None",
    path: "/",
    expires: 0,
    maxAge: 0,
  };
}

/**
 * serialiseCookie renders a spec into a Set-Cookie header value.
 *
 * The `__Host-` prefix is not emitted as an attribute — it is part of the name,
 * and adding it again would corrupt the cookie. Its requirements (Secure, Path=/,
 * no Domain) are all enforced by the specs above, which is why this function has
 * no way to emit a Domain.
 */
export function serialiseCookie(spec: CookieSpec): string {
  const parts = [`${spec.name}=${spec.value}`, `Path=${spec.path}`];
  if (spec.httpOnly) parts.push("HttpOnly");
  if (spec.secure) parts.push("Secure");
  if (spec.sameSite) parts.push(`SameSite=${spec.sameSite}`);
  if (spec.maxAge !== null) parts.push(`Max-Age=${spec.maxAge}`);
  if (spec.expires !== null) {
    parts.push(`Expires=${new Date(spec.expires * 1000).toUTCString()}`);
  }
  return parts.join("; ");
}

/**
 * parseCookies parses a Cookie header into a name → value map.
 *
 * Written by hand rather than pulled in, because a cookie parser is the kind of
 * dependency that comes with a prototype-pollution advisory history and this
 * service has no use for one. Values are percent-decoded, which is required
 * because the session secret is base64url and may arrive quoted.
 *
 * A malformed pair is skipped rather than throwing: one bad cookie should not
 * fail a request that also carries a valid session.
 */
export function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;

  for (const pair of header.split(";")) {
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();
    if (name === "") continue;
    let value = pair.slice(eq + 1).trim();
    // A quoted-string per RFC 6265. base64url never needs quoting, but a
    // misbehaving client may add it and the value should still compare.
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    out.set(name, safeDecode(value));
  }
  return out;
}

/** safeDecode percent-decodes, falling back to the raw value on bad input. */
function safeDecode(value: string): string {
  if (!value.includes("%")) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    // A malformed escape is the client's problem, not a reason to 500.
    return value;
  }
}

/** getCookie returns one cookie's value, or undefined. */
export function getCookie(
  header: string | undefined,
  name: string,
): string | undefined {
  return parseCookies(header).get(name);
}