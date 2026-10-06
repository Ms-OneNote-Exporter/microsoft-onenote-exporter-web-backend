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
 * The CSRF cookie is the deliberate exception: it must be readable by
 * JavaScript, because the browser echoes it in a header. It carries no authority
 * on its own — possessing it proves nothing without also holding the session
 * cookie, and the header value is verified against a token derived from a
 * per-session key the browser never sees.
 */

import { CSRF_COOKIE, SESSION_COOKIE } from "./csrf.js";

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
 * csrfCookie returns the spec for the CSRF token cookie.
 *
 * `httpOnly: false` is required and is the reason this cookie exists as a
 * separate thing: the browser has to read it to put it in a header.
 */
export function csrfCookie(value: string, maxAgeSeconds: number): CookieSpec {
  return {
    name: CSRF_COOKIE,
    value,
    httpOnly: false,
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

/** expiredCsrfCookie returns a spec that deletes the CSRF cookie. */
export function expiredCsrfCookie(): CookieSpec {
  return {
    name: CSRF_COOKIE,
    value: "",
    httpOnly: false,
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
 * because the session secret and the CSRF token are base64url and may arrive
 * quoted.
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