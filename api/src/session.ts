/**
 * Session secrets and CSRF tokens.
 *
 * PLAN-v3 §4 promotes the session secret from v2's deferred pre-launch blocker
 * to a v1 requirement, because the two-component split removed the same-origin
 * justification. Three properties, each of which is a control rather than a
 * convention:
 *
 *   1. The secret is 256 bits, client-generated. The api validates the length
 *      mechanically instead of trusting the client, because a compromised
 *      Component A could generate a weak one.
 *   2. Only sha256(secret) is stored. The secret itself is never written, logged
 *      or echoed.
 *   3. The CSRF token is *derived*, not stored per request:
 *      `base64url(HMAC-SHA256(csrf_key, session_id))`. So there is no server-side
 *      token table to keep consistent with the session table.
 */

import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

/**
 * The session secret's exact shape: 43 base64url characters, which is 32 bytes
 * unpadded.
 *
 * Checked on arrival. A 4-character secret is rejected as firmly as a wrong one,
 * because the failure mode of accepting one is an attacker enumerating it.
 */
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The GUID shape. 122 bits of entropy, lowercase, never shortened. */
const GUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Why a session credential was rejected. Kept distinct so handlers can map them. */
export type CredentialRejection =
  | "malformed-guid"
  | "malformed-secret"
  | "unknown-session"
  | "wrong-secret"
  | "expired";

/** isValidSecret reports whether a value is a well-formed session secret. */
export function isValidSecret(value: unknown): value is string {
  return typeof value === "string" && SECRET_PATTERN.test(value);
}

/** isValidGuid reports whether a value is a well-formed session GUID. */
export function isValidGuid(value: unknown): value is string {
  return typeof value === "string" && GUID_PATTERN.test(value);
}

/**
 * hashSecret returns the stored form of a session secret: base64url(sha256).
 *
 * sha256 is not a password hash and does not need to be: the input is 256 bits
 * of client-generated entropy, so there is no dictionary to attack. A
 * deliberately slow KDF here would add latency to every request and buy nothing,
 * and its cost would be paid on the credential path's hot route.
 */
export function hashSecret(secret: string): string {
  return base64url(createHash("sha256").update(secret, "utf8").digest());
}

/**
 * secretsMatch compares a presented secret against a stored hash in constant
 * time.
 *
 * The timingSafeEqual call requires equal lengths, so the hex lengths are
 * compared first — that leaks only whether the *stored* value is well-formed,
 * which is not caller-controlled.
 */
export function secretsMatch(presented: string, storedHash: string): boolean {
  const computed = Buffer.from(hashSecret(presented), "utf8");
  const stored = Buffer.from(storedHash, "utf8");
  if (computed.length !== stored.length || stored.length === 0) {
    return false;
  }
  return timingSafeEqual(computed, stored);
}

/** generateCsrfKey returns a fresh per-session CSRF key, base64url. */
export function generateCsrfKey(): string {
  return base64url(randomBytes(32));
}

/**
 * deriveCsrfToken computes the CSRF token for a session.
 *
 * Derived rather than random per request so there is no server-side token table
 * to keep consistent, and so a browser tab that reconnects can recompute what it
 * expects without asking.
 *
 * `csrfKey` is per-session and destroyed with the session, so a token from an
 * erased session cannot validate.
 */
export function deriveCsrfToken(csrfKey: string, sessionId: string): string {
  return base64url(
    createHmac("sha256", csrfKey).update(sessionId, "utf8").digest(),
  );
}

/**
 * csrfTokensMatch compares a presented token against the derived one in constant
 * time (T-C4).
 *
 * The derivation is repeated rather than the expected token being carried around,
 * so there is nothing to store between requests and nothing to leak from memory.
 */
export function csrfTokensMatch(
  presented: string,
  csrfKey: string,
  sessionId: string,
): boolean {
  const expected = deriveCsrfToken(csrfKey, sessionId);
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) {
    // timingSafeCompare would return 0 on a length mismatch, which is the same
    // answer; returning early here avoids the call and is not a timing
    // distinction, since both paths return false.
    return false;
  }
  return timingSafeEqual(a, b);
}

/** base64url encodes bytes without padding. */
export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * generateArtifactId returns an opaque download identifier.
 *
 * 32 random bytes, base64url, 43 characters — the same width and alphabet as the
 * session secret, and for the same reason. It appears in a download URL
 * (`GET /files/<artifactId>`), so it must be unguessable and must encode nothing:
 * v2's download paths leaked the session GUID into Caddy access logs and the
 * notebook name into any Referer (PLAN-v3 §5, invariant 8).
 */
export function generateArtifactId(): string {
  return base64url(randomBytes(32));
}