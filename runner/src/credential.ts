/**
 * The credential, from the request bytes to the bytes Microsoft sees.
 *
 * ## The property this module exists to hold
 *
 * **The bytes arrive from the api and reach the login form unchanged.** No
 * trimming, no newline handling, no JSON round trip, no encoding, no length cap
 * that silently shortens. A password containing quotes, backslashes, leading and
 * trailing spaces, a tab, or a `&` must arrive as those exact bytes, because a
 * user who typed them cannot retype them differently and does not know we changed
 * anything.
 *
 * ## How that has been broken before, in this project, twice, from opposite ends
 *
 * 1. The frontend sent `JSON.stringify(password)`, so `hunter2` became
 *    `"hunter2"` — quote characters included — and the apostrophe in a password
 *    turned a valid one invalid.
 * 2. The runner's own predecessor passed the password as `--password <value>` on
 *    a command line, where it is visible in `/proc/<pid>/cmdline` to every
 *    process in the container and lands in the child's own error messages.
 *
 * Neither showed up in a unit test that asserted a value was *set*. The tests
 * that would have caught them assert on the bytes at the far side of the hop, and
 * that is what `tests/credential.test.ts` does: it types a hostile password into
 * a real page and reads the field's value back.
 *
 * ## What is never done here
 *
 * - The credential is not logged, not at any level, not in an error message.
 * - It is not put in a query string, a header this module controls, or argv.
 * - It is not accumulated into a string beyond the single Buffer the body
 *   necessarily is. `Buffer` is the one representation that cannot re-encode, and
 *   the api's guarantee is that the bytes are never turned into anything else.
 */

/** A GUID is the only session identifier the runner accepts from a URL. */
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * True for a session guid, and only for one.
 *
 * Checked because this string reaches `path.join` to build a directory name. A
 * guid that is not one could contain `../`, and the runner would then write
 * outside its own data root — which is the one filesystem write an attacker
 * reaching this HTTP API controls.
 */
export function isValidGuid(value: unknown): value is string {
  return typeof value === "string" && GUID_RE.test(value);
}

/** Why a credential was refused, for an HTTP body. Never carries the value. */
export type CredentialRejection =
  | "no-body"
  | "too-large"
  | "empty-account"
  | "bad-guid";

export interface CredentialAcceptance {
  readonly ok: boolean;
  readonly reason?: CredentialRejection;
}

/**
 * The largest credential body accepted, in bytes.
 *
 * A Microsoft password is bounded well below this. The cap exists so a
 * misconfigured caller cannot stream an unbounded body into this process, which
 * is the only one holding it — and it is enforced by *refusing*, never by
 * truncating. A truncated password is a wrong password, and the user would be
 * told to check what they typed.
 */
export const CREDENTIAL_LIMIT_BYTES = 4096;

/**
 * Reads a credential body off the request as bytes, and nothing else.
 *
 * `parseAs: "buffer"` in the content-type parser is load-bearing. The obvious
 * alternative, `parseAs: "string"`, hands over a JS string, and then:
 *
 * - a lone surrogate in the body would already have been mangled by the UTF-8
 *   decode that produced it, irreversibly;
 * - every later `String(...)`, `trim()`, `JSON.parse` or template interpolation
 *   of that value is another chance to change bytes, and the tests would still
 *   pass because they would be asserting on the already-corrupted value.
 *
 * So the body crosses this hop as a `Buffer`, is handed to `login()` as a
 * `Buffer`, and the only thing between the api's write and Microsoft is the
 * string decode inside the login form itself — which is the browser's, and is
 * where a password belongs.
 */
export function readCredentialBytes(
  body: unknown,
  limit: number = CREDENTIAL_LIMIT_BYTES,
): { ok: true; bytes: Buffer } | { ok: false; reason: CredentialRejection } {
  if (body === undefined || body === null) {
    return { ok: false, reason: "no-body" };
  }
  if (!Buffer.isBuffer(body)) {
    // Reached only if something replaced the content-type parser. Treat a
    // non-buffer as a refusal rather than coercing it: coercing is how bytes
    // become a string, which is the thing this module exists to prevent.
    return { ok: false, reason: "no-body" };
  }
  if (body.length > limit) {
    return { ok: false, reason: "too-large" };
  }
  if (body.length === 0) {
    return { ok: false, reason: "empty-account" };
  }
  return { ok: true, bytes: body };
}

/**
 * The account, from the `X-Microsoft-Account` header.
 *
 * A header rather than part of the body, which is the whole point of the design:
 * the body stays byte-identical from the browser to the login form. Putting both
 * in one body would need a delimiter, and a delimiter is another place for a
 * truncation bug — which this pair has shipped twice from opposite ends.
 *
 * Not a secret, but an identifier, so it is never logged here either.
 */
export function readAccount(header: unknown): string | null {
  if (typeof header !== "string") return null;
  const trimmed = header.trim();
  if (trimmed === "") return null;
  // A newline in this value would let a caller inject extra log lines or a header
  // into something downstream. Microsoft addresses are not multiline.
  if (/[\r\n]/.test(trimmed)) return null;
  return trimmed;
}

/**
 * The exact password string handed to `login()`.
 *
 * The one and only decode, and it is a decode of UTF-8 bytes into a string
 * because that is what the login form's `fill()` takes. The password is not
 * trimmed, not normalised, and not length-checked beyond the cap above.
 *
 * Exported so the test can assert the mapping directly, and so the single place
 * that could mangle bytes is a named function rather than an expression spread
 * across the call site.
 */
export function passwordFrom(bytes: Buffer): string {
  return bytes.toString("utf8");
}
