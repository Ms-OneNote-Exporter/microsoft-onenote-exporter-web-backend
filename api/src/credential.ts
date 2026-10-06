/**
 * The credential path.
 *
 * PLAN-v3 §3.1 and PLAN-v2 §4.2. This is the hot path of the whole service and
 * the only place a Microsoft password exists outside the browser and the runner.
 *
 * The design is a raw-stream forward, and every clause below exists because
 * parsing a credential is the thing we are refusing to do:
 *
 *   - no JSON body parser is reachable from this route, from anywhere in the
 *     stack. This is why the api registers no global content-type parser at all
 *     and each route parses its own body; see server.ts.
 *   - the body is a byte count plus a stream, never a buffer. It is not
 *     accumulated into a string, not logged, and not passed to JSON.parse.
 *   - Content-Length is checked against a cap before a single byte is forwarded,
 *     so an oversized body is refused without the runner ever seeing a prefix of
 *     it.
 *   - the stream is destroyed the moment the cap is exceeded, which covers a
 *     caller who omits Content-Length and lies by omission.
 *
 * Cross-origin, this route additionally requires the preflight that
 * PLAN-v3 §3.3 layer 1 forces: `X-CSRF-Token` is not CORS-safelisted, so a
 * non-allowlisted origin cannot cause a browser to transmit this body at all.
 */

import { Readable } from "node:stream";

/**
 * maxCredentialBytes caps the credential body at roughly 4 KB.
 *
 * A Microsoft account password is well under 200 bytes; the cap exists to make
 * "a caller sent something enormous" a cheap refusal rather than an allocation
 * and a forwarded 4 MB of somebody else's data. PLAN-v2 §4.2 says "~4 KB".
 */
export const MAX_CREDENTIAL_BYTES = 4096;

/** Why a credential request was refused before anything was forwarded. */
export type CredentialRefusal =
  | "no-content-length"
  | "content-length-too-large"
  | "stream-exceeded-cap";

/** The result of validating a credential request's framing. */
export type CredentialFraming =
  | { readonly ok: true; readonly declaredLength: number }
  | { readonly ok: false; readonly refusal: CredentialRefusal };

/**
 * checkFraming validates the request headers before any byte is forwarded.
 *
 * A missing Content-Length is refused rather than assumed. Accepting it would
 * mean the cap could only be enforced while streaming, which is strictly worse:
 * the runner may already have acted on the first bytes by the time the stream is
 * killed. Refusing up front means an oversized credential is never partially
 * delivered.
 *
 * The `> max` rather than `>= max` boundary: exactly 4096 bytes is allowed,
 * 4097 is not.
 */
export function checkFraming(contentLength: string | undefined): CredentialFraming {
  // RFC 9110 defines Content-Length as 1*DIGIT — decimal digits and nothing else.
  // Checking the shape before parsing rather than after means exponent notation
  // ("1e3"), hex ("0x10") and whitespace-padded values are all rejected rather
  // than silently coerced to a number by Number(). A proxy and this process must
  // agree on the length, and the only way to guarantee that is to accept exactly
  // what the grammar allows.
  if (contentLength === undefined || !/^[0-9]+$/.test(contentLength)) {
    return { ok: false, refusal: "no-content-length" };
  }
  const declared = Number(contentLength);
  if (!Number.isSafeInteger(declared)) {
    // A value beyond 2^53 cannot be a real body length, and arithmetic on it
    // would be inexact.
    return { ok: false, refusal: "no-content-length" };
  }
  if (declared > MAX_CREDENTIAL_BYTES) {
    return { ok: false, refusal: "content-length-too-large" };
  }
  return { ok: true, declaredLength: declared };
}

/**
 * capStream returns a Readable that yields at most `limit` bytes and then
 * errors.
 *
 * This is the backstop for a caller whose Content-Length understates the body —
 * chunked encoding makes that trivial, and it is the difference between a
 * generous cap and an unbounded forward. Destroying the source on overflow
 * matters as much as stopping the output: otherwise the caller's connection
 * stays open and the request handler never returns.
 *
 * The stream is never buffered, so a 4 KB credential occupies a 4 KB buffer and
 * a 4 MB one is cut off at 4 KB.
 */
export function capStream(
  source: Readable,
  limit: number = MAX_CREDENTIAL_BYTES,
): Readable {
  let seen = 0;

  return new Readable({
    read(this: Readable) {
      const chunk = source.read(64 * 1024) as Buffer | null;
      if (chunk === null) {
        this.push(null);
        return;
      }
      seen += chunk.length;
      if (seen > limit) {
        // Destroy the source as well as ending this stream. Leaving the
        // caller's connection open would hold the handler open indefinitely.
        source.destroy();
        this.destroy(new Error("credential body exceeded the cap"));
        return;
      }
      this.push(chunk);
    },
  });
}

/**
 * countOnly is a sink that counts bytes without retaining them.
 *
 * Used where a caller must be told how much arrived without the bytes becoming
 * a value anywhere in this process. It is here because the temptation to write
 * `await streamToBuffer(req)` in this file is exactly the failure this module
 * documents.
 */
export function countOnly(): { write: (chunk: Buffer) => void; bytes: () => number } {
  let total = 0;
  return {
    write(chunk: Buffer) {
      total += chunk.length;
    },
    bytes: () => total,
  };
}

/**
 * contentTypeIsAcceptable reports whether a credential request's Content-Type is
 * acceptable.
 *
 * It deliberately does not pin a type. PLAN-v3 §3.3 layer 3 pins
 * `application/json` on every mutating route *except* this one, on the reasoning
 * that pinning a content type on a body we refuse to parse is theatre: we never
 * look at it. Accepting `text/plain`, `application/x-www-form-urlencoded` and
 * `application/json` alike is the honest behaviour, and it is why a JSON-encoded
 * password arriving here would be forwarded byte-for-byte — a caller bug, not a
 * server one.
 *
 * The one thing worth rejecting is a multipart body, because a multipart parser
 * is exactly the kind of thing that would want to be enabled globally.
 */
export function contentTypeIsAcceptable(contentType: string | undefined): boolean {
  if (contentType === undefined || contentType === "") return true;
  const type = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return !type.startsWith("multipart/");
}

/** Redacted headers for the audit log. */
export interface CredentialAuditHeaders {
  readonly contentLength: string | undefined;
  readonly contentType: string | undefined;
  readonly origin: string | undefined;
}

/**
 * auditFields returns the only header values that may be logged from this route.
 *
 * PLAN-v2 §4.2: redacted headers, `Authorization` never logged. Only cookies
 * reach this route, and a cookie value is a session secret — so `cookie` is
 * absent here too. Content-Length and Content-Type describe the request's shape
 * without describing its content.
 */
export function auditFields(headers: CredentialAuditHeaders): Record<string, unknown> {
  return {
    contentLength: headers.contentLength ?? null,
    contentType: headers.contentType ?? null,
    origin: headers.origin ?? null,
    // Named explicitly so a reader can see the omission was deliberate.
    credentialPresent: true,
    credentialLogged: false,
  };
}