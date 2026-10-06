import { describe, expect, it } from "vitest";
import {
  CSRF_HEADER,
  corsHeaders,
  checkNonGetRequest,
  isOriginAllowed,
  preflightHeaders,
} from "../src/csrf.js";
import { deriveCsrfToken, generateCsrfKey } from "../src/session.js";

const ALLOWED = new Set(["https://app.example.com", "https://www.example.com"]);
const FOREIGN = "https://evil.test";
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

describe("isOriginAllowed", () => {
  it("accepts an allowlisted origin", () => {
    expect(isOriginAllowed("https://app.example.com", ALLOWED)).toBe(true);
  });

  it("rejects a foreign origin", () => {
    expect(isOriginAllowed(FOREIGN, ALLOWED)).toBe(false);
  });

  it("does not prefix-match, so a lookalike host is rejected", () => {
    // The reason exact matching is required rather than "startsWith".
    for (const hostile of [
      "https://app.example.com.evil.test",
      "https://evil.test/https://app.example.com",
      "https://app.example.co",
      "http://app.example.com",
      "https://APP.example.com",
    ]) {
      expect(isOriginAllowed(hostile, ALLOWED)).toBe(false);
    }
  });

  it("accepts a request with no Origin header", () => {
    // Not a browser cross-origin request: curl, the health check and the
    // orchestrator's own calls all look like this. CORS is not the access
    // control, so this is not a hole — the CSRF token is still required.
    expect(isOriginAllowed(undefined, ALLOWED)).toBe(true);
    expect(isOriginAllowed("", ALLOWED)).toBe(true);
  });

  it("rejects the literal string 'null' when it is not configured", () => {
    expect(isOriginAllowed("null", ALLOWED)).toBe(false);
  });
});

describe("corsHeaders", () => {
  // T-C1 / T-F1: ACAO must be ABSENT for a foreign origin — not empty, not null.
  it("omits ACAO entirely for a foreign origin", () => {
    const headers = corsHeaders(FOREIGN, ALLOWED);
    expect(headers["access-control-allow-origin"]).toBeUndefined();
    expect(headers["access-control-allow-credentials"]).toBeUndefined();
    expect(Object.keys(headers)).toEqual(["vary"]);
  });

  it("emits ACAO and ACAC for an allowlisted origin", () => {
    const headers = corsHeaders("https://app.example.com", ALLOWED);
    expect(headers["access-control-allow-origin"]).toBe("https://app.example.com");
    expect(headers["access-control-allow-credentials"]).toBe("true");
  });

  it("emits ACAC only alongside a non-wildcard ACAO", () => {
    // A wildcard ACAO with ACAC is rejected by browsers anyway, and emitting ACAC
    // without one is the shape of a footgun.
    for (const origin of [FOREIGN, undefined, ""]) {
      const headers = corsHeaders(origin, ALLOWED);
      if (headers["access-control-allow-credentials"] !== undefined) {
        expect(headers["access-control-allow-origin"]).toBeDefined();
        expect(headers["access-control-allow-origin"]).not.toBe("*");
      }
    }
  });

  it("never reflects an arbitrary Origin back", () => {
    // The specific failure mac flagged: reflection would allowlist every origin,
    // making the CSRF header layer decorative.
    const headers = corsHeaders(FOREIGN, ALLOWED);
    expect(headers["access-control-allow-origin"]).not.toBe(FOREIGN);
    expect(corsHeaders("https://attacker.test", ALLOWED)["access-control-allow-origin"]).toBeUndefined();
  });

  it("always sets Vary: Origin, so a cache cannot cross the streams", () => {
    for (const origin of ["https://app.example.com", FOREIGN, undefined]) {
      expect(corsHeaders(origin, ALLOWED)["vary"]).toBe("Origin");
    }
  });

  it("includes the requested headers on a preflight", () => {
    const headers = preflightHeaders("https://app.example.com", ALLOWED, [
      CSRF_HEADER,
      "content-type",
    ]);
    // ", " not "," — RFC 9110 allows optional whitespace around list separators,
    // and browsers accept both.
    expect(headers["access-control-allow-headers"]).toBe(`${CSRF_HEADER}, content-type`);
    expect(headers["access-control-max-age"]).toBe("600");
  });

  it("omits everything but Vary on a foreign preflight", () => {
    expect(preflightHeaders(FOREIGN, ALLOWED, [CSRF_HEADER])).toEqual({ vary: "Origin" });
  });
});

describe("checkNonGetRequest", () => {
  const key = generateCsrfKey();
  const token = deriveCsrfToken(key, GUID);

  const ok = {
    origin: "https://app.example.com",
    presentedToken: token,
    allowed: ALLOWED,
    csrfKey: key,
    sessionId: GUID,
  };

  it("accepts an allowlisted origin with a valid token", () => {
    const result = checkNonGetRequest(ok);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.allowedOrigin).toBe("https://app.example.com");
  });

  // T-C2: a valid cookie from a foreign origin must be refused, and it must be
  // refused before the token is even consulted.
  it("rejects a foreign origin with a valid token", () => {
    const result = checkNonGetRequest({ ...ok, origin: FOREIGN });
    expect(result).toEqual({ ok: false, failure: "origin-not-allowed" });
  });

  it("rejects a foreign origin even when the token is valid and the session is real", () => {
    // This is the CSRF scenario: the victim's cookie rides along automatically.
    const result = checkNonGetRequest({ ...ok, origin: FOREIGN, presentedToken: token });
    expect(result.ok).toBe(false);
  });

  // T-C3
  it("rejects a missing token", () => {
    expect(checkNonGetRequest({ ...ok, presentedToken: undefined })).toEqual({
      ok: false,
      failure: "csrf-missing",
    });
    expect(checkNonGetRequest({ ...ok, presentedToken: "" })).toEqual({
      ok: false,
      failure: "csrf-missing",
    });
  });

  // T-C4
  it("rejects a mismatched token", () => {
    expect(checkNonGetRequest({ ...ok, presentedToken: "A".repeat(43) })).toEqual({
      ok: false,
      failure: "csrf-mismatch",
    });
  });

  it("rejects a token derived for a different session", () => {
    const other = deriveCsrfToken(key, "00000000-0000-0000-0000-000000000000");
    expect(checkNonGetRequest({ ...ok, presentedToken: other })).toEqual({
      ok: false,
      failure: "csrf-mismatch",
    });
  });

  it("checks the origin before the token, so the expensive HMAC stays off rejected requests", () => {
    let called = false;
    const result = checkNonGetRequest({
      ...ok,
      origin: FOREIGN,
      tokensMatch: () => {
        called = true;
        return true;
      },
    });
    expect(result.ok).toBe(false);
    expect(called).toBe(false);
  });

  it("requires the token even when there is no Origin header", () => {
    // Otherwise a non-browser client with a cookie could skip the check.
    expect(checkNonGetRequest({ ...ok, origin: undefined, presentedToken: undefined })).toEqual({
      ok: false,
      failure: "csrf-missing",
    });
    expect(checkNonGetRequest({ ...ok, origin: undefined }).ok).toBe(true);
  });

  it("reports allowedOrigin as null when there was no Origin header", () => {
    const result = checkNonGetRequest({ ...ok, origin: undefined });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.allowedOrigin).toBeNull();
  });

  it("does not accept a token that merely shares a prefix", () => {
    expect(checkNonGetRequest({ ...ok, presentedToken: token.slice(0, 40) })).toEqual({
      ok: false,
      failure: "csrf-mismatch",
    });
  });
});