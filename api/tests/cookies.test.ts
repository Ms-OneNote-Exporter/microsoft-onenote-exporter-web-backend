import { describe, expect, it } from "vitest";
import { CSRF_COOKIE, SESSION_COOKIE } from "../src/csrf.js";
import {
  csrfCookie,
  expiredCsrfCookie,
  expiredSessionCookie,
  getCookie,
  parseCookies,
  serialiseCookie,
  sessionCookie,
} from "../src/cookies.js";

/**
 * PLAN-v3 §3.3 layer 4 and T-C5. The attribute set is asserted individually
 * because each one is load-bearing for a different reason, and a test that only
 * checked "the cookie is HttpOnly" would miss three of the four.
 */

const TWELVE_HOURS = 43_200;

describe("sessionCookie", () => {
  const spec = sessionCookie("secret-value", TWELVE_HOURS);

  // T-C5: SameSite=None, Secure, HttpOnly, Path=/, and no Domain.
  it("sets SameSite=None because the two origins are cross-site", () => {
    // Lax would break the app entirely, and moving to None without noticing the
    // CSRF implication is the failure §3.3 exists to prevent.
    expect(spec.sameSite).toBe("None");
  });

  it("is Secure, HttpOnly and Path=/", () => {
    expect(spec.secure).toBe(true);
    expect(spec.httpOnly).toBe(true);
    expect(spec.path).toBe("/");
  });

  it("uses the __Host- prefix, which forbids a Domain attribute", () => {
    // The prefix is what makes a sibling subdomain unable to shadow the cookie.
    expect(spec.name).toBe("__Host-msout");
    expect(spec.name.startsWith("__Host-")).toBe(true);
  });

  it("can never emit a Domain attribute", () => {
    // Structural: there is no field to populate, so a future edit cannot add one.
    for (const key of Object.keys(spec)) {
      expect(key.toLowerCase()).not.toContain("domain");
    }
    expect(serialiseCookie(spec)).not.toMatch(/domain/i);
  });

  it("expires with the session's own TTL", () => {
    // The browser dropping the cookie and the server expiring the row are the
    // same deadline, so a stale tab cannot present a cookie the server honours
    // past it.
    expect(spec.maxAge).toBe(TWELVE_HOURS);
  });

  it("never leaves the secret readable by JavaScript", () => {
    expect(spec.httpOnly).toBe(true);
  });
});

describe("csrfCookie", () => {
  const spec = csrfCookie("token-value", TWELVE_HOURS);

  it("is readable by JavaScript, which is the whole point of it", () => {
    // The browser has to read it to echo it in a header.
    expect(spec.httpOnly).toBe(false);
  });

  it("is still Secure, SameSite=None and Path=/", () => {
    expect(spec.secure).toBe(true);
    expect(spec.sameSite).toBe("None");
    expect(spec.path).toBe("/");
  });

  it("does not use the __Host- prefix, because it is readable and has no Domain either", () => {
    // Both are fine; what matters is that it carries no Domain, which the specs
    // structurally cannot.
    expect(spec.name).toBe(CSRF_COOKIE);
    expect(serialiseCookie(spec)).not.toMatch(/domain/i);
  });
});

describe("expiry", () => {
  // PLAN-v3 T7: erase must expire the cookie as well as invalidating the row.
  it("expires the session cookie with Max-Age=0 and a past Expires", () => {
    const spec = expiredSessionCookie();
    expect(spec.maxAge).toBe(0);
    expect(spec.expires).toBe(0);

    // Both are emitted because a browser that ignores one honours the other.
    const header = serialiseCookie(spec);
    expect(header).toContain("Max-Age=0");
    expect(header).toMatch(/Expires=Thu, 01 Jan 1970/);
  });

  it("expires the csrf cookie too", () => {
    const header = serialiseCookie(expiredCsrfCookie());
    expect(header).toContain("Max-Age=0");
    expect(header).toContain(`${CSRF_COOKIE}=`);
  });

  it("keeps the expired cookies' attributes, so the browser matches and replaces them", () => {
    // An expired cookie that drops SameSite or Path may not match the original,
    // leaving it in place.
    const spec = expiredSessionCookie();
    expect(spec.httpOnly).toBe(true);
    expect(spec.secure).toBe(true);
    expect(spec.sameSite).toBe("None");
    expect(spec.path).toBe("/");
  });

  it("takes no session state, so it works when the row is already gone", () => {
    // T-E1: "in both orders, including when the row is already gone".
    expect(() => expiredSessionCookie()).not.toThrow();
    expect(expiredSessionCookie().value).toBe("");
  });
});

describe("serialiseCookie", () => {
  it("renders the attributes in a stable order", () => {
    expect(serialiseCookie(sessionCookie("v", 60))).toBe(
      "__Host-msout=v; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=60",
    );
  });

  it("omits the __Host- prefix as an attribute, because it is part of the name", () => {
    const header = serialiseCookie(sessionCookie("v", 60));
    expect(header.startsWith(`${SESSION_COOKIE}=`)).toBe(true);
    expect(header).not.toMatch(/__Host-=/);
  });

  it("emits Max-Age only when set", () => {
    const noMaxAge: ReturnType<typeof sessionCookie> = { ...sessionCookie("v", 60), maxAge: null };
    expect(serialiseCookie(noMaxAge)).not.toContain("Max-Age");
  });
});

describe("parseCookies", () => {
  it("parses a single pair", () => {
    expect(parseCookies("a=1").get("a")).toBe("1");
  });

  it("parses several pairs with whitespace", () => {
    const map = parseCookies("a=1; b=2;c=3");
    expect(map.get("a")).toBe("1");
    expect(map.get("b")).toBe("2");
    expect(map.get("c")).toBe("3");
  });

  it("preserves base64url values, including - and _", () => {
    const value = "aB3-_aB3-_aB3-_aB3-_aB3-_aB3-_aB3-_aB3";
    expect(parseCookies(`__Host-msout=${value}`).get("__Host-msout")).toBe(value);
  });

  it("keeps an = inside a value", () => {
    // Slicing on the first = rather than splitting on all of them.
    expect(parseCookies("t=abc=def").get("t")).toBe("abc=def");
  });

  it("unquotes a quoted value", () => {
    expect(parseCookies('a="quoted"').get("a")).toBe("quoted");
  });

  it("returns an empty map for an absent or empty header", () => {
    expect(parseCookies(undefined).size).toBe(0);
    expect(parseCookies("").size).toBe(0);
  });

  it("skips a malformed pair rather than throwing", () => {
    // One bad cookie must not fail a request that also carries a valid session.
    const map = parseCookies("novalue; =empty; a=1; ; b");
    expect(map.get("a")).toBe("1");
    expect(map.get("")).toBeUndefined();
    expect(map.get("novalue")).toBeUndefined();
  });

  it("falls back to the raw value on a bad percent escape", () => {
    expect(parseCookies("a=%zz").get("a")).toBe("%zz");
  });

  it("percent-decodes a valid escape", () => {
    expect(parseCookies("a=hello%20world").get("a")).toBe("hello world");
  });
});

describe("getCookie", () => {
  it("finds the session cookie", () => {
    const header = `${CSRF_COOKIE}=tok; ${SESSION_COOKIE}=sec`;
    expect(getCookie(header, SESSION_COOKIE)).toBe("sec");
    expect(getCookie(header, CSRF_COOKIE)).toBe("tok");
  });

  it("returns undefined for a missing cookie", () => {
    expect(getCookie("a=1", SESSION_COOKIE)).toBeUndefined();
    expect(getCookie(undefined, SESSION_COOKIE)).toBeUndefined();
  });
});