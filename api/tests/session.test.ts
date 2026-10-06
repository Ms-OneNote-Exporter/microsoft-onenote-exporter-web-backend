import { describe, expect, it } from "vitest";
import {
  base64url,
  csrfTokensMatch,
  deriveCsrfToken,
  generateArtifactId,
  generateCsrfKey,
  hashSecret,
  isValidGuid,
  isValidSecret,
  secretsMatch,
} from "../src/session.js";

const SECRET = "A".repeat(43);
const OTHER_SECRET = "B".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

describe("isValidSecret", () => {
  it("accepts exactly 43 base64url characters", () => {
    expect(isValidSecret("A".repeat(43))).toBe(true);
    expect(isValidSecret("aB3-_".repeat(8) + "abc")).toBe(true);
  });

  it("rejects the wrong length, weakly or wrongly", () => {
    for (const bad of ["", "A".repeat(42), "A".repeat(44), "short", "A".repeat(100)]) {
      expect(isValidSecret(bad)).toBe(false);
    }
  });

  it("rejects base64 standard-alphabet and padding characters", () => {
    expect(isValidSecret(`${"A".repeat(40)}+/=`)).toBe(false);
    expect(isValidSecret(`${"A".repeat(42)}=`)).toBe(false);
  });

  it("rejects non-strings without throwing", () => {
    for (const bad of [undefined, null, 42, {}, [], true]) {
      expect(isValidSecret(bad)).toBe(false);
    }
  });
});

describe("isValidGuid", () => {
  it("accepts a lowercase uuid", () => {
    expect(isValidGuid(GUID)).toBe(true);
  });

  it("is case-sensitive, so one session has one spelling", () => {
    expect(isValidGuid(GUID.toUpperCase())).toBe(false);
  });

  it("rejects anything that is not a uuid", () => {
    for (const bad of [
      "",
      "not-a-guid",
      "3f2504e04f8911d39a0c0305e82c3301",
      `${GUID}x`,
      "../../etc",
      `${GUID}/../../x`,
      `${GUID}\n`,
    ]) {
      expect(isValidGuid(bad)).toBe(false);
    }
  });
});

describe("hashSecret", () => {
  it("is deterministic", () => {
    expect(hashSecret(SECRET)).toBe(hashSecret(SECRET));
  });

  it("does not contain the secret", () => {
    expect(hashSecret(SECRET)).not.toContain(SECRET);
  });

  it("differs for a different secret", () => {
    expect(hashSecret(SECRET)).not.toBe(hashSecret(OTHER_SECRET));
  });

  it("produces 43 base64url characters, like the secret it replaces", () => {
    expect(hashSecret(SECRET)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe("secretsMatch", () => {
  it("accepts the correct secret", () => {
    expect(secretsMatch(SECRET, hashSecret(SECRET))).toBe(true);
  });

  it("rejects a wrong secret", () => {
    expect(secretsMatch(OTHER_SECRET, hashSecret(SECRET))).toBe(false);
  });

  it("rejects rather than throwing on an empty stored hash", () => {
    // A row whose secret_hash is null is a session created but never
    // authenticated. It must not authenticate against an empty string.
    expect(secretsMatch(SECRET, "")).toBe(false);
    expect(secretsMatch("", "")).toBe(false);
  });

  it("rejects a truncated or padded stored hash", () => {
    const stored = hashSecret(SECRET);
    expect(secretsMatch(SECRET, stored.slice(0, 42))).toBe(false);
    expect(secretsMatch(SECRET, `${stored}=`)).toBe(false);
  });
});

describe("deriveCsrfToken", () => {
  it("is deterministic for a key and session id", () => {
    const key = generateCsrfKey();
    expect(deriveCsrfToken(key, GUID)).toBe(deriveCsrfToken(key, GUID));
  });

  it("differs per session, so one session's token is not another's", () => {
    const key = generateCsrfKey();
    expect(deriveCsrfToken(key, GUID)).not.toBe(deriveCsrfToken(key, OTHER_SECRET));
  });

  it("differs per key, so an erased session's token cannot validate", () => {
    expect(deriveCsrfToken(generateCsrfKey(), GUID)).not.toBe(
      deriveCsrfToken(generateCsrfKey(), GUID),
    );
  });

  it("is 43 base64url characters", () => {
    expect(deriveCsrfToken(generateCsrfKey(), GUID)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe("csrfTokensMatch", () => {
  it("accepts the derived token", () => {
    const key = generateCsrfKey();
    expect(csrfTokensMatch(deriveCsrfToken(key, GUID), key, GUID)).toBe(true);
  });

  it("rejects a mismatched token", () => {
    // T-C4.
    const key = generateCsrfKey();
    expect(csrfTokensMatch("A".repeat(43), key, GUID)).toBe(false);
  });

  it("rejects a token derived for a different session", () => {
    const key = generateCsrfKey();
    const token = deriveCsrfToken(key, OTHER_SECRET);
    expect(csrfTokensMatch(token, key, GUID)).toBe(false);
  });

  it("rejects a token derived with a different key", () => {
    const token = deriveCsrfToken(generateCsrfKey(), GUID);
    expect(csrfTokensMatch(token, generateCsrfKey(), GUID)).toBe(false);
  });

  it("rejects an empty or malformed token", () => {
    const key = generateCsrfKey();
    expect(csrfTokensMatch("", key, GUID)).toBe(false);
    expect(csrfTokensMatch("garbage", key, GUID)).toBe(false);
    expect(csrfTokensMatch(deriveCsrfToken(key, GUID) + "x", key, GUID)).toBe(false);
  });
});

describe("generateArtifactId", () => {
  it("is 43 base64url characters, the same width as the session secret", () => {
    const id = generateArtifactId();
    expect(id).toHaveLength(43);
    expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("encodes nothing about the session or the notebook", () => {
    // PLAN-v3 §5, invariant 8: no GUID and no notebook name in a download URL.
    const id = generateArtifactId();
    expect(id).not.toContain(GUID);
    expect(id).not.toContain("Personal");
    expect(id).not.toContain("/");
  });

  it("does not repeat", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => generateArtifactId()));
    expect(ids.size).toBe(1000);
  });
});

describe("generateCsrfKey", () => {
  it("is 43 base64url characters", () => {
    expect(generateCsrfKey()).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("does not repeat", () => {
    const keys = new Set(Array.from({ length: 1000 }, () => generateCsrfKey()));
    expect(keys.size).toBe(1000);
  });
});

describe("base64url", () => {
  it("produces no padding and no standard-alphabet characters", () => {
    for (let i = 0; i < 64; i++) {
      const out = base64url(new Uint8Array(i).fill(0xfb));
      expect(out).not.toMatch(/[+/=]/);
    }
  });

  it("encodes 32 bytes as 43 characters", () => {
    expect(base64url(new Uint8Array(32))).toHaveLength(43);
  });
});