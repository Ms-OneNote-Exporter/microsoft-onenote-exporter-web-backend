import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig, validateInternalOrigin, validateOrigins, validateSecret } from "../src/config.js";

/** A minimal valid environment, so each test states only what it varies. */
function baseEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    ALLOWED_ORIGINS: "https://app.example.com",
    PUBLIC_ORIGIN: "https://one-backend.example.com",
    CSRF_KEY: "A".repeat(43),
    ORCHESTRATOR_URL: "http://orchestrator:9100",
    ORCHESTRATOR_HMAC_SECRET: "B".repeat(43),
    // The token the api presents to a runner. It is a bearer value, not a
    // 256-bit key, so it is a fixed string rather than a repeat of 43 — and
    // deliberately not the same shape as the CSRF key, which is what
    // `validateRunnerToken` asserts.
    RUNNER_TOKEN: "runner-token-for-tests",
    ...overrides,
  };
}

describe("validateOrigins", () => {
  it("accepts exact https origins", () => {
    const out = validateOrigins("https://app.example.com,https://www.example.com");
    expect([...out].sort()).toEqual(["https://app.example.com", "https://www.example.com"]);
  });

  it("rejects an empty value rather than defaulting to permissive", () => {
    // T-C6. An api that starts with no allowlist and an implicit "*" is an open
    // service, which is the failure this whole function exists to prevent.
    expect(() => validateOrigins(undefined)).toThrow(ConfigError);
    expect(() => validateOrigins("")).toThrow(/at least one/);
    expect(() => validateOrigins("  ,  ")).toThrow(/at least one/);
  });

  it("rejects a wildcard", () => {
    expect(() => validateOrigins("*")).toThrow(/wildcard/);
    expect(() => validateOrigins("https://app.example.com,*")).toThrow(/wildcard/);
  });

  it('rejects "null", which is what a sandboxed iframe sends', () => {
    expect(() => validateOrigins("null")).toThrow(/sandboxed iframe/);
  });

  it("rejects http for a real host", () => {
    // A credential over http to a real host crosses a wire in clear, which is the
    // entire reason the rule exists.
    for (const hostile of [
      "http://app.example.com",
      "http://192.168.1.10:5173",
      "http://10.0.0.5",
      "http://172.16.0.1",
      "http://evil.test",
    ]) {
      expect(() => validateOrigins(hostile)).toThrow(/must be https/);
    }
  });

  // The narrow exception, so a development frontend can be named in the
  // allowlist without the mock server having to bypass validation entirely.
  it("allows http on loopback only", () => {
    for (const dev of [
      "http://localhost:5173",
      "http://127.0.0.1:5173",
      "http://127.0.0.1",
      "http://[::1]:5173",
    ]) {
      expect(() => validateOrigins(dev)).not.toThrow();
      expect(validateOrigins(dev).has(new URL(dev).origin)).toBe(true);
    }
  });

  it("does not extend the loopback exception to private ranges", () => {
    // 127/8 is loopback by definition. 10/8 and 192.168/16 are reachable over a
    // real network, so they stay https-only.
    expect(() => validateOrigins("http://192.168.1.10")).toThrow(/must be https/);
    expect(() => validateOrigins("http://10.1.2.3")).toThrow(/must be https/);
    // And a hostname that merely looks local is not local.
    expect(() => validateOrigins("http://localhost.evil.test")).toThrow(/must be https/);
  });

  it("rejects a trailing slash", () => {
    expect(() => validateOrigins("https://app.example.com/")).toThrow(/trailing a slash|must not end with a slash/);
  });

  it("rejects an entry with a path, query or fragment", () => {
    expect(() => validateOrigins("https://app.example.com/app")).toThrow(/no path/);
    expect(() => validateOrigins("https://app.example.com?x=1")).toThrow(/no path/);
    expect(() => validateOrigins("https://app.example.com#frag")).toThrow(/no path/);
  });

  it("rejects a non-URL", () => {
    expect(() => validateOrigins("app.example.com")).toThrow(ConfigError);
  });

  it("normalises so a configured value and an incoming header compare equal", () => {
    // URL drops the default port; a browser sends "https://x" for "https://x:443".
    const out = validateOrigins("https://app.example.com:443");
    expect(out.has("https://app.example.com")).toBe(true);
    expect(out.has("https://app.example.com:443")).toBe(false);
  });

  it("keeps a non-default port", () => {
    const out = validateOrigins("https://app.example.com:8443");
    expect(out.has("https://app.example.com:8443")).toBe(true);
  });

  it("is not fooled by a prefix or suffix of an allowlisted origin", () => {
    // The reason exact matching is required: a prefix rule turns the allowlist
    // into "any subdomain of the allowed host", which is not what was configured.
    const out = validateOrigins("https://app.example.com");
    for (const hostile of [
      "https://app.example.com.evil.test",
      "https://evil.test/app.example.com",
      "https://app.example.co",
      "http://app.example.com",
    ]) {
      expect(out.has(hostile)).toBe(false);
    }
  });

  it("keeps a wildcard subdomain entry out", () => {
    expect(() => validateOrigins("https://*.example.com")).toThrow(ConfigError);
  });
});

describe("validateSecret", () => {
  it("accepts exactly 43 base64url characters", () => {
    expect(validateSecret("A".repeat(43))).toHaveLength(43);
    expect(validateSecret("aB3-_".repeat(8) + "abc")).toHaveLength(43);
  });

  it("rejects the wrong length mechanically", () => {
    // T9 / PLAN-v3 §4: a compromised Component A could generate a weak secret,
    // so the API validates length rather than trusting the client.
    expect(() => validateSecret("")).toThrow(/required/);
    expect(() => validateSecret(undefined)).toThrow(/required/);
    expect(() => validateSecret("A".repeat(42))).toThrow(/exactly 43/);
    expect(() => validateSecret("A".repeat(44))).toThrow(/exactly 43/);
    expect(() => validateSecret("short")).toThrow(/exactly 43/);
  });

  it("rejects non-base64url characters, including padding", () => {
    expect(() => validateSecret(`${"A".repeat(40)}+/=`)).toThrow(/exactly 43/);
    expect(() => validateSecret(`${"A".repeat(42)}=`)).toThrow(/exactly 43/);
  });

  it("names the variable in the error so the operator can find the line", () => {
    try {
      validateSecret("nope", "ORCHESTRATOR_HMAC_SECRET");
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as ConfigError).variable).toBe("ORCHESTRATOR_HMAC_SECRET");
      expect((error as ConfigError).message).toContain("ORCHESTRATOR_HMAC_SECRET");
    }
  });
});

describe("validateInternalOrigin", () => {
  it("accepts an internal name over http", () => {
    expect(validateInternalOrigin("http://orchestrator:9100")).toBe("http://orchestrator:9100");
  });

  it("refuses http to a public host, because the HMAC secret would cross in clear", () => {
    expect(() => validateInternalOrigin("http://orch.example.com")).toThrow(/HMAC secret/);
  });

  it("accepts https anywhere", () => {
    expect(validateInternalOrigin("https://orch.example.com")).toBe("https://orch.example.com");
  });

  it("rejects a path and a missing value", () => {
    expect(() => validateInternalOrigin("http://orchestrator:9100/api")).toThrow(/no path/);
    expect(() => validateInternalOrigin("")).toThrow(/required/);
  });
});

describe("loadConfig", () => {
  it("loads a valid environment", () => {
    const cfg = loadConfig(baseEnv());
    expect(cfg.allowedOrigins.has("https://app.example.com")).toBe(true);
    expect(cfg.sessionTtlHours).toBe(12);
    expect(cfg.minFreeDiskMb).toBe(2048);
    expect(cfg.orchestratorReplayWindowSeconds).toBe(60);
    expect(cfg.logLevel).toBe("info");
    // The download origin is a first-class config value, not derived from a
    // request header — see validatePublicOrigin.
    expect(cfg.publicOrigin).toBe("https://one-backend.example.com");
  });

  it("honours explicit values", () => {
    const cfg = loadConfig(
      baseEnv({ SESSION_TTL_HOURS: "6", MIN_FREE_DISK_MB: "512", LOG_LEVEL: "debug" }),
    );
    expect(cfg.sessionTtlHours).toBe(6);
    expect(cfg.minFreeDiskMb).toBe(512);
    expect(cfg.logLevel).toBe("debug");
  });

  it("rejects a bad integer rather than coercing it", () => {
    expect(() => loadConfig(baseEnv({ SESSION_TTL_HOURS: "0" }))).toThrow(ConfigError);
    expect(() => loadConfig(baseEnv({ SESSION_TTL_HOURS: "-1" }))).toThrow(/positive/);
    expect(() => loadConfig(baseEnv({ MIN_FREE_DISK_MB: "lots" }))).toThrow(/positive/);
  });

  it("rejects an unknown log level", () => {
    expect(() => loadConfig(baseEnv({ LOG_LEVEL: "verbose" }))).toThrow(/LOG_LEVEL/);
  });
});