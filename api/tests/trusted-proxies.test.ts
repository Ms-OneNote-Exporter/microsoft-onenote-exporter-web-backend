// Every caller on the internet shared one rate-limit bucket.
//
// ## What the user saw
//
// ```
// I systematically get error: "Too many attempts. Wait a moment."
// I tried from 2 differents ips
// ```
//
// Two IPs, one limit. The two facts are the bug, not a coincidence.
//
// ## What the api logged for every attempt
//
// ```
// {"method":"POST","url":"/api/session","remoteAddress":"172.24.0.4"}
//   → {"statusCode":429}
// ```
//
// `172.24.0.4` is **Caddy**. Every request, from every caller, on every network,
// resolved to Caddy's container address — so `sessionsPerWindow: { max: 3 }` was three
// sessions an hour for the entire internet.
//
// ## How, given that Caddy sets the header correctly
//
// `infra/Caddyfile` does the right thing, and says so:
//
//     # The client's address, so the rate limiter counts per user rather than
//     # per proxy hop. Trusted by the api only because it is set here and the
//     # api's port is on an internal network; PLAN-v3 §3.5.
//     header_up X-Forwarded-For {remote_host}
//
// That comment asserts a trust relationship that did not exist in code. The api's rule
// (PLAN-v3 §3.5) is not "the header is present, believe it" but "**the peer is a proxy
// we were told about**, and only then is the header evidence". And `knownProxies` had no
// way to be set from the environment at all — it defaulted to an empty set on every
// code path. So the header arrived and was refused, correctly, forever.
//
// The fail-closed default is right. What was missing is any way to say who the proxy
// is, which made a correct security property into a denial of service.
//
// ## What this file asserts
//
// That a request from a trusted proxy is counted against the **client's** address, that
// one from an untrusted peer is counted against the peer even when it sends the header,
// that a CIDR covers the addresses inside it, that a malformed list refuses to start,
// and that a session **restore** is not charged as a new session.

import { beforeEach, describe, expect, it } from "vitest";

import { Db } from "../src/db.js";
import { RateLimiter } from "../src/rate-limit.js";
import {
  NO_PROXIES,
  normalise,
  parseTrustedProxies,
  resolveClientAddress,
} from "../src/client-ip.js";
import { ConfigError } from "../src/config.js";

const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

/** Caddy's address and network on the live deployment. */
const CADDY = "172.24.0.4";
const CADDY_NET = "172.24.0.0/16";
const CADDY_NETWORK = "msout-control";

describe("a request through the proxy", () => {
  it("is counted against the client's address, not the proxy's", () => {
    const resolved = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "203.0.113.9",
      knownProxies: parseTrustedProxies(CADDY_NET),
    });

    // The whole bug. Before, `address` was `172.24.0.4` for every caller.
    expect(resolved.address).toBe("203.0.113.9");
    expect(resolved.source).toBe("rightmost-forwarded");
  });

  it("keeps two callers in two buckets", () => {
    const proxies = parseTrustedProxies(CADDY_NET);
    const a = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "203.0.113.9",
      knownProxies: proxies,
    });
    const b = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "198.51.100.4",
      knownProxies: proxies,
    });

    expect(a.address).not.toBe(b.address);
  });

  it("survives Caddy being recreated, because the trust is a network", () => {
    // The reason for CIDR support, stated as a test: a container's address changes
    // on every recreate, so an exact address would stop matching and silently
    // return to the shared bucket.
    const proxies = parseTrustedProxies(CADDY_NET);
    for (const address of ["172.24.0.2", "172.24.0.99", "172.24.7.7"]) {
      expect(
        resolveClientAddress({
          peerAddress: address,
          forwardedFor: "203.0.113.9",
          knownProxies: proxies,
        }).address,
      ).toBe("203.0.113.9");
    }
  });

  it("does not trust an address outside that network", () => {
    // The api is on two networks; only one has Caddy on it. Trusting the wrong subnet
    // looks configured and matches nothing.
    const resolved = resolveClientAddress({
      peerAddress: "172.18.0.7",
      forwardedFor: "203.0.113.9",
      knownProxies: parseTrustedProxies(CADDY_NET),
    });

    expect(resolved.address).toBe("172.18.0.7");
    expect(resolved.source).toBe("peer");
  });
});

describe("a request from an untrusted peer", () => {
  it("is counted against its own address even when it sends the header", () => {
    // T-P1, and it must survive the change: a forged header must still not be believed.
    const resolved = resolveClientAddress({
      peerAddress: "198.51.100.4",
      forwardedFor: "203.0.113.9",
      knownProxies: parseTrustedProxies(CADDY_NET),
    });

    expect(resolved.address).toBe("198.51.100.4");
    expect(resolved.source).toBe("peer");
  });

  it("with no proxy configured, behaves the same way", () => {
    const resolved = resolveClientAddress({
      peerAddress: "198.51.100.4",
      forwardedFor: "203.0.113.9",
      knownProxies: NO_PROXIES,
    });

    expect(resolved.address).toBe("198.51.100.4");
  });
});

describe("the limit itself, keyed by the resolved address", () => {
  it("gives each caller its own budget", () => {
    // The behaviour the user asked for, asserted on the limiter rather than on the
    // resolver, because the resolver returning the right value only helps if the
    // limiter is handed it.
    const limiter = new RateLimiter();
    const proxies = parseTrustedProxies(CADDY_NET);

    // One caller exhausts their own budget.
    for (let i = 0; i < 3; i++) {
      const { address } = resolveClientAddress({
        peerAddress: CADDY,
        forwardedFor: "203.0.113.9",
        knownProxies: proxies,
      });
      expect(limiter.checkNewSession(address).allowed).toBe(true);
    }
    expect(limiter.checkNewSession("203.0.113.9").allowed).toBe(false);

    // A different caller on the same proxy is unaffected. Before the fix this was the
    // same bucket and they would have been refused too.
    expect(limiter.checkNewSession("198.51.100.4").allowed).toBe(true);
  });

  it("would have refused them all before, on the shared bucket", () => {
    // Stated directly, so the regression is legible rather than inferred: with the
    // proxy untrusted — which is how it actually ran — one caller starves the rest.
    const limiter = new RateLimiter();
    const proxies = NO_PROXIES;
    const addresses = ["203.0.113.9", "198.51.100.4", "192.0.2.7"].map(
      (client) =>
        resolveClientAddress({ peerAddress: CADDY, forwardedFor: client, knownProxies: proxies })
          .address,
    );

    // All three collapse to one address — that is the bug, stated as an assertion.
    expect(new Set(addresses).size).toBe(1);

    // Three sessions from the first caller exhaust the one shared bucket...
    for (let i = 0; i < 3; i++) expect(limiter.checkNewSession(addresses[0]!).allowed).toBe(true);

    // ...and the third caller, who has never used the service, is refused. Note the
    // address checked is the *resolved* one, which is what the limiter is handed.
    const third = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "192.0.2.7",
      knownProxies: proxies,
    }).address;
    expect(third).toBe(addresses[0]);
    expect(limiter.checkNewSession(third).allowed).toBe(false);
  });
});

describe("an IPv6 caller", () => {
  it("is limited per /48, by design", () => {
    // Not a bug, but the thing to know before reporting "two IPs did not help": a
    // residential IPv6 address and its rotation share a /48, and PLAN-v2 §10 limits
    // on the /48. So two addresses from one subscriber are one bucket even with the
    // proxy bug fixed.
    const proxies = parseTrustedProxies(CADDY_NET);
    const first = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "2001:db8:1:2:aaaa::1",
      knownProxies: proxies,
    });
    const rotated = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "2001:db8:1:2:bbbb::9",
      knownProxies: proxies,
    });

    expect(first.address).toBe(rotated.address);
  });

  it("keeps two different /48s apart", () => {
    const proxies = parseTrustedProxies(CADDY_NET);
    const a = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "2001:db8:1:2::1",
      knownProxies: proxies,
    });
    const b = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "2001:db8:3:4::1",
      knownProxies: proxies,
    });

    expect(a.address).not.toBe(b.address);
  });
});

describe("the trust list itself", () => {
  it("refuses to start on a malformed entry rather than skipping it", () => {
    // Skipping would leave a half-configured list that reads as configured. The
    // symptom is a silently global rate limit, which is the failure this prevents.
    expect(() => parseTrustedProxies("172.24.0.0/16,not-an-address")).toThrow(ConfigError);
    expect(() => parseTrustedProxies("172.24.0.0/99")).toThrow(ConfigError);
    expect(() => parseTrustedProxies("172.24.0.0/16, ")).not.toThrow();
  });

  it("treats an absent value as trusting nothing", () => {
    // The pre-fix state. Asserted so the fail-closed default stays deliberate rather
    // than becoming an accident.
    expect(resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "203.0.113.9",
      knownProxies: parseTrustedProxies(undefined),
    }).address).toBe(CADDY);
  });

  it("counts one hop per entry, which is what the chain check needs", () => {
    expect(parseTrustedProxies(CADDY_NET).hops).toBe(1);
    expect(parseTrustedProxies(`${CADDY_NET},10.0.0.0/8`).hops).toBe(2);
    expect(NO_PROXIES.hops).toBe(0);
  });

  it("refuses a chain longer than the declared hops", () => {
    // T-P4, preserved: a prepended entry means someone is forging the chain.
    const resolved = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "1.2.3.4, 5.6.7.8, 203.0.113.9",
      knownProxies: parseTrustedProxies(CADDY_NET),
    });

    expect(resolved.suspiciousChain).toBe(true);
    expect(resolved.address).toBe(CADDY);
  });
});

// ---- the second bug: a restore was charged as a new session ----------------
//
// The limiter ran *before* the existing-session lookup, so reloading into a session
// the frontend had already created consumed the "new sessions" budget. On the shared
// bucket that meant a user reloading a few times could lock themselves out of creating
// a session at all. The comment three lines below the old limiter said "this is a
// restore, not a creation" — while the code above it had already charged one.

describe("a session restore", () => {
  let db: Db;

  beforeEach(() => {
    db = new Db(":memory:");
  });

  it("does not consume the new-session budget", async () => {
    const { buildServer } = await import("../src/server.js");
    const { generateCsrfKey, hashSecret } = await import("../src/session.js");
    const secret = "S".repeat(43);

    const app = buildServer(
      {
        allowedOrigins: new Set(["https://one.example.com"]),
        csrfKey: "C".repeat(43),
        sessionTtlHours: 12,
        minFreeDiskMb: 2048,
        publicOrigin: "https://one-backend.example.com",
        orchestratorUrl: "http://orchestrator:9100",
        orchestratorSecret: "B".repeat(43),
        orchestratorReplayWindowSeconds: 60,
        logLevel: "silent",
        listen: "127.0.0.1:0",
        databasePath: ":memory:",
        sseBufferEvents: 10,
        sseKeepaliveMs: 60_000,
        trustedProxies: NO_PROXIES,
        runnerToken: "R".repeat(43),
      } as never,
      {
        db,
        sse: { emit: () => {}, drop: () => {}, subscribe: () => () => {} } as never,
        limiter: new RateLimiter(),
        orchestrator: { healthz: async () => ({ ok: true, value: {} }) } as never,
      } as never,
    );
    await app.ready();

    const post = async (): Promise<number> => {
      const response = await app.inject({
        method: "POST",
        url: "/api/session",
        headers: { origin: "https://one.example.com", "content-type": "application/json" },
        payload: JSON.stringify({ guid: GUID, secret }),
      });
      return response.statusCode;
    };

    try {
      expect(await post()).toBe(201);
      // A reload into the same session, repeatedly. The frontend does this whenever
      // the page is reopened, and each one used to cost the user a session.
      for (let i = 0; i < 6; i++) expect(await post()).toBe(200);

      // Budget is 3. Six restores must not have exhausted it, so a genuinely new
      // session still works.
      const fresh = "9f2504e0-4f89-11d3-9a0c-0305e82c3302";
      const response = await app.inject({
        method: "POST",
        url: "/api/session",
        headers: { origin: "https://one.example.com", "content-type": "application/json" },
        payload: JSON.stringify({ guid: fresh, secret: "T".repeat(43) }),
      });
      expect(response.statusCode).toBe(201);
    } finally {
      await app.close();
      void generateCsrfKey;
      void hashSecret;
    }
  });
});

describe("normalise", () => {
  it("is unchanged in intent — a /48 for v6, the address for v4", () => {
    expect(normalise("203.0.113.9")).toBe("203.0.113.9");
    // A /48 is the first three groups, so the fourth is *not* part of the key. Two
    // addresses differing only there are one subscriber and therefore one bucket.
    expect(normalise("2001:db8:1:2::1")).toBe("2001:db8:1::/48");
    expect(normalise("2001:db8:1:9::1")).toBe("2001:db8:1::/48");
  });
});

void CADDY_NETWORK;
// ---- the wiring, which the tests above could not reach ---------------------
//
// Everything above constructs its own `trustedProxies` and passes it in, which proves
// the resolver and the route but says **nothing** about whether the deployed process
// ever supplies one. That is the same gap that let this bug ship: the resolver was
// correct, the route was correct, and the value had no path from the environment to
// either. Reverting `index.ts` left all sixteen tests above green.
//
// So: boot the real process from an environment, exactly as the deployment does, and
// count sessions the way a user would.

describe("a booted process", () => {
  it("reads its proxies from the environment", async () => {
    const { loadConfig } = await import("../src/config.js");
    const config = loadConfig({
      ALLOWED_ORIGINS: "https://app.example.com",
      PUBLIC_ORIGIN: "https://one-backend.example.com",
      CSRF_KEY: "A".repeat(43),
      ORCHESTRATOR_HMAC_SECRET: "B".repeat(43),
      RUNNER_TOKEN: "a-runner-token-long-enough",
      ORCHESTRATOR_URL: "http://orchestrator:9100",
      DATABASE_PATH: ":memory:",
      API_TRUSTED_PROXIES: CADDY_NET,
    } as NodeJS.ProcessEnv);

    // The link that was missing: config carries a matcher, and it is one that
    // matches the proxy.
    expect(config.trustedProxies.contains(CADDY)).toBe(true);
  });

  it("with no value set, believes nothing — and says so by limiting globally", async () => {
    // Not a warning about the old behaviour: this is the state a misconfigured
    // deployment is in, and the test names the consequence so the next reader does not
    // have to rediscover it.
    const { loadConfig } = await import("../src/config.js");
    const config = loadConfig({
      ALLOWED_ORIGINS: "https://app.example.com",
      PUBLIC_ORIGIN: "https://one-backend.example.com",
      CSRF_KEY: "A".repeat(43),
      ORCHESTRATOR_HMAC_SECRET: "B".repeat(43),
      RUNNER_TOKEN: "a-runner-token-long-enough",
      ORCHESTRATOR_URL: "http://orchestrator:9100",
      DATABASE_PATH: ":memory:",
    } as NodeJS.ProcessEnv);

    expect(config.trustedProxies.contains(CADDY)).toBe(false);
  });

  it("refuses to start on a malformed list", async () => {
    const { loadConfig } = await import("../src/config.js");
    expect(() =>
      loadConfig({
        ALLOWED_ORIGINS: "https://app.example.com",
        PUBLIC_ORIGIN: "https://one-backend.example.com",
        CSRF_KEY: "A".repeat(43),
        ORCHESTRATOR_HMAC_SECRET: "B".repeat(43),
        RUNNER_TOKEN: "a-runner-token-long-enough",
        ORCHESTRATOR_URL: "http://orchestrator:9100",
        DATABASE_PATH: ":memory:",
        API_TRUSTED_PROXIES: "172.24.0.0/16, garbage",
      } as NodeJS.ProcessEnv),
    ).toThrow(ConfigError);
  });
});

// ---- and a 429 has to say which bucket it hit ------------------------------
//
// The reason this took a deploy to find: a user reported "Too many attempts", two IPs
// did not help, and no log line said which address had been charged. It was the
// proxy's. A limit that cannot be diagnosed is a limit that will be diagnosed again.

describe("a refused session creation", () => {
  // Four distinct sessions, because a *restore* of an existing guid is no longer
  // charged — so reusing one would exercise the other bug and never exhaust a budget.
  const guids = [0, 1, 2, 3].map((n) => `${n}${GUID.slice(1)}`);

  // No default parameter. `trusted: string | undefined = CADDY_NET` looks equivalent
  // and is not: passing `undefined` explicitly *triggers* the default, so the
  // "no trusted proxy" case silently ran with the trusted one and asserted nothing.
  async function appWith(
    logs: Array<Record<string, unknown>>,
    trusted: string | undefined,
  ): Promise<{
    post: (guid: string, forwarded?: string) => Promise<number>;
    close: () => Promise<void>;
  }> {
    const { buildServer } = await import("../src/server.js");
    const { Db } = await import("../src/db.js");
    const { RateLimiter } = await import("../src/rate-limit.js");
    const { SseHub } = await import("../src/sse.js");

    const app = buildServer(
      {
        allowedOrigins: new Set(["https://one.example.com"]),
        csrfKey: "C".repeat(43),
        sessionTtlHours: 12,
        minFreeDiskMb: 2048,
        publicOrigin: "https://one-backend.example.com",
        orchestratorUrl: "http://orchestrator:9100",
        orchestratorSecret: "B".repeat(43),
        orchestratorReplayWindowSeconds: 60,
        logLevel: "silent",
        listen: "127.0.0.1:0",
        databasePath: ":memory:",
        sseBufferEvents: 10,
        sseKeepaliveMs: 60_000,
        trustedProxies: parseTrustedProxies(trusted),
        runnerToken: "R".repeat(43),
      } as never,
      {
        db: new Db(":memory:"),
        sse: new SseHub({ bufferEvents: 10, keepaliveMs: 60_000 }),
        limiter: new RateLimiter(),
        orchestrator: { healthz: async () => ({ ok: true, value: {} }) } as never,
      } as never,
      {
        logger: {
          level: "warn",
          hooks: {
            // Captured with a rest signature on purpose: the hook's argument order is
            // not the documented one (payload first, then the log function, then the
            // level), and guessing it wrong captures the level as the message — a test
            // that fails for a reason unrelated to the code. The object is the payload,
            // wherever it lands, so take any object.
            logMethod: (...all: unknown[]) => {
              for (const arg of all) {
                if (Array.isArray(arg)) {
                  // `log.warn(payload, "message")` arrives as the two arguments the
                  // call passed, in a single array. The payload is the first.
                  const first = arg.find(
                    (a): a is Record<string, unknown> =>
                      a !== null && typeof a === "object" && !Array.isArray(a),
                  );
                  if (first !== undefined) logs.push(first);
                } else if (arg !== null && typeof arg === "object") {
                  logs.push(arg as Record<string, unknown>);
                }
              }
            },
          },
        },
      },
    );
    await app.ready();

    return {
      post: async (guid: string, forwarded?: string): Promise<number> => {
        const response = await app.inject({
          method: "POST",
          url: "/api/session",
          remoteAddress: CADDY,
          headers: {
            origin: "https://one.example.com",
            "content-type": "application/json",
            ...(forwarded === undefined ? {} : { "x-forwarded-for": forwarded }),
          },
          payload: JSON.stringify({ guid, secret: "S".repeat(43) }),
        });
        return response.statusCode;
      },
      close: async () => {
        await app.close();
      },
    };
  }

  it("logs the address it charged and how it resolved it", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { post, close } = await appWith(logs, CADDY_NET);
    try {
      // Exhaust one caller's budget: three are allowed, the fourth is refused.
      for (const guid of guids.slice(0, 3)) {
        expect(await post(guid, "203.0.113.9")).toBe(201);
      }
      expect(await post(guids[3]!, "203.0.113.9")).toBe(429);

      const refused = logs.find((l) => l.address !== undefined);
      expect(refused).toBeDefined();
      // The client's address, and that it came from the header — so a reader can tell
      // a per-user limit from a global one at a glance.
      expect(refused?.address).toBe("203.0.113.9");
      expect(refused?.source).toBe("rightmost-forwarded");
    } finally {
      await close();
    }
  });

  it("names the proxy itself when the header is not believed", async () => {
    // The deployed state, restated as an assertion on the log: `address` is Caddy and
    // `source` is `peer`, which is the whole bug visible in one line.
    const logs: Array<Record<string, unknown>> = [];
    const { post, close } = await appWith(logs, undefined);
    try {
      // Same three-then-refused shape, but with no trusted proxy configured.
      for (const guid of guids.slice(0, 3)) await post(guid, "203.0.113.9");
      expect(await post(guids[3]!, "203.0.113.9")).toBe(429);

      const refused = logs.find((l) => l.address !== undefined);
      expect(refused?.address).toBe(CADDY);
      expect(refused?.source).toBe("peer");
    } finally {
      await close();
    }
  });
});
