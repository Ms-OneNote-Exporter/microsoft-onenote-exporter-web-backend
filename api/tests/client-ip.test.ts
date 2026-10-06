import { describe, expect, it } from "vitest";
import {
  hashForLog,
  ipv6Prefix48,
  normalise,
  rateLimitKeys,
  resolveClientAddress,
} from "../src/client-ip.js";

/**
 * PLAN-v3 §3.5. Without this, every per-IP limit in PLAN-v2 §10 is decorative:
 * behind a proxy a caller can claim any address by setting a header.
 */

const CADDY = "172.20.0.3";
const CADDY2 = "172.20.0.4";
const ONE_PROXY = new Set([CADDY]);

describe("resolveClientAddress", () => {
  // T-P1: a forged XFF from an unlisted peer is limited as its real peer.
  it("ignores X-Forwarded-For from a peer that is not a known proxy", () => {
    const result = resolveClientAddress({
      peerAddress: "198.51.100.7",
      forwardedFor: "1.2.3.4",
      knownProxies: ONE_PROXY,
    });
    expect(result.address).toBe("198.51.100.7");
    expect(result.source).toBe("peer");
  });

  // T-P2: a request from a listed proxy resolves to the rightmost hop — the
  // address that proxy actually saw.
  it("takes the rightmost hop from a known proxy", () => {
    // One hop, one known proxy: the ordinary case, where a client sent no XFF
    // and Caddy wrote the address it saw into it.
    const result = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "198.51.100.5",
      knownProxies: ONE_PROXY,
    });
    expect(result.address).toBe("198.51.100.5");
    expect(result.source).toBe("rightmost-forwarded");
  });

  it("takes the rightmost hop of a multi-hop chain from a known proxy", () => {
    const result = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "203.0.113.9, 198.51.100.5",
      knownProxies: new Set([CADDY, CADDY2]),
    });
    expect(result.address).toBe("198.51.100.5");
    expect(result.source).toBe("rightmost-forwarded");
  });

  it("does not take the leftmost hop", () => {
    const result = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "1.1.1.1, 2.2.2.2, 3.3.3.3",
      knownProxies: new Set([CADDY, CADDY2, "172.20.0.5"]),
    });
    expect(result.address).not.toBe("1.1.1.1");
    expect(result.address).toBe("3.3.3.3");
  });

  // The plan's rule is "reject a chain LONGER than the known-proxy count". A
  // two-hop chain arriving at a single-proxy deployment is exactly what a
  // client-supplied XFF looks like after Caddy appends to it, so it is refused
  // rather than resolved.
  it("refuses a two-hop chain at a single-proxy deployment", () => {
    const result = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "203.0.113.9, 198.51.100.5",
      knownProxies: ONE_PROXY,
    });
    expect(result.suspiciousChain).toBe(true);
    expect(result.address).toBe(CADDY);
  });

  // T-P3: X-Real-IP alone changes nothing. This module never reads it.
  it("ignores a header the caller supplies that is not X-Forwarded-For", () => {
    const result = resolveClientAddress({
      peerAddress: "198.51.100.7",
      knownProxies: ONE_PROXY,
    });
    expect(result.address).toBe("198.51.100.7");
  });

  // T-P4: a chain longer than the known-proxy count is rejected, not guessed.
  it("refuses a chain longer than the known-proxy count", () => {
    const result = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4",
      knownProxies: ONE_PROXY,
    });
    expect(result.suspiciousChain).toBe(true);
    expect(result.address).toBe(CADDY);
  });

  it("accepts a single-hop chain when two proxies are configured", () => {
    // Fewer hops than known proxies is not suspicious: the second configured
    // proxy is simply not in this request's path. Only a longer chain is.
    const result = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "198.51.100.5",
      knownProxies: new Set([CADDY, CADDY2]),
    });
    expect(result.suspiciousChain).toBe(false);
    expect(result.address).toBe("198.51.100.5");
  });

  it("refuses a non-address value in the rightmost hop", () => {
    for (const hostile of ["unknown", "not-an-ip", "1.2.3.4:8080", "999.1.1.1", "::1/128"]) {
      const result = resolveClientAddress({
        peerAddress: CADDY,
        // Two hops against two known proxies, so the chain length is legitimate
        // and the rightmost entry is what is being judged.
        forwardedFor: `198.51.100.5, ${hostile}`,
        knownProxies: new Set([CADDY, CADDY2]),
      });
      expect(result.suspiciousChain).toBe(true);
      expect(result.address).toBe(CADDY);
    }
  });

  it("ignores empty chain entries rather than treating them as a hop", () => {
    // A trailing comma is noise, not an attempt to shift the rightmost hop.
    // Filtering empties means the judgement is made on the addresses that are
    // actually present.
    const result = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "198.51.100.5, ",
      knownProxies: new Set([CADDY, CADDY2]),
    });
    expect(result.suspiciousChain).toBe(false);
    expect(result.address).toBe("198.51.100.5");
  });

  it("falls back to the peer when a known proxy sends no forwarded header", () => {
    const result = resolveClientAddress({ peerAddress: CADDY, knownProxies: ONE_PROXY });
    expect(result.address).toBe(CADDY);
    expect(result.source).toBe("peer");
  });

  it("handles an empty forwarded header from a known proxy", () => {
    const result = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "   ",
      knownProxies: ONE_PROXY,
    });
    expect(result.address).toBe(CADDY);
  });

  it("fails closed when no proxy is configured", () => {
    // The default deployment has nothing in front of api for public traffic, so
    // every request resolves to its peer.
    const result = resolveClientAddress({
      peerAddress: "198.51.100.7",
      forwardedFor: "1.2.3.4",
      knownProxies: new Set(),
    });
    expect(result.address).toBe("198.51.100.7");
  });

  it("reduces an IPv6 client to its /48", () => {
    // /48 is three groups. A /64 would leave the fourth group as an allocation
    // boundary nobody should be limited within.
    const result = resolveClientAddress({
      peerAddress: "2001:db8:abcd:1234::1",
      knownProxies: new Set(),
    });
    expect(result.address).toBe("2001:db8:abcd::/48");
  });

  it("does not case-fold an IPv4 address into something else", () => {
    const result = resolveClientAddress({ peerAddress: "198.51.100.7", knownProxies: new Set() });
    expect(result.address).toBe("198.51.100.7");
  });
});

describe("ipv6Prefix48", () => {
  it("takes the first three groups", () => {
    expect(ipv6Prefix48("2001:db8:abcd:1234::1")).toBe("2001:db8:abcd::/48");
  });

  it("handles a compressed form", () => {
    expect(ipv6Prefix48("2001:db8:1:2:3:4:5:6")).toBe("2001:db8:1::/48");
    expect(ipv6Prefix48("2001:db8::")).toBe("2001:db8:0::/48");
  });

  it("returns null for IPv4", () => {
    expect(ipv6Prefix48("198.51.100.7")).toBeNull();
  });

  it("groups addresses in one allocation onto one limit bucket", () => {
    // PLAN-v2 §10 limits IPv6 per /48: a /64 is handed to one subscriber, so
    // per-/64 limiting would let one subscriber churn addresses to exhaust a pool.
    const a = normalise("2001:db8:abcd:1111::1");
    const b = normalise("2001:db8:abcd:2222::9");
    expect(a).toBe(b);
  });

  it("keeps different allocations apart", () => {
    expect(normalise("2001:db8:abcd::1")).not.toBe(normalise("2001:db8:1234::1"));
  });
});

describe("normalise", () => {
  it("trims and lowercases", () => {
    expect(normalise("  198.51.100.7  ")).toBe("198.51.100.7");
  });

  it("returns 'unknown' for an empty value rather than an empty bucket", () => {
    // An empty key would make every malformed peer share one bucket.
    expect(normalise("")).toBe("unknown");
    expect(normalise("   ")).toBe("unknown");
  });
});

describe("rateLimitKeys", () => {
  it("keys on the client address", () => {
    const client = resolveClientAddress({ peerAddress: "198.51.100.7", knownProxies: new Set() });
    expect(rateLimitKeys({ client })).toEqual(["ip:198.51.100.7"]);
  });

  it("adds a session key, so one address cannot burn many sessions", () => {
    const client = resolveClientAddress({ peerAddress: "198.51.100.7", knownProxies: new Set() });
    const keys = rateLimitKeys({ client, sessionId: "session-1" });
    expect(keys).toContain("ip:198.51.100.7");
    expect(keys).toContain("session:session-1");
  });

  it("gives a spoofing attempt its own bucket", () => {
    const client = resolveClientAddress({
      peerAddress: CADDY,
      forwardedFor: "1.1.1.1, 2.2.2.2, 3.3.3.3",
      knownProxies: ONE_PROXY,
    });
    expect(rateLimitKeys({ client })).toContain(`spoof:${CADDY}`);
  });

  it("adds no session key when there is no session", () => {
    const client = resolveClientAddress({ peerAddress: "198.51.100.7", knownProxies: new Set() });
    for (const key of rateLimitKeys({ client })) {
      expect(key.startsWith("session:")).toBe(false);
    }
  });
});

describe("hashForLog", () => {
  // T-P5: a raw address must not appear in logs or SQLite.
  it("does not contain the address", () => {
    const address = "198.51.100.7";
    expect(hashForLog(address, "salt")).not.toContain(address);
  });

  it("is stable for the same salt", () => {
    expect(hashForLog("198.51.100.7", "salt")).toBe(hashForLog("198.51.100.7", "salt"));
  });

  it("differs per salt, so buckets are not correlatable across deployments", () => {
    expect(hashForLog("198.51.100.7", "salt-a")).not.toBe(hashForLog("198.51.100.7", "salt-b"));
  });

  it("is fixed length, so it cannot leak the address length", () => {
    expect(hashForLog("1.1.1.1", "s")).toHaveLength(16);
    expect(hashForLog("2001:db8:1:2:3:4:5:6", "s")).toHaveLength(16);
  });

  it("does not collide across the whole IPv4 space in a small sample", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 5000; i++) {
      seen.add(hashForLog(`198.51.${(i / 256) | 0}.${i % 256}`, "salt"));
    }
    expect(seen.size).toBe(5000);
  });
});