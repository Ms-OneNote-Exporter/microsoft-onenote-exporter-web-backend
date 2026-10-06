/**
 * Client address resolution.
 *
 * PLAN-v3 §3.5. This exists because the layered per-IP rate limits in PLAN-v2
 * §10 are otherwise decorative: behind a proxy, a caller who can set a header
 * can claim any address, and a limiter that can be bypassed by sending a header
 * is not a control.
 *
 * The rule is mechanical rather than advisory:
 *
 *   - the socket peer is authoritative
 *   - a request from a *known* proxy takes the rightmost `X-Forwarded-For` entry
 *     — the address that proxy actually saw, not the leftmost
 *   - a request from an unknown peer uses the peer address as-is and the
 *     forwarded header is ignored entirely
 *   - a chain longer than the known-proxy count is rejected, not guessed
 *
 * Why rightmost rather than "strip inbound headers": stripping is correct but
 * brittle, because it is a Caddy directive a later config edit can silently drop.
 * Rightmost-plus-known-peer is checkable in CI (T-P1…T-P4).
 */

import { createHash } from "node:crypto";

/** A resolved client identity, plus how it was arrived at. */
export interface ClientAddress {
  /** The address used for rate limiting. Normalised, never a raw header value. */
  readonly address: string;
  /** Which rule produced it, for logging and for the tests that assert the rule. */
  readonly source: "peer" | "rightmost-forwarded";
  /**
   * True when an X-Forwarded-For chain was longer than the known-proxy count.
   *
   * A spoofed chain is a strong signal rather than an error to guess around, so
   * it is surfaced for the limiter to weigh and never silently truncated.
   */
  readonly suspiciousChain: boolean;
}

/** An IP address string, v4 or v6. Deliberately strict. */
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-fA-F:]+$/;

/** isIpLike reports whether a string plausibly is an IP address. */
function isIpLike(value: string): boolean {
  if (value.includes(",")) return false; // a chain entry must be a single address
  if (value.includes(" ")) return false; // no "ip:port", no padding
  if (IPV4.test(value)) {
    return value.split(".").every((octet) => {
      const n = Number(octet);
      return Number.isInteger(n) && n >= 0 && n <= 255;
    });
  }
  return value.includes(":") && IPV6.test(value);
}

/**
 * isIPv6 returns the /48 prefix of an IPv6 address, which is what PLAN-v2 §10
 * limits on.
 *
 * A single /64 address is one host, but a residential or mobile allocation is a
 * /64 handed to one subscriber, so per-/64 limiting would let a single subscriber
 * exhaust a pool by churning addresses within their own allocation. The plan
 * specifies per-/48.
 */
export function ipv6Prefix48(address: string): string | null {
  if (!address.includes(":")) return null;
  // Expand to the full 8 groups so a compressed form is handled.
  const parts = address.split("::");
  const head = parts[0] ?? "";
  const tail = parts[1] ?? "";
  const headGroups = head === "" ? [] : head.split(":");
  const tailGroups = tail === "" ? [] : tail.split(":");
  const missing = 8 - headGroups.length - tailGroups.length;
  if (missing < 0) return null;
  const groups = [...headGroups, ...Array<string>(missing).fill("0"), ...tailGroups];
  if (groups.length !== 8) return null;
  return `${groups[0]}:${groups[1]}:${groups[2]}::/48`;
}

/**
 * resolveClientAddress derives the limiting address for a request.
 *
 * `peerAddress` is the socket peer. `forwardedFor` is the raw header, which may be
 * absent, may hold a chain, or may be attacker-supplied — it is only consulted
 * when the peer is a known proxy, and even then only its rightmost entry.
 *
 * `knownProxies` is the configured set of proxy addresses. Empty means "no proxy
 * in front of me", which is the fail-closed default: every request resolves to
 * its peer.
 */
export function resolveClientAddress(input: {
  peerAddress: string;
  forwardedFor?: string | undefined;
  knownProxies: ReadonlySet<string>;
}): ClientAddress {
  const peer = normalise(input.peerAddress);

  if (!input.knownProxies.has(peer)) {
    // Not from a proxy we trust. The header is attacker-controlled and is
    // ignored — this is T-P1, a forged XFF from an unlisted peer being limited
    // as its real peer.
    return { address: peer, source: "peer", suspiciousChain: false };
  }

  const raw = input.forwardedFor;
  if (raw === undefined || raw.trim() === "") {
    // A trusted proxy with no forwarded header. Fall back to the peer, which is
    // the proxy itself; that is a shared address and so limits coarsely rather
    // than wrongly.
    return { address: peer, source: "peer", suspiciousChain: false };
  }

  const hops = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");

  // A chain longer than the number of proxies we know about means someone
  // prepended entries. Guessing which are real is exactly the ambiguity that
  // makes header-based limiting untrustworthy, so the chain is flagged and the
  // peer is used instead (T-P4).
  const suspiciousChain = hops.length > input.knownProxies.size;
  if (suspiciousChain) {
    return { address: peer, source: "peer", suspiciousChain: true };
  }

  const rightmost = hops[hops.length - 1];
  if (rightmost === undefined || !isIpLike(rightmost)) {
    return { address: peer, source: "peer", suspiciousChain: true };
  }

  return {
    address: normalise(rightmost),
    source: "rightmost-forwarded",
    suspiciousChain: false,
  };
}

/**
 * normalise canonicalises an address.
 *
 * Lowercased so a comparison is not case-sensitive for IPv6, and an IPv6 address
 * is reduced to its /48 because that is what the limits are defined on. Trimming
 * only; nothing is invented.
 */
export function normalise(address: string): string {
  const trimmed = address.trim().toLowerCase();
  if (trimmed === "") return "unknown";
  const prefix = ipv6Prefix48(trimmed);
  return prefix ?? trimmed;
}

/**
 * rateLimitKeys returns the keys a request counts against.
 *
 * Three keys, because PLAN-v2 §10 imposes layered limits and a caller with one
 * address can still try to act as many sessions. The session key is what stops
 * a single IP burning the pool with many sessions, and the global cap is the
 * backstop.
 */
export function rateLimitKeys(input: {
  client: ClientAddress;
  sessionId?: string | undefined;
}): readonly string[] {
  const keys: string[] = [`ip:${input.client.address}`];

  // A session-scoped key would let an attacker evict another session's bucket
  // by guessing its id, so it is namespaced and only added when a session was
  // actually authenticated.
  if (input.sessionId) {
    keys.push(`session:${input.sessionId}`);
  }
  if (input.client.suspiciousChain) {
    // Counted separately so a spoofing attempt cannot share a bucket with
    // honest traffic from the same peer.
    keys.push(`spoof:${input.client.address}`);
  }
  return keys;
}

/**
 * hashForLog returns the form of an address that may be written down.
 *
 * PLAN-v2 §10 requires that only truncated or hashed addresses are retained,
 * because a retained raw address is a user identifier that outlived the request.
 * T-P5 asserts a raw address appears in neither logs nor SQLite.
 */
export function hashForLog(address: string, salt: string): string {
  // A non-cryptographic hash would be reversible by brute force over the IPv4
  // space — about four billion entries — so this is SHA-256 truncated to 64
  // bits: enough to bucket, not enough to enumerate.
  return createHash("sha256")
    .update(`${salt}:${address}`, "utf8")
    .digest("hex")
    .slice(0, 16);
}