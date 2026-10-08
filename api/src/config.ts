/**
 * Environment parsing and validation.
 *
 * Every rule here fails closed: a malformed value stops the process rather than
 * falling back to something permissive. That is a stated design property, not a
 * preference — PLAN-v3 §3.3 lists the startup assertions that turn a bad
 * deployment into a loud failure instead of a silently open service, and T-C6
 * is the test for the origin allowlist specifically.
 *
 * The error messages name the offending variable. "refuses to start" is only
 * useful during an incident if the operator can tell which line to fix.
 */

/** A configuration value that failed validation. */
export class ConfigError extends Error {
  constructor(
    readonly variable: string,
    message: string,
  ) {
    super(`${variable}: ${message}`);
    this.name = "ConfigError";
  }
}

/** The api's validated runtime configuration. */
export interface ApiConfig {
  /** Exact origins allowed to call this API. Never empty, never a wildcard. */
  readonly allowedOrigins: ReadonlySet<string>;
  /** Secret for deriving per-session CSRF keys. Base64url, exactly 43 chars. */
  readonly csrfKey: string;
  /** How long a session and its artifacts survive. */
  readonly sessionTtlHours: number;
  /** Refuse to start an export below this much free disk. */
  readonly minFreeDiskMb: number;
  /**
   * Proxies whose `X-Forwarded-For` may be believed.
   *
   * Empty means "believe none", and behind a reverse proxy that silently turns a
   * per-user rate limit into a **global** one: every caller is counted against the
   * proxy's address. This was the deployed state on a live host — 3 sessions an hour
   * for everyone on the internet, because `knownProxies` had no way to be set at all.
   *
   * So a deployment behind a proxy must name it. See `parseTrustedProxies`.
   */
  readonly trustedProxies: ProxyMatcher;
  /** Base URL of the orchestrator. Internal only. */
  readonly orchestratorUrl: string;
  /** HMAC secret for signed internal calls. */
  readonly orchestratorSecret: string;
  /** Replay window for internal calls, in seconds. */
  readonly orchestratorReplayWindowSeconds: number;
  /**
   * The bearer token a runner requires on every route but `/healthz`.
   *
   * Held because this is the component that calls a runner, not the
   * orchestrator — the orchestrator creates containers and drives none of them.
   * It authorises starting work in a container that already exists; it never
   * carries or reveals a password, and it cannot create a container.
   *
   * Validated to the runner's own rule — at least 16 characters — rather than
   * the 43-character rule the CSRF key uses. Those are different secrets with
   * different jobs, and reusing one shape for both would make a 32-byte runner
   * token an unrepresentable configuration.
   */
  readonly runnerToken: string;
  /** Log level. */
  readonly logLevel: "debug" | "info" | "warn" | "error";
  /** Listen address for the HTTP surface. */
  readonly listen: string;
  /**
   * The origin this service is reached at, e.g. `https://one-backend.phttp.com`.
   *
   * Artifact `downloadUrl`s are absolute and built from this. It is operator
   * configuration, never a request header — see `validatePublicOrigin`.
   */
  readonly publicOrigin: string;
  /** Path to the SQLite database file. */
  readonly databasePath: string;
  /** SSE ring buffer size, in events. */
  readonly sseBufferEvents: number;
  /** SSE keepalive interval, in milliseconds. */
  readonly sseKeepaliveMs: number;
}

/**
 * validatePublicOrigin checks the origin this service is reached at.
 *
 * This is the value `artifact.downloadUrl` is built from, and it must be an
 * explicit configuration rather than something derived. Two reasons, and the
 * second is why deriving it looks tempting and is still wrong:
 *
 *   1. **The download needs it.** The session cookie is `__Host-msout`, which the
 *      `__Host-` prefix pins to this host with no `Domain`. A relative download
 *      URL would resolve against the *frontend's* origin, where the browser will
 *      not attach the cookie, so Caddy's `forward_auth` would receive no `Cookie`
 *      at all and refuse every download. `SameSite=None` does not help: SameSite
 *      governs site, not host. So the URL must be absolute and point here.
 *   2. **Deriving it would put a proxy header in the trust path.** An
 *      `X-Forwarded-Host` would make the download URL depend on a request header,
 *      and therefore make a second operator's proxy able to redirect a user's
 *      artifact download. The value is operator-supplied, validated once at boot,
 *      and used for every URL this process emits.
 *
 * The rules match `ALLOWED_ORIGINS` deliberately: https unless loopback, bare
 * origin with no path, no wildcard. A public origin carrying a path would make
 * every `downloadUrl` wrong in a way that only shows after an export finishes.
 */
export function validatePublicOrigin(value: string): string {
  const entry = value.trim();
  if (entry === "") {
    throw new ConfigError(
      "PUBLIC_ORIGIN",
      "is required. Artifact download URLs are absolute and point at this service; " +
        "see cookies.ts for why they cannot be relative.",
    );
  }

  let url: URL;
  try {
    url = new URL(entry);
  } catch {
    throw new ConfigError("PUBLIC_ORIGIN", `"${entry}" is not a URL`);
  }

  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHostname(url.hostname))) {
    throw new ConfigError(
      "PUBLIC_ORIGIN",
      `"${entry}" must be https, or http on loopback for development`,
    );
  }
  if (url.pathname !== "/" || url.search !== "" || url.hash !== "") {
    throw new ConfigError(
      "PUBLIC_ORIGIN",
      `"${entry}" must be a bare origin with no path, query or fragment`,
    );
  }
  if (/[*?]/.test(url.hostname)) {
    throw new ConfigError(
      "PUBLIC_ORIGIN",
      `"${entry}" contains a wildcard label; downloads need one exact host`,
    );
  }

  return url.origin;
}

/**
 * isLoopbackHostname reports whether a hostname can only resolve to this machine.
 *
 * Loopback names, not "private ranges": 10/8 and 192.168/16 are reachable over a
 * real network, and a credential sent to a dev frontend on one of those would
 * cross a wire in clear, which is the whole thing the https rule prevents.
 */
function isLoopbackHostname(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]" ||
    // Any 127/8 address is loopback by definition, not just 127.0.0.1.
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
  );
}

/**
 * secretPattern is the session secret's exact shape: 43 base64url characters,
 * which is 32 bytes unpadded.
 *
 * Enforced mechanically rather than trusted from the client, because under the
 * two-component split the secret is generated by Component A (PLAN-v3 §4) and a
 * compromised frontend could generate a weak one. The API is the last place that
 * can say no.
 */
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * validateOrigins checks the ALLOWED_ORIGINS value against every rule in
 * PLAN-v3 §3.3.
 *
 * Rejects: empty, `*`, `null`, non-https, trailing slash, and any entry with a
 * path. Each of those is a distinct footgun, and each is checked by name so the
 * failure says which one it was.
 */
export function validateOrigins(raw: string | undefined): Set<string> {
  const entries = (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");

  if (entries.length === 0) {
    throw new ConfigError(
      "ALLOWED_ORIGINS",
      "must list at least one exact origin (PLAN-v3 §3.3)",
    );
  }

  const out = new Set<string>();
  for (const entry of entries) {
    if (entry === "*") {
      throw new ConfigError("ALLOWED_ORIGINS", `wildcard "${entry}" is not permitted`);
    }
    if (entry === "null") {
      throw new ConfigError(
        "ALLOWED_ORIGINS",
        '"null" is not permitted; it is what a sandboxed iframe sends',
      );
    }
    if (entry.endsWith("/")) {
      throw new ConfigError("ALLOWED_ORIGINS", `"${entry}" must not end with a slash`);
    }

    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      throw new ConfigError("ALLOWED_ORIGINS", `"${entry}" is not a URL`);
    }

    if (url.protocol !== "https:") {
      // The one exception is loopback, and it is narrow on purpose.
      //
      // A development frontend runs on http://localhost, and without this the
      // allowlist could not name it — which would push the mock server toward
      // bypassing config validation entirely, and a mock that skips validation
      // stops exercising the thing that catches a misconfigured deployment.
      //
      // Loopback is not a weakening of "http would put the credential on the wire
      // in clear", because a loopback address never reaches a wire: the bytes go
      // from the browser to a process on the same machine, which is the same
      // trust boundary as the api talking to a sidecar. What it *does* mean is
      // that a credential is visible to anything on the host that can read loopback
      // traffic, so it is scoped to the three loopback names rather than to
      // "private ranges" or "no TLS".
      if (url.protocol === "http:" && isLoopbackHostname(url.hostname)) {
        out.add(url.origin);
        continue;
      }
      throw new ConfigError(
        "ALLOWED_ORIGINS",
        `"${entry}" must be https; http would put the credential on the wire in clear`,
      );
    }
    // A path (or query, or fragment) makes the origin a prefix, and prefix
    // matching is how an allowlist becomes "any subdomain".
    if (url.pathname !== "/" || url.search !== "" || url.hash !== "") {
      throw new ConfigError(
        "ALLOWED_ORIGINS",
        `"${entry}" must be a bare origin with no path, query or fragment`,
      );
    }

    // A wildcard label is not caught by the bare-origin check: URL happily parses
    // "https://*.example.com" into a hostname of "*.example.com". That value can
    // never match a real Origin header — a browser sends the literal hostname —
    // so accepting it would produce an allowlist entry that silently does
    // nothing, and every request would be refused. Loudly rejected instead.
    if (/[*?]/.test(url.hostname)) {
      throw new ConfigError(
        "ALLOWED_ORIGINS",
        `"${entry}" contains a wildcard label; list each origin exactly`,
      );
    }

    // Normalise to the serialised origin so a configured value and an incoming
    // header compare equal. URL drops the default port, which is the common
    // mismatch ("https://x:443" vs the browser's "https://x").
    out.add(url.origin);
  }

  return out;
}

/**
 * readSecret resolves a secret from either an inline value or a file path.
 *
 * Docker secrets arrive as files, and the `*_FILE` convention is the reason the
 * value never appears in `docker inspect` or in `/proc/<pid>/environ`. Compose
 * passes `CSRF_KEY_FILE=/run/secrets/csrf_key` and no `CSRF_KEY` at all, so this
 * is the path a real deployment takes and the inline form is the development one.
 *
 * The trailing newline is stripped, and it has to be: a file written with
 * `echo "$secret" >` has one, and without stripping it every deployment would
 * fail `validateSecret` with a shape error pointing at the wrong thing.
 *
 * `_FILE` wins when both are set. A deployment that sets both has made a mistake,
 * and preferring the file is the choice that cannot leak the inline value into a
 * process listing.
 */
function readSecret(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const file = env[`${name}_FILE`]?.trim();
  if (file !== undefined && file !== "") {
    try {
      return readFileSync(file, "utf8").trim();
    } catch (error) {
      throw new ConfigError(
        `${name}_FILE`,
        `points at ${file}, which could not be read: ${
          error instanceof Error ? error.message : "unknown error"
        }`,
      );
    }
  }
  return env[name];
}

/** validateSecret checks the CSRF key's shape. */
export function validateSecret(raw: string | undefined, variable = "CSRF_KEY"): string {
  const value = (raw ?? "").trim();
  if (value === "") {
    throw new ConfigError(variable, "is required");
  }
  if (!SECRET_PATTERN.test(value)) {
    throw new ConfigError(
      variable,
      `must be exactly 43 base64url characters (256 bits unpadded), got ${value.length} characters`,
    );
  }
  return value;
}

/** RUNNER_TOKEN_PATTERN mirrors the runner's own check, minus the base64url rule. */
const RUNNER_TOKEN_PATTERN = /^[\x21-\x7e]{16,}$/;

/**
 * validateRunnerToken checks the bearer token presented to a runner.
 *
 * The minimum length is the runner's, not this api's: the runner refuses to start
 * below 16 characters, and a token the api accepted but the runner rejected would
 * present as every login being refused for no stated reason.
 *
 * The character class is printable ASCII with no spaces, because the value travels
 * in a header — a token with a space in it would be transmitted, be rejected, and
 * be invisible in the `docker inspect` output an operator would check.
 */
export function validateRunnerToken(raw: string | undefined): string {
  const value = (raw ?? "").trim();
  if (value === "") {
    throw new ConfigError("RUNNER_TOKEN", "is required");
  }
  if (!RUNNER_TOKEN_PATTERN.test(value)) {
    throw new ConfigError(
      "RUNNER_TOKEN",
      "must be at least 16 printable non-space ASCII characters, which is the " +
        "runner's own minimum",
    );
  }
  return value;
}

/**
 * validateInternalOrigin checks the orchestrator URL.
 *
 * It must be https, or http on a name that cannot be a public host — an http URL
 * to a public address would send the HMAC secret in clear on every container
 * creation, which is the one call worth protecting most.
 */
export function validateInternalOrigin(raw: string | undefined): string {
  const value = (raw ?? "").trim();
  if (value === "") {
    throw new ConfigError("ORCHESTRATOR_URL", "is required");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError("ORCHESTRATOR_URL", `"${value}" is not a URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new ConfigError("ORCHESTRATOR_URL", `"${value}" must be http or https`);
  }
  if (url.protocol === "http:") {
    const host = url.hostname;
    // localhost and single-label names resolve inside the compose network only.
    const internal =
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "[::1]" ||
      host === "::1" ||
      !host.includes(".");
    if (!internal) {
      throw new ConfigError(
        "ORCHESTRATOR_URL",
        `"${value}" is a public host over http; the HMAC secret would cross the wire in clear. Use https or an internal name`,
      );
    }
  }
  if (url.pathname !== "/") {
    throw new ConfigError("ORCHESTRATOR_URL", `"${value}" must have no path`);
  }
  return url.origin;
}

/** positiveInt reads a positive integer from the environment. */
function positiveInt(
  env: NodeJS.ProcessEnv,
  key: string,
  fallback: number,
): number {
  const raw = env[key]?.trim();
  if (!raw) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) {
    throw new ConfigError(key, `must be a positive integer, got "${raw}"`);
  }
  return n;
}

/** loadConfig validates the whole environment and returns the result. */
import { readFileSync } from "node:fs";

import { parseTrustedProxies } from "./client-ip.js";
import type { ProxyMatcher } from "./client-ip.js";

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ApiConfig {
  const level = (env.LOG_LEVEL?.trim() || "info") as ApiConfig["logLevel"];
  if (!["debug", "info", "warn", "error"].includes(level)) {
    throw new ConfigError("LOG_LEVEL", `must be debug|info|warn|error, got "${level}"`);
  }

  return {
    allowedOrigins: validateOrigins(env.ALLOWED_ORIGINS),
    csrfKey: validateSecret(readSecret(env, "CSRF_KEY")),
    sessionTtlHours: positiveInt(env, "SESSION_TTL_HOURS", 12),
    minFreeDiskMb: positiveInt(env, "MIN_FREE_DISK_MB", 2048),
    trustedProxies: parseTrustedProxies(env.API_TRUSTED_PROXIES),
    orchestratorUrl: validateInternalOrigin(env.ORCHESTRATOR_URL),
    orchestratorSecret: validateSecret(
      readSecret(env, "ORCHESTRATOR_HMAC_SECRET"),
      "ORCHESTRATOR_HMAC_SECRET",
    ),
    orchestratorReplayWindowSeconds: positiveInt(
      env,
      "ORCHESTRATOR_REPLAY_WINDOW_SECONDS",
      60,
    ),
    runnerToken: validateRunnerToken(readSecret(env, "RUNNER_TOKEN")),
    logLevel: level,
    listen: env.LISTEN?.trim() || "0.0.0.0:3000",
    publicOrigin: validatePublicOrigin(env.PUBLIC_ORIGIN ?? ""),
    databasePath: env.DATABASE_PATH?.trim() || "/srv/msout/data/api.db",
    sseBufferEvents: positiveInt(env, "SSE_BUFFER_EVENTS", 500),
    sseKeepaliveMs: positiveInt(env, "SSE_KEEPALIVE_MS", 15_000),
  };
}