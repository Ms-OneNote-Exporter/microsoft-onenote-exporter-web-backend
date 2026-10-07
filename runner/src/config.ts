/**
 * The runner's configuration, read from the environment once.
 *
 * ## What is deliberately not configurable
 *
 * **There is no way to turn on `--dodump` or `--screenshot`.** Not through the
 * environment, not through a request header, not through a query parameter. That
 * is the difference between a default and a control: a default can be turned off
 * by whoever deploys next, and a control cannot be turned on at all.
 *
 * The two flags are credential artefacts in a hosted service. An HTML dump
 * contains the authenticated DOM with live cookies and tenant hostnames; a
 * screenshot cannot redact a password field at all, because it is a bitmap, and
 * it shows the number-match MFA code. `runner/README.md` calls this a security
 * control rather than a tidiness preference, and `tests/debug-surface.test.ts`
 * asserts it by enumerating this app's routes.
 *
 * ## What is read
 *
 * Only what the sidecar genuinely needs to run. Notably absent: any session
 * secret, any CSRF key, and the orchestrator's HMAC secret. The runner holds the
 * credential bytes and nothing else, and a configuration surface is how that
 * would quietly stop being true.
 */

import { readFileSync } from "node:fs";

export interface RunnerConfig {
  /** Where per-session directories live. One subdirectory per session guid. */
  readonly dataRoot: string;
  /** Where finished archives are written, for the orchestrator to claim. */
  readonly artifactRoot: string;
  /**
   * The bearer token the orchestrator presents.
   *
   * Read from a file rather than an environment variable, for the reason the
   * rest of the stack uses secret files: an env var is visible in
   * `docker inspect` and in `/proc/<pid>/environ` to anything that can read the
   * container's config.
   */
  readonly token: string;
  /** Hard cap on a credential body. A password is short; this is generous. */
  readonly credentialBodyLimit: number;
  /** How long one login may take before it is stopped. */
  readonly loginTimeoutMs: number;
  /** How long one export may take. Exports are minutes; logins are too. */
  readonly exportTimeoutMs: number;
  /** Cap on the size of one finished archive, in bytes. */
  readonly quotaBytes: number;
  /** Refuse to start an export below this much free space on the data volume. */
  readonly minFreeBytes: number;
  /** Lines of child output retained per session for replay. */
  readonly ringSize: number;
}

function intFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer, got ${JSON.stringify(raw)}`);
  }
  return parsed;
}

function bytesFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer of bytes, got ${JSON.stringify(raw)}`);
  }
  return parsed;
}

/**
 * Loads the configuration, or throws with a message naming the missing variable.
 *
 * Throwing rather than defaulting is the point: a runner that starts with a
 * default token would accept requests from anything on the network, and the
 * symptom of that is a credential handed to the wrong process.
 */
export function loadConfig(): RunnerConfig {
  const dataRoot = process.env.MSOUT_DATA_ROOT ?? "/data";
  const artifactRoot = process.env.MSOUT_ARTIFACT_ROOT ?? "/artifacts";
  const tokenPath = process.env.MSOUT_RUNNER_TOKEN_FILE;

  if (tokenPath === undefined || tokenPath.trim() === "") {
    throw new Error(
      "MSOUT_RUNNER_TOKEN_FILE is required. The runner refuses to start without a " +
        "token: a default would accept requests from anything that can reach it, and " +
        "this process holds credential bytes.",
    );
  }

  let token: string;
  try {
    token = readFileSync(tokenPath, "utf8").trim();
  } catch (cause) {
    throw new Error(
      `MSOUT_RUNNER_TOKEN_FILE could not be read at ${tokenPath}: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
  }
  if (token.length < 16) {
    // Short enough to be a placeholder that reached production. The value is a
    // bearer token, so the only thing that matters is that it is not guessable.
    throw new Error(
      `the runner token in ${tokenPath} is ${token.length} characters; at least 16 are ` +
        "required",
    );
  }

  return {
    dataRoot,
    artifactRoot,
    token,
    credentialBodyLimit: bytesFromEnv("MSOUT_CREDENTIAL_LIMIT", 4096),
    loginTimeoutMs: intFromEnv("MSOUT_LOGIN_TIMEOUT_MS", 300_000),
    exportTimeoutMs: intFromEnv("MSOUT_EXPORT_TIMEOUT_MS", 3_600_000),
    quotaBytes: bytesFromEnv("MSOUT_QUOTA_BYTES", 8 * 1024 * 1024 * 1024),
    minFreeBytes: bytesFromEnv("MSOUT_MIN_FREE_BYTES", 2 * 1024 * 1024 * 1024),
    ringSize: intFromEnv("MSOUT_RING_SIZE", 500),
  };
}
