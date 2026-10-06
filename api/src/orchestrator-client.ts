/**
 * The signed client for `api` -> orchestrator calls.
 *
 * PLAN-v3 §2.1. A bare bearer token is not enough, because the threat is a
 * *replayed* request to an endpoint that can create containers. Every call
 * carries:
 *
 *   X-Msout-TS:  <unix ms>
 *   X-Msout-Sig: base64url(HMAC-SHA256(secret, TS + "\n" + METHOD + "\n" + path + "\n" + sha256hex(body)))
 *
 * The same construction the orchestrator verifies (orchestrator/internal/auth),
 * expressed here in TypeScript. Both sides assemble the signed string in one
 * place each, so they cannot drift, and the shared test vector in
 * `orchestrator/internal/auth/auth_test.go` is what pins them together.
 *
 * This client holds the secret. Nothing else on the host does — not the
 * orchestrator's environment, not any runner, not a bind mount.
 */

import { createHmac, createHash } from "node:crypto";

/** The header carrying the Unix-millisecond timestamp. */
export const HEADER_TS = "x-msout-ts";
/** The header carrying the signature. */
export const HEADER_SIG = "x-msout-sig";

/**
 * signingString assembles the exact bytes both sides sign.
 *
 * The newlines are load-bearing separators. Without them a method and a path
 * could be chosen so that one request's field boundaries produce another's
 * string, which is why a body *digest* is included rather than the body.
 *
 * Exported so a test can assert the vector against the Go implementation.
 */
export function signingString(
  ts: string,
  method: string,
  path: string,
  body: Buffer,
): string {
  const digest = createHash("sha256").update(body).digest("hex");
  return `${ts}\n${method.toUpperCase()}\n${path}\n${digest}`;
}

/** computeSignature returns the base64url signature for a request. */
export function computeSignature(
  secret: string,
  ts: string,
  method: string,
  path: string,
  body: Buffer,
): string {
  return createHmac("sha256", secret)
    .update(signingString(ts, method, path, body), "utf8")
    .digest("base64url");
}

/** The five verbs. The orchestrator's entire surface; see PLAN-v3 §2.1. */
export type OrchestratorVerb =
  | "claim"
  | "release"
  | "recycle"
  | "remove"
  | "stat"
  | "stats"
  | "healthz";

/** A claim request body. Only identifiers — never an image or a flag. */
export interface ClaimBody {
  sessionGuid: string;
  sessionExpiresAtMs: number;
}

/** The claim response. */
export interface ClaimResponse {
  slotId: string;
  containerId: string;
}

/** The stat response — the download authoriser's only question. */
export interface StatResponse {
  exists: boolean;
  size: number;
}

/** Pool occupancy, from GET /stats. */
export interface OrchestratorStats {
  size: number;
  byState: Record<string, number>;
  runnerTtlSeconds: number;
}

/** Errors the orchestrator's HTTP surface can produce, as typed results. */
export type OrchestratorResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: OrchestratorError };

/** An orchestrator failure, classified so callers can react correctly. */
export type OrchestratorError =
  | { readonly kind: "unauthorized"; readonly status: number }
  | { readonly kind: "pool-exhausted" }
  | { readonly kind: "conflict"; readonly status: number }
  | { readonly kind: "unreachable"; readonly cause: string }
  | { readonly kind: "unexpected"; readonly status: number; readonly body: string };

/** Options for the client. */
export interface OrchestratorClientOptions {
  /** Base URL, e.g. http://orchestrator:9100. Validated at config load. */
  baseUrl: string;
  /** The HMAC secret. Held only here. */
  secret: string;
  /** Replay window, for the error the orchestrator would return. */
  replayWindowSeconds?: number;
  /** Per-request timeout. */
  timeoutMs?: number;
  /** Injected for tests. */
  fetchImpl?: typeof fetch;
  /** Injected for tests, so the timestamp is deterministic. */
  now?: () => Date;
}

/**
 * OrchestratorClient signs and sends internal calls.
 *
 * Every method maps the orchestrator's status codes onto a typed result rather
 * than throwing, because the callers care about the distinction: pool exhaustion
 * is a 503 the api turns into a wait estimate, a conflict is a stale view the api
 * re-reads, and unauthorized is a clock or secret problem that should page
 * someone.
 */
export class OrchestratorClient {
  readonly #baseUrl: string;
  readonly #secret: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;
  readonly #now: () => Date;

  constructor(options: OrchestratorClientOptions) {
    this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#secret = options.secret;
    this.#timeoutMs = options.timeoutMs ?? 15_000;
    this.#fetch = options.fetchImpl ?? fetch;
    this.#now = options.now ?? (() => new Date());
  }

  /**
   * call signs and sends one request.
   *
   * The body is serialised once and the same bytes are signed and sent, so a
   * mismatch between what was signed and what was transmitted is not possible.
   */
  async #call<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<OrchestratorResult<T>> {
    const payload =
      body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), "utf8");
    const ts = String(this.#now().getTime());
    const sig = computeSignature(this.#secret, ts, method, path, payload);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);

    try {
      // Built conditionally rather than with `body: undefined`, because
      // exactOptionalPropertyTypes treats an explicit undefined as a different
      // value from an absent key and `RequestInit.body` does not accept it.
      const init: RequestInit = {
        method,
        headers: {
          [HEADER_TS]: ts,
          [HEADER_SIG]: sig,
          ...(payload.length > 0
            ? { "content-type": "application/json", "content-length": String(payload.length) }
            : {}),
        },
        signal: controller.signal,
      };
      if (payload.length > 0) {
        init.body = payload;
      }

      const response = await this.#fetch(`${this.#baseUrl}${path}`, init);

      const text = await response.text();

      if (response.status === 401 || response.status === 400) {
        return { ok: false, error: { kind: "unauthorized", status: response.status } };
      }
      if (response.status === 503) {
        return { ok: false, error: { kind: "pool-exhausted" } };
      }
      if (response.status === 409) {
        return { ok: false, error: { kind: "conflict", status: 409 } };
      }
      if (!response.ok) {
        return {
          ok: false,
          error: { kind: "unexpected", status: response.status, body: text.slice(0, 200) },
        };
      }

      return { ok: true, value: (text === "" ? {} : JSON.parse(text)) as T };
    } catch (error) {
      if (controller.signal.aborted) {
        return {
          ok: false,
          error: { kind: "unreachable", cause: `timed out after ${this.#timeoutMs}ms` },
        };
      }
      return {
        ok: false,
        error: { kind: "unreachable", cause: (error as Error).message },
      };
    } finally {
      clearTimeout(timer);
    }
  }

  /** claim takes an idle slot and binds it to a session. */
  claim(
    sessionGuid: string,
    sessionExpiresAt: Date,
  ): Promise<OrchestratorResult<ClaimResponse>> {
    return this.#call<ClaimResponse>("POST", "/claim", {
      sessionGuid,
      sessionExpiresAtMs: sessionExpiresAt.getTime(),
    } satisfies ClaimBody);
  }

  /** release returns a slot and destroys its container. */
  release(slotId: string): Promise<OrchestratorResult<{ released: boolean }>> {
    return this.#call("POST", "/release", { slotId });
  }

  /** recycle replaces a container that outlived the runner TTL. */
  recycle(slotId: string, reason: string): Promise<OrchestratorResult<{ recycled: boolean }>> {
    return this.#call("POST", "/recycle", { slotId, reason });
  }

  /** remove tears a slot down entirely. */
  remove(slotId: string): Promise<OrchestratorResult<{ removed: boolean }>> {
    return this.#call("POST", "/remove", { slotId });
  }

  /**
   * stat reports whether an artifact exists.
   *
   * This is the call that lets the api decide download authorisation from SQLite
   * without any filesystem access to the artifact tree (PLAN-v3 §2.2). The
   * artifactId is validated before it is sent, so a malformed id cannot become a
   * path in the orchestrator.
   */
  stat(artifactId: string): Promise<OrchestratorResult<StatResponse>> {
    return this.#call<StatResponse>("POST", "/stat", { artifactId });
  }

  /** stats reports pool occupancy. */
  stats(): Promise<OrchestratorResult<OrchestratorStats>> {
    return this.#call("GET", "/stats");
  }

  /** healthz checks the orchestrator's liveness and reconciliation result. */
  healthz(): Promise<OrchestratorResult<{ ok: boolean; pool: OrchestratorStats }>> {
    return this.#call("GET", "/healthz");
  }
}