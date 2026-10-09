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
  /**
   * The slot to take, when this process has already claimed one.
   *
   * Sent because `claimRunner` claims a **SQLite row** and the slot's identity *is*
   * that row's id — `release` and `recycle` take it straight back. Without this field
   * the orchestrator picked an idle slot independently, at random, and the two
   * routinely disagreed. Observed on a real host:
   *
   *     runners: slot-1  status=active  runner_url=http://msout-runner-slot-2:3100
   *     /stats : slotIds=["slot-2"]  byState={"bound":1}
   *
   * — a slot recorded as active carrying another slot's address, and no slot-1
   * container anywhere.
   *
   * **A lock on a row that is not the thing being locked is not a lock.** That is the
   * whole argument for this process choosing rather than the orchestrator.
   *
   * Omitted when there is no claim to honour, so the call still works against an
   * orchestrator that has not shipped the field.
   */
  slotId?: string;
}

/** The claim response. */
export interface ClaimResponse {
  slotId: string;
  containerId: string;
  /**
   * Where the runner in this slot is reachable — the credential path.
   *
   * `api` posts the password here, so this is the one value it must not have to
   * construct. A runner is addressed by a network alias derived from the *slot*,
   * not the container, so it stays correct when `recycle` replaces the container
   * underneath it; that is why it is stored once at claim time and reused for the
   * life of the session rather than re-fetched.
   *
   * Optional for the same reason `stats().slotIds` is: a rolling deploy may reach
   * an orchestrator that predates the field. Absent means "this orchestrator does
   * not say", and the caller must refuse rather than guess — see
   * `runnerAddress`.
   */
  readonly runnerUrl?: string;
}

/** The stat response — the download authoriser's only question. */
export interface StatResponse {
  exists: boolean;
  size: number;
}

/** What `/finalize` reports about what it published. */
export interface FinalizeResponse {
  artifactId: string;
  /** `vault.zip`, or `vault.partial.zip`. The name a download dialog will show. */
  archiveName: string;
  bytes: number;
  partial: boolean;
}

/** What a finalise is asked to publish. */
export interface FinalizeInput {
  /** The api's opaque id, 43 base64url characters. Becomes the published directory. */
  readonly artifactId: string;
  /** The session whose vault is being published. Never appears in the published path. */
  readonly sessionGuid: string;
  /**
   * The truth about the export, which only the api knows.
   *
   * The orchestrator trusts this for *labelling only* — it selects the
   * `.partial.zip` name and writes the marker — because it never saw the walk and
   * cannot check. So the caller passing `false` for a truncated vault gets an
   * unmarked archive, and the only honest source of this bit is the side that
   * observed whether the export finished.
   */
  readonly partial: boolean;
}

/** Pool occupancy, from GET /stats. */
export interface OrchestratorStats {
  size: number;
  byState: Record<string, number>;
  runnerTtlSeconds: number;
  /**
   * The orchestrator's own names for its slots.
   *
   * Optional because the two components are deployed independently, and a new api
   * will briefly talk to an orchestrator that predates this field. An absent list
   * means "this orchestrator cannot tell me its slot names", and the caller treats
   * that as an unseedable pool rather than as an empty one — see `syncPool`.
   */
  readonly slotIds?: readonly string[];

  /**
   * Why the last pool top-up failed, when it did.
   *
   * Optional because an orchestrator predating the field simply does not report it.
   * Absent is **not** read as "healthy": a pool with no idle slot and no reported
   * fault is still a pool that cannot currently serve anyone, and the distinction
   * this enables is between "wait" and "escalate", not between "working" and
   * "broken".
   */
  readonly fillError?: string;

  /** Consecutive failed top-up attempts, when there has been one. */
  readonly fillFailures?: number;
}

/** Errors the orchestrator's HTTP surface can produce, as typed results. */
export type OrchestratorResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: OrchestratorError };

/** An orchestrator failure, classified so callers can react correctly. */
export type OrchestratorError =
  | { readonly kind: "unauthorized"; readonly status: number }
  | { readonly kind: "pool-exhausted"; readonly fillError?: string }
  | { readonly kind: "conflict"; readonly status: number }
  | { readonly kind: "unreachable"; readonly cause: string }
  | { readonly kind: "unexpected"; readonly status: number; readonly body: string };

/**
 * OrchestratorApi is the surface `api` needs from the orchestrator.
 *
 * A structural interface rather than the concrete `OrchestratorClient`, for one
 * reason: `api` holds no Docker socket and must never do container work itself, so
 * what it needs is six calls and nothing more. Naming that surface makes the
 * authority explicit and lets a local mock satisfy it without inheriting signing
 * code it would never use.
 *
 * The real client is the only production implementation. It is also the only
 * implementation that signs anything — which is why this interface has no
 * `secret` and no way to make an unsigned call.
 */
export interface OrchestratorApi {
  claim(
    sessionGuid: string,
    sessionExpiresAt: Date,
    slotId?: string,
  ): Promise<OrchestratorResult<ClaimResponse>>;
  release(slotId: string): Promise<OrchestratorResult<{ released: boolean }>>;
  recycle(slotId: string, reason: string): Promise<OrchestratorResult<{ recycled: boolean }>>;
  remove(slotId: string): Promise<OrchestratorResult<{ removed: boolean }>>;
  stat(artifactId: string): Promise<OrchestratorResult<StatResponse>>;
  stats(): Promise<OrchestratorResult<OrchestratorStats>>;
  healthz(): Promise<OrchestratorResult<{ ok: boolean; pool: OrchestratorStats }>>;
  /**
   * finalize publishes a staged archive under its artifact id.
   *
   * PLAN-v3 §2.2 splits publishing in two: the runner streams the zip into a
   * staging directory, and the orchestrator — the only holder of the artifact
   * volume — renames it into place. Without this call the archive exists only
   * under `.staging/`, which `ArtifactStat` skips and Caddy never serves, so a
   * completed export is not downloadable.
   *
   * A `409` here means **nothing was staged**, which is not the same as a
   * transport failure: the runner never streamed an archive. Callers must treat
   * it as an export that produced no artifact rather than retrying.
   */
  finalize(input: FinalizeInput): Promise<OrchestratorResult<FinalizeResponse>>;
}

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
export class OrchestratorClient implements OrchestratorApi {
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
        // Carry the orchestrator's reason through, when it reported one. A 503
        // without it is a pool that is merely full; a 503 with it is a pool that
        // cannot fill at all, and the two call for different user-facing advice.
        let fillError: string | undefined;
        try {
          const parsed = JSON.parse(text) as { fillError?: unknown };
          if (typeof parsed.fillError === "string" && parsed.fillError !== "") {
            fillError = parsed.fillError;
          }
        } catch {
          // A 503 with an unparseable body is still a 503. No fillError, so it
          // reads as the plain case.
        }
        // Built conditionally rather than with an explicit `undefined`, because
        // `exactOptionalPropertyTypes` treats `fillError: undefined` as a
        // different value from an absent key — and "the orchestrator did not
        // report a reason" must stay distinguishable from "the reason is empty".
        return fillError === undefined
          ? { ok: false, error: { kind: "pool-exhausted" } }
          : { ok: false, error: { kind: "pool-exhausted", fillError } };
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
    slotId?: string,
  ): Promise<OrchestratorResult<ClaimResponse>> {
    return this.#call<ClaimResponse>("POST", "/claim", {
      sessionGuid,
      sessionExpiresAtMs: sessionExpiresAt.getTime(),
      ...(slotId === undefined ? {} : { slotId }),
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

  /**
   * finalize renames a staged archive into its published location.
   *
   * The whole operation is one `os.Rename` on the orchestrator's side, so its cost
   * does not depend on the vault's size — the reason a multi-gigabyte archive can
   * be published atomically rather than copied.
   *
   * `partial` is forwarded rather than recomputed. See `FinalizeInput.partial`:
   * the orchestrator cannot verify it and deliberately does not try.
   */
  finalize(input: FinalizeInput): Promise<OrchestratorResult<FinalizeResponse>> {
    return this.#call<FinalizeResponse>("POST", "/finalize", {
      artifactId: input.artifactId,
      sessionGuid: input.sessionGuid,
      partial: input.partial,
    });
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