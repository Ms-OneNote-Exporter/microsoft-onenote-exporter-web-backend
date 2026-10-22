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

/**
 * The budget for the four verbs whose server-side work is a container lifecycle.
 *
 * `claim`, `release`, `recycle` and `remove` are the **slowest** calls in this
 * surface, not the fast ones, and 15 s — the shared default — was shorter than the
 * work they ask for. A claim on a *warm* pool first destroys the idle runner, and
 * that is `StopContainer` with a 10-second SIGTERM grace, before anything is
 * created. Ten seconds of stop grace alone put the claim at the edge of the old
 * budget, and two of three attempts breached it: the api aborted, the
 * orchestrator's in-flight Docker calls died with the request context, and the api
 * compensated by releasing its SQLite row. The user saw a failed login, twice.
 *
 * The derivation, which is the whole reason this is a named constant:
 *
 *     10s   stop grace before SIGKILL          (orchestrator pool.destroy)
 *     ~2s   create + start                     (orchestrator start)
 *     45s   waiting for the healthcheck        (RunnerReadyTimeout, not env-settable)
 *     ---
 *     ~57s  the orchestrator's own worst case
 *
 * So the client budget must sit **above** it, and **below** the server's
 * `WriteTimeout`, which must sit above it too: 75 s here, 90 s there. A legitimate
 * claim then always completes before the client gives up, and a wedged one is still
 * bounded on both sides.
 *
 * This constant is the one place that agreement is written down. The api cannot
 * read the orchestrator's configuration, and the orchestrator cannot read the
 * api's — which is exactly how a 15 s budget came to sit below a 60 s server that
 * sat below 57 s of real work.
 *
 * `stat`, `stats`, `healthz` and `finalize` keep the 15 s default: they are all
 * fast, and a long budget on a wedged read would hold a request open for nothing.
 */
export const CONTAINER_VERB_TIMEOUT_MS = 75_000;

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
  /**
   * How many slots are in each pool state: `{"idle": 2}`, `{"idle": 1, "bound": 1}`.
   *
   * **Keys are present only for states that currently hold at least one slot.** Go's
   * `Stats` counts with `byState[string(s.State)]++` over every slot, so a state with
   * zero slots contributes *no key* — not a `0`. Read the live body from the deployed
   * host (pool of two, nobody using it): `{"size":2,"byState":{"idle":2},…}`. There is
   * no `bound` key in it, and `bound: 0` would have been a different response.
   *
   * That absence is what makes this field load-bearing rather than descriptive. The
   * sweeper repairs a session stuck `exporting` whose slot nobody holds, and
   * `boundSessions` — the field that names *which* slots are held — is `omitempty`, so
   * on an all-idle pool it is absent entirely and the repair could not be reached from
   * it. This map can: **no `bound` key is positive evidence that no slot is bound to
   * any session**, because that is the same response that counted zero `StateBound`
   * slots. `poolBindsNobody` in `sweep.ts` is the reader, and the state names it
   * accepts are pinned by `POOL_STATE_NAMES` there — a renamed state makes it refuse
   * to answer rather than read the renamed word as "nothing is bound".
   *
   * Required, and not for the reason the optional fields above are optional: `ByState`
   * has carried no `omitempty` since before this api existed, so a body without it is
   * malformed rather than old. Nothing here rolls back with a deploy.
   */
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
   * Which slots are **bound**, and to which session: `{ "slot-1": "<guid>" }`.
   *
   * `byState` answers "how many are bound", which is not the same question. A slot
   * held for a session that no longer existed was indistinguishable from a slot
   * doing work, and only this process can tell them apart — it owns the session
   * rows. Observed on the deployed host: two slots on a pool of two held by
   * sessions whose rows were gone, so `EnsurePool` saw a full pool and every login
   * 409'd until someone restarted the orchestrator.
   *
   * Optional for the same reason `slotIds` is: a rolling deploy briefly pairs this
   * api with an orchestrator that predates the field. Absent means "this
   * orchestrator does not say", which reads as "no orphans to look for" — today's
   * behaviour, with no regression. The field is omitted entirely when nothing is
   * bound, so an idle pool marshals exactly as it did before it existed.
   */
  readonly boundSessions?: Readonly<Record<string, string>>;

  /**
   * Bound slots whose container the orchestrator has seen die: `["slot-1"]`.
   *
   * `boundSessions` says a slot is *held*; nothing said whether the runner behind it
   * was still there. So a session whose export died with its container kept its row,
   * its `runner_id` and a `runners` row that all agreed the slot was fine — and
   * `POST /api/export` refused every future export with a 409 until the 12-hour
   * absolute cap, because the sweeper skips `exporting` sessions to protect live
   * ones. Only the orchestrator holds the Engine, so it is the only side that can
   * see this; only this process holds the session rows, so it is the only side that
   * can act on it.
   *
   * Optional for the same reason `slotIds` is: a rolling deploy briefly pairs this
   * api with an orchestrator that predates the field, and during that window the
   * absence is treated as `[]` — "this orchestrator reports none dead", which is
   * today's behaviour, with no regression. The field is omitted entirely when
   * nothing is dead, so a healthy pool marshals exactly as it did before it existed.
   *
   * Slot ids, never container ids: §2.1 restricts the api from holding container
   * identities it cannot verify, and a slot name is how it asks for a slot.
   */
  readonly deadSlots?: readonly string[];

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

  /**
   * Per-slot container age in seconds, keyed by slot id.
   *
   * Optional for rolling-deploy compatibility: a new api talking to an orchestrator
   * that predates this field will not see it. Absent means "this orchestrator does
   * not say", which reads as "no floor check" — today's behaviour, with no regression.
   *
   * The orchestrator already holds every fact behind this: `Slot.CreatedAt` is the
   * label-derived clock its reconciler already trusts, and `RunnerTTL` is its own
   * config. It was simply not saying.
   */
  readonly slotAgeSec?: Readonly<Record<string, number>>;

  /**
   * Per-slot remaining budget in seconds, keyed by slot id.
   *
   * `remainingSec = max(0, budgetSec - ageSec)`. Monotone non-increasing between
   * container replacements, so a reset is always a replacement and never a silence.
   *
   * Optional for the same reason `slotAgeSec` is. A slot is absent from the map when
   * it holds no container — there is no age to report for a container that does not
   * exist yet.
   */
  readonly slotRemainingSec?: Readonly<Record<string, number>>;
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
  /**
   * deleteArtifact removes a published artifact directory.
   *
   * The ninth verb, and the first one whose only argument is an **artifact id**
   * rather than a slot.
   *
   * ## Why it exists here rather than being done by the api
   *
   * `POST /api/session/erase` destroys three things on three hosts: the SQLite row
   * (here), the cookie (in the browser), and the vault directory plus the published
   * archive (on volumes this process does not have). PLAN-v3 §4.3 is the mount
   * split that puts the artifact tree behind Caddy and the orchestrator, and §4.4
   * makes the orchestrator the holder of it. So this process **cannot** delete
   * `/opt/msout/data/artifacts/<id>/` even if it wanted to — there is no path there
   * to open, and the mount is not its to open.
   *
   * That is the same reason `finalize` is a verb and not something the runner does
   * for itself, and the same reason `stat` is: the component that decides what
   * happens to an artifact is the one that owns the volume.
   *
   * ## Why erase needs it
   *
   * `finalize` renames a staged archive into `<artifactId>/vault.zip`, and until
   * this verb existed **nothing ever removed it**. The erase machine shredded the
   * session directory, removed the container and deleted the row, and the published
   * vault stayed on the volume for the life of the disk — while `ERASE_UI_WORDING`
   * told the user *"We deleted everything this service stored for this session."*
   *
   * Idempotent by contract: a not-found artifact is success, because erase is
   * best-effort and retried, and "the thing I was deleting is already gone" is the
   * outcome it wanted.
   */
  deleteArtifact(artifactId: string): Promise<OrchestratorResult<{ deleted: boolean }>>;
  /**
   * deleteSessionDir removes a session's vault directory.
   *
   * The tenth verb. Modelled on `/delete-artifact`: one validated GUID, joined to
   * a root the process owns.
   *
   * ## Why it exists
   *
   * The orchestrator's `bindSession` creates `/opt/msout/data/vault/<guid>/` and
   * nothing ever removes it. The runner's `DELETE /sessions/:guid` removes only
   * the inner `<guid>/` and the api has no mount of the vault at all.
   *
   * Idempotent by contract: a not-found directory is success.
   */
  deleteSessionDir(sessionGuid: string): Promise<OrchestratorResult<{ deleted: boolean }>>;
}

/** Options for the client. */
export interface OrchestratorClientOptions {
  /** Base URL, e.g. http://orchestrator:9100. Validated at config load. */
  baseUrl: string;
  /** The HMAC secret. Held only here. */
  secret: string;
  /** Replay window, for the error the orchestrator would return. */
  replayWindowSeconds?: number;
  /**
   * Per-request timeout, for the **read** verbs (`stat`, `stats`, `healthz`,
   * `finalize`).
   *
   * It deliberately does not apply to `claim`, `release`, `recycle` or `remove`:
   * those are sized by `CONTAINER_VERB_TIMEOUT_MS` from the orchestrator's own
   * worst case, which is a property of that server's work rather than of this
   * deployment. An option that could lower it below the work being asked for is the
   * bug this budget was introduced to fix, so those four ignore it.
   */
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
   *
   * `timeoutMs` defaults to the configured read budget; the four container verbs pass
   * `CONTAINER_VERB_TIMEOUT_MS` explicitly. It is a parameter rather than a second
   * client because the budget is a property of the *verb* — of the work the
   * orchestrator is asked to do — and a second client would be a second place for
   * that agreement to be written down wrongly.
   */
  async #call<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    timeoutMs: number = this.#timeoutMs,
  ): Promise<OrchestratorResult<T>> {
    const payload =
      body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), "utf8");
    const ts = String(this.#now().getTime());
    const sig = computeSignature(this.#secret, ts, method, path, payload);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

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
          error: { kind: "unreachable", cause: `timed out after ${timeoutMs}ms` },
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
    return this.#call<ClaimResponse>(
      "POST",
      "/claim",
      {
        sessionGuid,
        sessionExpiresAtMs: sessionExpiresAt.getTime(),
        ...(slotId === undefined ? {} : { slotId }),
      } satisfies ClaimBody,
      CONTAINER_VERB_TIMEOUT_MS,
    );
  }

  /** release returns a slot and destroys its container. */
  release(slotId: string): Promise<OrchestratorResult<{ released: boolean }>> {
    return this.#call("POST", "/release", { slotId }, CONTAINER_VERB_TIMEOUT_MS);
  }

  /**
   * recycle replaces a container that outlived the runner TTL.
   *
   * Same budget as the other container verbs and for the same reason: a timed-out
   * `/remove` is exactly what makes erase retain its row, so the verb that destroys
   * a container is the last one that should be cut short.
   */
  recycle(slotId: string, reason: string): Promise<OrchestratorResult<{ recycled: boolean }>> {
    return this.#call("POST", "/recycle", { slotId, reason }, CONTAINER_VERB_TIMEOUT_MS);
  }

  /** remove tears a slot down entirely. */
  remove(slotId: string): Promise<OrchestratorResult<{ removed: boolean }>> {
    return this.#call("POST", "/remove", { slotId }, CONTAINER_VERB_TIMEOUT_MS);
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

  /**
   * deleteArtifact removes a published artifact directory.
   *
   * The read budget, not `CONTAINER_VERB_TIMEOUT_MS`: the work is an
   * `os.RemoveAll` under the artifact root, sized by neither the pool nor a
   * container. It is called from the erase machine, which is holding a session's
   * cookie open, so it must not inherit the 75 s a container lifecycle needs.
   */
  deleteArtifact(artifactId: string): Promise<OrchestratorResult<{ deleted: boolean }>> {
    return this.#call("POST", "/delete-artifact", { artifactId });
  }

  /**
   * deleteSessionDir removes a session's vault directory.
   *
   * The read budget, not `CONTAINER_VERB_TIMEOUT_MS`: the work is an
   * `os.RemoveAll` under the vault root, sized by neither the pool nor a container.
   * It is called from the erase machine, which is holding a session's cookie open,
   * so it must not inherit the 75 s a container lifecycle needs.
   */
  deleteSessionDir(sessionGuid: string): Promise<OrchestratorResult<{ deleted: boolean }>> {
    return this.#call("POST", "/delete-session-dir", { sessionGuid });
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