/**
 * The real `RunnerAdapter`: `api` → a runner container.
 *
 * This is the wiring that unblocks sign-in. Before it, `POST
 * /api/session/credential` answered 501 — a real session was created, a real
 * cookie was set, the live-update stream attached, and the login could not
 * complete past the password field.
 *
 * ## The four routes, and what each is for
 *
 *   POST /sessions/:guid/login       the credential, as bytes
 *   POST /sessions/:guid/notebooks   list
 *   POST /sessions/:guid/exports     export
 *   POST /sessions/:guid/exports/:id/abort
 *   GET  /events?guid=               what happened, as SSE
 *
 * ## The credential is forwarded as a stream, never buffered
 *
 * The `RequestInit` carries the capped stream directly, so the password is read
 * from the socket and written to the socket without ever existing as a value in
 * this process. That is the property the whole credential path is built around,
 * and it is why `submitCredential` takes a `Readable` and not a `string`.
 *
 * Three things that would silently break it, and are asserted in the tests
 * rather than left to review:
 *
 *   - **No `JSON.stringify` on the body.** This project shipped that bug from
 *     both ends: the frontend turned `hunter2` into `"hunter2"`, and `capStream`
 *     once cut a body before it began. Both presented as "wrong password".
 *   - **No string conversion.** `Buffer.from(await streamToBuffer(...))` is
 *     byte-equivalent but makes the credential a value. `passwordFrom` in the
 *     runner already refuses to hand back a string for exactly this reason.
 *   - **The account travels as a header**, so the body stays byte-identical to
 *     what the browser sent. Putting both in one body needs a delimiter, and a
 *     delimiter is another place for the truncation bug this pair has shipped
 *     twice.
 *
 * ## The address comes from the orchestrator, never from here
 *
 * `resolve()` is given the `runnerUrl` the claim response carried, and refuses
 * anything else. An adapter that constructed a container name, or took a URL from
 * configuration, would be a second implementation of the orchestrator's naming —
 * and two implementations sharing one convention is where every serious bug in
 * this project has been. See `orchestrator/internal/pool.runnerAlias`.
 *
 * The URL is validated against the alias shape anyway, because a field crossing a
 * process boundary is untrusted input regardless of who produced it. A value that
 * does not name this stack's own runner is a misconfiguration or an attack, and
 * both deserve a refusal rather than a connection attempt.
 *
 * ## What this does not implement, and says so
 *
 * **Answering a `challenge` of kind `code`.** The runner waits 120 seconds and
 * then fails; there is no route to hand it a typed code, and the api has no UI to
 * collect one. Rather than let that present as a login that mysteriously
 * succeeds-with-nothing, `unsupportedChallenge` is raised where a caller can see
 * it and a test asserts the refusal. The number-match path — push approval, the
 * common case — needs nothing from the user and works.
 *
 * Building that route is a deliberate separate piece of work: a runner route, an
 * adapter method, an api route, and a frontend screen. Doing it here would make
 * this change unreviewable and would put a new UI in the stack while the
 * credential path is still unproven.
 */

import type { Readable as ReadableType } from "node:stream";
import type {
  RunnerAdapter,
  StartExportInput,
  AbortExportInput,
  SubmitCredentialInput,
  PublishArtifactInput,
} from "./runner-adapter.js";
import type { SseHub } from "./sse.js";

/** The header the runner requires on every route but `/healthz`. */
export const RUNNER_TOKEN_HEADER = "x-runner-token";

/**
 * RUNNER_ALIAS_PATTERN matches the alias the orchestrator registers.
 *
 * `msout-runner-` plus a Docker-safe name. The slot ids it generates are the only
 * thing that should ever appear here, so the shape is narrow on purpose: a
 * `runnerUrl` that does not match is refused rather than dialled.
 */
const RUNNER_ALIAS_PATTERN = /^http:\/\/msout-runner-[a-zA-Z0-9][a-zA-Z0-9_.-]*:\d{1,5}$/;

/** Why a call to a runner could not be made. */
export type RunnerCallFailure =
  /** No address: the orchestrator did not report one for this slot. */
  | "no-address"
  /** The address was not one this stack's own runners use. */
  | "bad-address"
  /** The runner refused the token. */
  | "unauthorised"
  /** The runner is holding a job; another request must wait. */
  | "busy"
  /** No runner is bound, or it has no auth state for this call. */
  | { readonly kind: "not-ready"; readonly reason: "no_auth" | "no_output" | "conflict" }
  /** The runner answered, but not with success. */
  | { readonly kind: "rejected"; readonly status: number; readonly error: string }
  /** The connection failed, or timed out. */
  | { readonly kind: "unreachable"; readonly cause: string };

export class RunnerCallError extends Error {
  readonly failure: RunnerCallFailure;
  constructor(failure: RunnerCallFailure, message: string) {
    super(message);
    this.name = "RunnerCallError";
    this.failure = failure;
  }
}

/**
 * What a terminal export event tells the rest of the api.
 *
 * Carries the counts because they are the only record of what the export produced,
 * and `finishedAt` is set from the moment of completion rather than reconstructed.
 */
export interface ExportFinishedInput {
  readonly sessionId: string;
  /** The api's opaque artifact id, echoed back from `startExport`. */
  readonly artifactId: string;
  /**
   * Whether the export stopped short.
   *
   * True for `export-partial` and for an `export-done` that followed an abort. This
   * is the bit `/finalize` trusts for labelling and cannot check, so it is derived
   * here from what the runner actually reported.
   */
  readonly partial: boolean;
  /** Why, when partial. `null` for a clean finish. */
  readonly partialReason: "aborted" | "quota" | "disk" | null;
  readonly notebook: string;
  readonly progress: { readonly pages: number; readonly sections: number; readonly assets: number } | null;
  /** When the export finished, in epoch milliseconds. */
  readonly finishedAt: number;
}

/** Options for the adapter. */
export interface HttpRunnerAdapterOptions {
  /**
   * The address of a bound session's runner, or null when none is known.
   *
   * Injected rather than computed here: the api already stored what the
   * orchestrator's claim response said, and re-deriving it would be the second
   * implementation this module exists to avoid.
   */
  readonly addressFor: (sessionId: string) => string | null;
  /** The bearer token. Held here and nowhere else in this process. */
  readonly token: string;
  /** The hub runner events are republished into. */
  readonly sse: SseHub;
  /**
   * Called when the runner reports the *outcome* of a login: `authenticated`, or
   * `failed`.
   *
   * Injected as a narrow callback rather than a `Db` handle, because this module is
   * transport: it knows the runner's wire format and nothing about storage. It was
   * missing precisely because the adapter had no way to say anything except "forward
   * this to the browser" — so `login-success` reached the frontend while the database
   * went on saying `authenticating`, and the two routes that need `valid` refused a
   * session that had really authenticated.
   *
   * Optional so that a caller which does not care about persisted state (the mock,
   * some tests) does not have to supply one.
   */
  readonly onAuthOutcome?: (
    sessionId: string,
    outcome: "authenticated" | "failed",
  ) => void;
  /**
   * Called with the account's notebook names when a listing completes.
   *
   * Present for the same reason as `onAuthOutcome`: this module is transport, and
   * "remember it" is somebody else's job. The names go to the session row because the
   * api publishes this field on **two** routes, and a value that exists on only one of
   * them is a value that disappears the next time the client reads the other.
   *
   * Optional, for the same reason: a caller with no store to write to does not have to
   * supply one.
   */
  readonly onNotebooksListed?: (sessionId: string, names: readonly string[]) => void;
  /**
   * Called when an export reaches a terminal outcome, with the truth about it.
   *
   * ## This is the callback that was missing, and it is why the export never arrived
   *
   * `login-success` and `notebooks-listed` each had one, and each wrote a column the
   * api reads back. `export-done` had neither: the frame was published to the SSE hub
   * and **discarded**. So a runner could export a vault to completion — bytes on
   * disk, `export-done` on the wire, the right numbers in the payload — and the
   * database would keep saying `state: "running"`, `finishedAt: null`,
   * `artifact.available: false` until the session expired.
   *
   * The test that let this ship asserted the **event** arrived. Nothing asserted the
   * row changed. Same shape as the two credential bugs this repository's tests were
   * explicitly rewritten to catch: the handler ran, the transport was fine, and the
   * thing a user depends on was never written.
   *
   * ## `partial` is the api's claim, not the orchestrator's
   *
   * The orchestrator's `/finalize` selects the `.partial.zip` name and writes the
   * marker, and it **cannot verify** this bit — it never saw the walk. So it is
   * forwarded as whatever the side that watched the export believes, and that is
   * why the field exists here rather than being re-derived downstream.
   *
   * May be async: publishing an artifact is slow (it zips the vault), and the
   * adapter must not block the event pump waiting for it. Failures are caught and
   * logged rather than thrown — a failed publish must not kill the stream and lose
   * every subsequent event. Await `drain()` to observe them.
   */
  readonly onExportFinished?: (input: ExportFinishedInput) => Promise<void> | void;
  /** Per-request timeout. Logins and exports return immediately, so this is short. */
  readonly timeoutMs?: number;
  /**
   * Clock, injected so `finishedAt` is deterministic in tests.
   *
   * Set once per terminal event, from the moment the api observes it — not from
   * the runner, which does not send a timestamp, and not reconstructed from the
   * stored `startedAt`. An export that ran for four minutes must say it finished
   * now, not four minutes ago.
   */
  readonly now?: () => number;
  /** Injected for tests. */
  readonly fetchImpl?: typeof fetch;
}

/**
 * The runner's wire format, as it actually is.
 *
 * `formatSse` in `runner/src/events.ts` is the authority, and it writes:
 *
 *     id: <seq>\ndata: <the event object itself>\n\n
 *
 * — the event inline in `data`, with **no** `{seq, event}` envelope. That is not
 * what this api's own `formatEvent` writes, which uses a separate `event:` line,
 * and it is worth being explicit about because the first version of this parser
 * assumed an envelope and silently dropped every event: the frame parsed fine,
 * `parsed.data` was `undefined`, and `publish` was handed nothing. The login
 * would have appeared to hang with the runner reporting success.
 *
 * A boundary whose two sides disagree about the wire format fails exactly this
 * way — quietly, with every log line saying the right thing.
 */
interface RunnerWireEvent {
  readonly type?: unknown;
  [key: string]: unknown;
}


/** Options for one call. */
interface CallOptions {
  readonly method: "GET" | "POST" | "DELETE";
  readonly path: string;
  readonly sessionId: string;
  /** JSON body, or nothing. Never used for the credential. */
  readonly json?: unknown;
  /** Raw body, for the credential. Mutually exclusive with `json`. */
  readonly stream?: ReadableType;
  /** Raw body headers, for the credential. */
  readonly headers?: Readonly<Record<string, string>>;
  /**
   * Overrides the adapter's default timeout for this one call.
   *
   * Exists for exactly one caller — `publishArtifact` — and the reason it is a
   * per-call field rather than a second adapter is that the default is correct for
   * every control verb in this file. Raising the default to accommodate archiving
   * would mean a wedged runner could hold a *login* open for thirty minutes.
   */
  readonly timeoutMs?: number;
}

export class HttpRunnerAdapter implements RunnerAdapter {
  readonly #addressFor: (sessionId: string) => string | null;
  readonly #token: string;
  readonly #sse: SseHub;
  readonly #onAuthOutcome:
    | ((sessionId: string, outcome: "authenticated" | "failed") => void)
    | undefined;
  readonly #onNotebooksListed:
    | ((sessionId: string, names: readonly string[]) => void)
    | undefined;
  readonly #onExportFinished: ((input: ExportFinishedInput) => Promise<void> | void) | undefined;
  readonly #now: () => number;
  /**
   * Artifact publishes still in flight, so `drain()` can wait for them.
   *
   * Tracked rather than fired and forgotten because a publish is the only step of
   * an export that outlives the request that started it: the export runs for
   * minutes, then zipping it runs for minutes more, and nothing is holding a
   * promise. Without this, shutting the api down mid-publish loses an archive the
   * runner has already written and the orchestrator has already been told about.
   */
  readonly #publishing = new Set<Promise<void>>();
  /**
   * Artifact ids whose publish has been started, so a second terminal event for the
   * same export is a duplicate rather than new work.
   *
   * Bounded by session lifetime rather than pruned, and that is deliberate: it
   * holds at most a handful of ids for a session whose absolute TTL is twelve
   * hours, and a prune policy would be a way to lose the protection without
   * gaining anything. Cleared with the pumps, in `stopAll`.
   */
  readonly #published = new Set<string>();
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;
  /** One event stream per session, so a reconnect does not double-deliver. */
  readonly #pumps = new Map<string, AbortController>();
  /** The runner's last sequence number seen per session, for gap-free resume. */
  readonly #seq = new Map<string, number>();
  /**
   * The address each live pump is currently attached to.
   *
   * Not derivable from `#pumps` alone, and not derivable by re-reading
   * `addressFor`: that reads the session's *current* runner, which is the whole
   * point — it cannot report where the open stream is actually pointed. See
   * `ensurePump`.
   */
  readonly #pumpAddress = new Map<string, string>();

  constructor(options: HttpRunnerAdapterOptions) {
    this.#addressFor = options.addressFor;
    this.#token = options.token;
    this.#sse = options.sse;
    this.#onAuthOutcome = options.onAuthOutcome;
    this.#onNotebooksListed = options.onNotebooksListed;
    this.#onExportFinished = options.onExportFinished;
    this.#now = options.now ?? Date.now;
    this.#timeoutMs = options.timeoutMs ?? 15_000;
    this.#fetch = options.fetchImpl ?? fetch;
  }

  /**
   * drain waits for every artifact publish in flight to settle.
   *
   * Never rejects: a publish that failed has already logged the reason, and a
   * shutdown path that threw on it would replace a clear log line with an
   * unhandled rejection.
   */
  async drain(): Promise<void> {
    while (this.#publishing.size > 0) {
      await Promise.allSettled([...this.#publishing]);
    }
  }

  /**
   * call signs nothing and sends one request.
   *
   * The token is a bearer header rather than the orchestrator's signed pair,
   * which is a real difference in strength and worth stating: this call does not
   * cross a network the api does not already control. The runner is on one
   * internal network whose only other member is this process, so there is no
   * replay window to defend — an attacker who can capture this header is already
   * inside that network, and is holding a container this api created.
   */
  async #call(options: CallOptions): Promise<unknown> {
    const raw = this.#addressFor(options.sessionId);
    if (raw === null || raw === "") {
      throw new RunnerCallError(
        "no-address",
        "no runner address for this session; the orchestrator did not report one",
      );
    }
    // Validated even though the orchestrator produced it. A value crossing a
    // process boundary is untrusted input regardless of provenance, and the cost
    // of being wrong here is a request carrying a password somewhere unexpected.
    if (!RUNNER_ALIAS_PATTERN.test(raw)) {
      throw new RunnerCallError(
        "bad-address",
        "the runner address is not one this stack's own runners use",
      );
    }

    const controller = new AbortController();
    // Read once, so the timeout in force is the one the error message names. The
    // message quotes `this.#timeoutMs` today and would quote the wrong number for
    // an archiving call — an operator reading "timed out after 10000ms" on a
    // thirty-minute zip has been told something false.
    const budgetMs = options.timeoutMs ?? this.#timeoutMs;
    const timer = setTimeout(() => controller.abort(), budgetMs);

    // Spelled as the type of the field rather than `BodyInit`, which is a DOM
    // type this project does not include: it compiles only with `lib: DOM`, and
    // adding that to reach one name would put every browser global in scope of a
    // service that must never use one.
    type RequestBody = NonNullable<RequestInit["body"]>;

    let body: RequestBody | undefined;
    const headers: Record<string, string> = {
      [RUNNER_TOKEN_HEADER]: this.#token,
      accept: "application/json",
    };
    if (options.stream !== undefined) {
      // The stream, unconverted. See the header comment. The cast is because a
      // Node `Readable` is not a DOM `BodyInit`; undici accepts it, and this is
      // the one place a stream is allowed to cross into a fetch call.
      body = options.stream as unknown as RequestBody;
      // `duplex: "half"` is required by undici for a streaming request body and
      // its absence is a TypeError at the first write — so it is set here rather
      // than discovered on the credential path.
      Object.assign(headers, { ...(options.headers ?? {}) });
      headers["content-type"] = options.headers?.["content-type"] ?? "text/plain";
    } else if (options.json !== undefined) {
      const encoded = Buffer.from(JSON.stringify(options.json), "utf8");
      body = encoded;
      headers["content-type"] = "application/json";
      headers["content-length"] = String(encoded.length);
    }

    const init: RequestInit & { duplex?: string } = {
      method: options.method,
      headers,
      signal: controller.signal,
    };
    if (body !== undefined) init.body = body;
    if (options.stream !== undefined) init.duplex = "half";

    try {
      const response = await this.#fetch(`${raw}${options.path}`, init);
      const text = await response.text();

      if (response.ok) {
        return text === "" ? {} : (JSON.parse(text) as unknown);
      }

      // Every refusal is named, because "the login failed" has six causes and an
      // operator cannot tell them apart from a log line that says 500.
      throw await classify(response.status, text);
    } catch (cause) {
      if (cause instanceof RunnerCallError) throw cause;
      if (controller.signal.aborted) {
        throw new RunnerCallError(
          { kind: "unreachable", cause: `timed out after ${budgetMs}ms` },
          "the runner did not answer in time",
        );
      }
      throw new RunnerCallError(
        { kind: "unreachable", cause: (cause as Error).message },
        "could not reach the runner",
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * submitCredential hands the password over and starts the event pump.
   *
   * The pump is started *before* the call, deliberately. The runner publishes
   * `login-started` as it accepts the request, so a pump attached after the
   * response could miss events the runner already emitted — and the symptom would
   * be a login that works with no `challenge` shown and no failure, which is the
   * one outcome a user cannot act on.
   *
   * `login-started` on the api's own hub is emitted by the route, not here, so
   * there is exactly one of it.
   */
  async submitCredential(input: SubmitCredentialInput): Promise<void> {
    this.#ensurePump(input.sessionId);
    try {
      await this.#call({
        method: "POST",
        path: `/sessions/${encodeURIComponent(input.sessionId)}/login`,
        sessionId: input.sessionId,
        stream: input.stream,
        headers: {
          "content-type": "text/plain",
          // The account as a header, so the body is byte-identical. See header.
          "x-microsoft-account": input.account,
        },
      });
    } catch (cause) {
      // The pump exists for this session's login, which has not happened. Leaving
      // it running would leak a connection to a runner that has nothing to say.
      this.stopPump(input.sessionId);
      throw cause;
    }
  }

  /** listNotebooks asks the runner to enumerate, reporting the result on the hub. */
  async listNotebooks(sessionId: string): Promise<void> {
    this.#ensurePump(sessionId);
    await this.#call({
      method: "POST",
      path: `/sessions/${encodeURIComponent(sessionId)}/notebooks`,
      sessionId,
    });
  }

  /** startExport begins an export and streams its progress onto the hub. */
  async startExport(input: StartExportInput): Promise<void> {
    this.#ensurePump(input.sessionId);
    try {
      await this.#call({
        method: "POST",
        path: `/sessions/${encodeURIComponent(input.sessionId)}/exports`,
        sessionId: input.sessionId,
        json: {
          // The api's id, echoed on every export event. The runner does not
          // invent one — it does not know what a session is.
          id: input.exportId,
          // Exactly one target, and the runner's route rejects a body carrying
          // both — because it has to choose, and a caller that supplied both would
          // be relying on which one it picked.
          ...(input.notebookUrl !== undefined
            ? { notebookUrl: input.notebookUrl }
            : { notebook: input.notebook }),
        },
      });
    } catch (cause) {
      // An abort signal on the caller's side is the user cancelling, not a
      // transport failure, and the route turns it into a `export-partial`.
      if (input.signal.aborted) throw cause;
      throw cause;
    }
  }

  /** abortExport cancels a running export. The runner keeps what it wrote. */
  async abortExport(input: AbortExportInput): Promise<void> {
    await this.#call({
      method: "POST",
      path: `/sessions/${encodeURIComponent(input.sessionId)}/exports/${encodeURIComponent(
        input.exportId,
      )}/abort`,
      sessionId: input.sessionId,
    });
  }

  /**
   * publishArtifact asks the runner to stream the finished vault into staging.
   *
   * The artifact id travels in the **body**, never in the path: it is the api's
   * own opaque id, and the runner validates it against the 43-base64url rule before
   * it becomes a directory name. That is a shape check, not sanitisation — "reject
   * anything that is not exactly 43 base64url characters" is a smaller and more
   * obviously complete rule than stripping the wrong characters out.
   *
   * ## The long timeout is not a guess
   *
   * This call zips a vault that may be several gigabytes on a 2-CPU VPS, while
   * every other call in this adapter is a fast control verb that returns 202
   * immediately. Sharing the 10-second default would abort almost every real
   * export *at the archiving step* — after the work succeeded — and the user would
   * be told their export failed when it is sitting complete in staging. So it gets
   * its own budget, and it is deliberately generous rather than tight: the cost of
   * this call exceeding it is a timeout, and the cost of setting it too low is a
   * completed export reported as a failure.
   */
  async publishArtifact(input: PublishArtifactInput): Promise<void> {
    await this.#call({
      method: "POST",
      path: `/sessions/${encodeURIComponent(input.sessionId)}/artifacts`,
      sessionId: input.sessionId,
      json: { artifactId: input.artifactId },
      // 30 minutes. An export itself is already bounded by the runner's own export
      // timeout, so this only has to outlast the *archiving* of what it produced.
      timeoutMs: 30 * 60 * 1000,
    });
  }

  /**
   * finishExport hands a terminal export to the injected completion callback.
   *
   * Fire-and-forget by design, and the reason is a timing constraint rather than a
   * convenience: `readEvents` awaits `#handleFrame` on the reader loop, so anything
   * awaited here would stop the pump consuming frames until the publish finished.
   * Zipping a multi-gigabyte vault takes minutes, and every event after it — the
   * abort a user clicks, the `export-partial` that explains what happened — would
   * sit unread behind it.
   *
   * So it is started, tracked in `#publishing`, and its failure is reported rather
   * than thrown. Throwing here would be worse than dropping it: `#handleFrame` runs
   * inside `#pump`'s try, so a rejection would tear down the event stream and lose
   * every subsequent event for this session too.
   *
   * Duplicate suppression lives here rather than in the callback, because this is
   * the only place that knows both events arrived: the runner publishes
   * `export-aborted` **and** `export-partial` for one cancellation, and a naive
   * handler would zip and finalise the same vault twice.
   */
  #finishExport(input: ExportFinishedInput): void {
    const callback = this.#onExportFinished;
    if (callback === undefined) return;

    // One publish per artifact id. The second terminal event for the same export is
    // a duplicate of the first, not new work.
    if (this.#published.has(input.artifactId)) return;
    this.#published.add(input.artifactId);

    const task = (async () => {
      await callback(input);
    })();
    this.#publishing.add(task);
    void task
      .catch((cause: unknown) => {
        this.#reportPublishFailure(cause, input);
      })
      .finally(() => {
        this.#publishing.delete(task);
      });
  }

  /**
   * reportPublishFailure surfaces a publish that did not complete.
   *
   * On the session's own event stream, because that is the one channel that needs
   * no new plumbing and that the client is already listening to: a user whose
   * export finished but could not be downloaded is otherwise told nothing, and the
   * session sits at `done` with no artifact and no explanation.
   *
   * The message names what failed and why. "Export failed" here would be a lie —
   * the walk succeeded — and it would send the user to re-run hours of work over a
   * problem that is about archiving, not exporting.
   */
  #reportPublishFailure(cause: unknown, input: ExportFinishedInput): void {
    const detail = cause instanceof Error ? cause.message : String(cause);
    this.#sse.emit(input.sessionId, "error", {
      id: input.artifactId,
      message:
        "The export finished, but the file could not be published for download. " +
        `Nothing was lost and you do not need to export again: ${detail}`,
    });
  }

  /**
   * abort stops whatever the runner is doing for a session.
   *
   * The erase machine calls this with no export id, because it is running when an
   * export may or may not exist and asking would mean querying state the runner
   * owns. So it goes to the session rather than to a job: the runner's abort route
   * is idempotent and answers 409 when nothing is running, and a 409 here means
   * the thing erase wanted to stop was not running — which is the outcome it
   * wanted, not a failure.
   */
  async abortAny(sessionId: string): Promise<void> {
    try {
      await this.#call({
        method: "POST",
        path: `/sessions/${encodeURIComponent(sessionId)}/exports/erase/abort`,
        sessionId,
      });
    } catch (cause) {
      if (cause instanceof RunnerCallError && cause.failure === "busy") {
        // Nothing running: there is nothing left to abort.
        return;
      }
      if (
        cause instanceof RunnerCallError &&
        typeof cause.failure === "object" &&
        cause.failure.kind === "not-ready" &&
        cause.failure.reason === "conflict"
      ) {
        return;
      }
      throw cause;
    }
  }

  /**
   * shredDirectory asks the runner to remove a session's files.
   *
   * This process has no mount of the vault and could not do it — §2.1 is the
   * reason. The runner's `DELETE /sessions/:guid` removes the directory, and the
   * container that mounted it is destroyed by the orchestrator moments later, so
   * there is nothing left either way.
   *
   * Not called `shred`: that promises a secure overwrite, which depends on CoW,
   * SSD wear levelling and the filesystem underneath, and this call does not
   * choose any of those. Naming it `shred` would be the kind of claim that reads
   * as a guarantee and is not one.
   */
  async removeSessionDir(sessionId: string): Promise<void> {
    this.stopPump(sessionId);
    await this.#call({
      method: "DELETE",
      path: `/sessions/${encodeURIComponent(sessionId)}`,
      sessionId,
    });
  }

  /**
   * stopPump closes a session's event stream and forgets where it was pointing.
   *
   * ## Why the sequence cursor goes with it
   *
   * `since` is a cursor into **one runner's** event log, and the runner numbers
   * that log per process — `runner/src/events.ts` holds a `private seq = 0` on the
   * hub, not a global counter. A freshly created runner therefore starts its own
   * log at 1, and `history()` answers with `ring.filter((e) => e.seq > since)`.
   *
   * Carry a cursor of, say, 47 from the previous runner and that filter returns
   * **nothing** — while `gap` evaluates **false**, because 47 is greater than the
   * new ring's oldest. The api would be handed a clean, complete-looking, empty
   * stream and would wait for an `export-done` that can never arrive. That is bug
   * #54 again with the stream in the right place.
   *
   * So the cursor is per runner, not per session, and does not outlive the address
   * it was read from.
   *
   * ## Callers
   *
   * Erase (`removeSessionDir`), a credential handoff that failed before the
   * session ever logged in, shutdown and the tests. **Not** the sweeper's release
   * paths, which null `runner_id` and leave the stream in place — see the note on
   * `ensurePump`, which is what makes that survivable.
   */
  stopPump(sessionId: string): void {
    const controller = this.#pumps.get(sessionId);
    if (controller === undefined) return;
    this.#pumps.delete(sessionId);
    this.#seq.delete(sessionId);
    this.#pumpAddress.delete(sessionId);
    controller.abort();
  }

  /** stopAll closes every stream. For shutdown and for tests. */
  stopAll(): void {
    for (const sessionId of [...this.#pumps.keys()]) this.stopPump(sessionId);
    this.#published.clear();
  }

  /**
   * ensurePump guarantees this session has a stream attached to **its current
   * runner**, opening one if there is none and re-pointing one that has gone
   * stale.
   *
   * The re-point is the load-bearing half. Every caller — the credential,
   * notebook and export routes alike — reaches the runner through here, so
   * putting the check in this one function means a session that has been
   * released and rebound is healed by whichever route it next touches, rather
   * than by a call at each site remembering to say so. Four callers, one
   * invariant, and a fifth added later inherits it.
   *
   * This is deliberately the *general* form of the fix rather than a wiring at
   * the rebind call site: the failure was never that one route forgot, it was
   * that no component knew which runner a live pump was pointed at. Only this
   * function can compare that against the session's current runner.
   */
  #ensurePump(sessionId: string): void {
    const current = this.#addressFor(sessionId);

    // No runner known: leave any live pump alone. `null` is the sweeper's release
    // saying "this session has no runner *right now*", and the sweeper does not
    // stop the pump when it releases. Treating that as licence to tear the stream
    // down would destroy a stream that may be one frame away from delivering
    // `export-done` — a second instance of the bug this exists to fix. `#call`
    // throws `no-address` a moment later and the route answers it.
    if (current === null || current === "") return;

    if (this.#pumps.has(sessionId)) {
      // Still on the runner this stream was opened against. Returning here is what
      // stops a reconnect from double-delivering.
      if (this.#pumpAddress.get(sessionId) === current) return;

      // The session has moved. The open stream is pointed at a runner that no
      // longer holds it and will never deliver the events that matter; aborting
      // is what stops it leaking a connection, and its own cleanup cannot run
      // unguarded because it would delete the entry created below (see `#pump`).
      this.stopPump(sessionId);
    }

    const controller = new AbortController();
    this.#pumps.set(sessionId, controller);
    void this.#pump(sessionId, controller);
  }

  /**
   * pump subscribes to one session's runner event stream and republishes onto the
   * api's hub.
   *
   * Two implementations, one wire format: the runner writes
   * `id: <seq>\ndata: <json>` with the event type *inside* the JSON, while this
   * process's own `formatEvent` writes `event: <type>` as a separate line. So
   * the runner's stream is parsed here rather than by the api's SSE helpers, and
   * the type is read out of the payload.
   *
   * `since` is carried across reconnects, and the runner answers a replay that
   * cannot be complete with an explicit gap. That gap is forwarded rather than
   * papered over: a stream that looks continuous while missing the middle is
   * worse than one that admits a hole, because the user has no way to tell which
   * one they are looking at.
   */
  async #pump(sessionId: string, controller: AbortController): Promise<void> {
    const signal = controller.signal;
    const address = this.#addressFor(sessionId);
    if (address === null || address === "") {
      this.#clearPump(sessionId, controller);
      return;
    }

    // Recorded so `ensurePump` can tell "still on the runner this stream was
    // opened against" from "the session has moved and this stream is stale".
    this.#pumpAddress.set(sessionId, address);

    let attempt = 0;
    while (!signal.aborted) {
      const since = this.#seq.get(sessionId) ?? 0;
      let url: URL;
      try {
        url = new URL(`/events?guid=${encodeURIComponent(sessionId)}&since=${since}`, address);
      } catch {
        this.#clearPump(sessionId, controller);
        return;
      }

      try {
        const response = await this.#fetch(url, {
          headers: { [RUNNER_TOKEN_HEADER]: this.#token, accept: "text/event-stream" },
          signal,
        });
        if (!response.ok || response.body === null) {
          throw new Error(`event stream answered ${response.status}`);
        }
        // Reset only once the stream is accepted, so a runner that is up but
        // refusing does not spin at full rate.
        attempt = 0;
        await this.#readEvents(sessionId, response.body, signal);
      } catch (cause) {
        if (signal.aborted) break;
        attempt += 1;
        // Bounded and slow. A runner that is gone — released, recycled, erased —
        // will never answer, and a reconnect loop at full rate would be a
        // connection-per-second leak against a component that is not there.
        const delay = Math.min(1000 * 2 ** Math.min(attempt, 5), 30_000);
        await sleep(delay, signal).catch(() => {});
      }
    }
    if (signal.aborted) this.#clearPump(sessionId, controller);
  }

  /**
   * clearPump removes this pump's bookkeeping, but **only if it is still the owner**.
   *
   * `ensurePump` aborts a stale pump and immediately creates a replacement for
   * the same session. The aborted pump's retry loop then wakes, sees
   * `signal.aborted`, and runs its own exit path — which used to delete the map
   * entry by session id alone. It would delete the *new* pump's entry, and the
   * next call would open a third stream, delivering every event twice. That is
   * precisely what `#pumps` exists to prevent, and it is the same shape as §0.9.8:
   * two deleters of one piece of state and nothing to tell them apart.
   *
   * Comparing controllers is what tells them apart.
   */
  #clearPump(sessionId: string, controller: AbortController): void {
    if (this.#pumps.get(sessionId) !== controller) return;
    this.#pumps.delete(sessionId);
    this.#pumpAddress.delete(sessionId);
  }

  /**
   * readEvents consumes one SSE body and republishes what it carries.
   *
   * Reads the body through `getReader()` rather than `for await`, because
   * `Response.body` is a web `ReadableStream` and not a Node `Readable`. Node
   * makes the web stream async-iterable as a convenience, but that convenience is
   * not in the TypeScript lib this project compiles against, so the explicit
   * reader is what type-checks and it is also the form that works on every
   * runtime the api's `engines` allows.
   *
   * The reader is released on the way out. Leaving it locked keeps the underlying
   * connection open, and this is a long-lived stream that is expected to be torn
   * down — on abort, or when a session is erased.
   */
  async #readEvents(
    sessionId: string,
    body: ReadableStream<Uint8Array>,
    signal: AbortSignal,
  ): Promise<void> {
    const decoder = new TextDecoder();
    let buffer = "";
    const reader = body.getReader();

    try {
      for (;;) {
        // Abort is checked before each read as well as by the fetch signal: the
        // signal rejects the fetch, but a pump stopped between frames should not
        // wait for the next one to arrive.
        if (signal.aborted) return;
        const { done, value } = await reader.read();
        if (done) return;
        if (value === undefined) continue;

        buffer += decoder.decode(value, { stream: true });
        // Frames are separated by a blank line. Anything after the last one is a
        // partial frame and stays in the buffer for the next chunk — a frame
        // split across two TCP reads is normal, and treating a partial frame as
        // complete would produce JSON that fails to parse.
        let split = buffer.indexOf("\n\n");
        while (split !== -1) {
          const frame = buffer.slice(0, split);
          buffer = buffer.slice(split + 2);
          this.#handleFrame(sessionId, frame);
          split = buffer.indexOf("\n\n");
        }
      }
    } finally {
      // Cancel rather than merely release, so the socket is closed instead of
      // left half-read.
      reader.cancel().catch(() => {});
    }
  }

  /** handleFrame reads one SSE frame and publishes it, field by field. */
  #handleFrame(sessionId: string, frame: string): void {
    let data: string | null = null;
    let id: string | null = null;
    for (const line of frame.split("\n")) {
      // A comment line is a keepalive: `:` prefix, no field name.
      if (line === "" || line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      if (colon === -1) continue;
      const field = line.slice(0, colon);
      const value = line.slice(colon + 1).replace(/^ /, "");
      if (field === "data") data = (data === null ? "" : data + "\n") + value;
      else if (field === "id") id = value;
    }
    if (data === null) return;

    let parsed: RunnerWireEvent;
    try {
      parsed = JSON.parse(data) as RunnerWireEvent;
    } catch {
      // A frame that is not JSON is not a session claim. Refused rather than
      // guessed at — the alternative is a malformed event reaching a browser.
      this.#sse.emit(sessionId, "error", { message: "unreadable runner event" });
      return;
    }

    if (typeof id === "string" && /^[0-9]+$/.test(id)) {
      this.#seq.set(sessionId, Number(id));
    }

    // The event *is* the parsed object — see the wire-format note above. A frame
    // with no `type` is not something to publish, and dropping it is the honest
    // outcome: this process's event union is closed, and a name nobody can render
    // is not a claim worth making.
    if (typeof parsed !== "object" || parsed === null) return;
    const raw = parsed as Record<string, unknown>;
    const type = typeof raw.type === "string" ? raw.type : "";

    // The runner's gap signal, forwarded rather than hidden.
    if (type === "error" && typeof raw.message === "string" && raw.message.startsWith("gap:")) {
      this.#sse.emit(sessionId, "error", { message: raw.message });
      return;
    }

    const published = publish(
      this.#sse,
      sessionId,
      raw,
      this.#onAuthOutcome,
      this.#onNotebooksListed,
      (input) => this.#finishExport(input),
      this.#now,
    );
    if (published === "challenge-code") {
      // Reported, not silently dropped and not silently accepted. See the header:
      // there is no route to answer a typed code and pretending otherwise would
      // leave the user watching a login that cannot finish.
      this.#sse.emit(sessionId, "login-failed", {
        reason: "challenge-not-supported",
        message: unsupportedChallenge,
      });
    }
  }
}

/**
 * unsupportedChallenge is what a user is told when Microsoft asks for a typed
 * code.
 *
 * Named rather than generic because "sign-in failed" for an account that works
 * everywhere else is the most confusing message this product can produce. This
 * one says which part is missing and nothing else.
 */
export const unsupportedChallenge =
  "this account needs a sign-in code, which this service does not collect yet. " +
  "Approve the push notification instead, or use an account without a code prompt.";

/**
 * publish maps one runner event onto the api's own vocabulary and emits it.
 *
 * Returns `"challenge-code"` when a `challenge` of kind `code` arrived, so the
 * caller can react to the one kind it cannot carry.
 *
 * Field-by-field with a type check on each, because this is the seam where two
 * implementations of one contract meet and every serious bug in this project has
 * been at exactly this line. An event whose shape does not match is dropped
 * rather than passed through as `unknown`.
 */
function publish(
  sse: SseHub,
  sessionId: string,
  raw: Record<string, unknown>,
  onAuthOutcome?: (sessionId: string, outcome: "authenticated" | "failed") => void,
  onNotebooksListed?: (sessionId: string, names: readonly string[]) => void,
  onExportFinished?: (input: ExportFinishedInput) => void,
  now: () => number = Date.now,
): "published" | "dropped" | "challenge-code" {
  const str = (key: string): string => (typeof raw[key] === "string" ? (raw[key] as string) : "");
  const num = (key: string): number =>
    typeof raw[key] === "number" && Number.isFinite(raw[key] as number) ? (raw[key] as number) : 0;
  const nullableStr = (key: string): string | null =>
    typeof raw[key] === "string" ? (raw[key] as string) : null;

  /**
   * progress reads the runner's counts-so-far, which is all an in-flight export has.
   *
   * Null when the payload carried nothing usable, so the stored `progress` reads
   * "unknown" rather than a confident `{pages: 0, sections: 0, assets: 0}` — a
   * zero that was never measured is a different fact from a measured zero.
   */
  const progress = (): ExportFinishedInput["progress"] => {
    const p = (typeof raw.progress === "object" && raw.progress !== null ? raw.progress : {}) as Record<
      string,
      unknown
    >;
    const has = ["pages", "sections", "assets"].some((k) => typeof p[k] === "number");
    if (!has) return null;
    return {
      pages: typeof p.pages === "number" ? p.pages : 0,
      sections: typeof p.sections === "number" ? p.sections : 0,
      assets: typeof p.assets === "number" ? p.assets : 0,
    };
  };

  /**
   * partialReason validates the runner's reason against the three the api stores.
   *
   * Same reasoning as `parseExportState`: a stored value outside the union would
   * leave the client with a state it has no rendering for, and `partial` with an
   * unknown reason is the one case where guessing a message would be wrong.
   */
  const partialReason = (): "aborted" | "quota" | "disk" | null => {
    const r = str("reason");
    return r === "aborted" || r === "quota" || r === "disk" ? r : null;
  };

  switch (raw.type) {
    case "login-started":
      // Not emitted: the route emits this on its own hub, so forwarding it would
      // give the browser two of them.
      return "dropped";

    case "challenge": {
      const kind = str("kind");
      if (kind === "code") {
        sse.emit(sessionId, "challenge", {
          kind,
          label: str("label"),
          expiresAt: nullableStr("expiresAt"),
        });
        return "challenge-code";
      }
      // `number` is the phone-approval code, and it is the whole reason the
      // number-match path is worth supporting: a headless login has no Microsoft
      // window to read it from.
      sse.emit(sessionId, "challenge", {
        kind,
        label: str("label"),
        number: nullableStr("number"),
        expiresAt: nullableStr("expiresAt"),
      });
      return "published";
    }

    case "login-success":
      sse.emit(sessionId, "login-success", {});
      // Recorded **before** the return, and not after it: the caller needs to know the
      // session is authenticated whether or not anyone was listening on the SSE hub.
      // A missed write here is a 409 on every subsequent route for this session, and
      // the frontend would have seen `login-success` and believed otherwise.
      onAuthOutcome?.(sessionId, "authenticated");
      return "published";

    case "login-failed":
      sse.emit(sessionId, "login-failed", { reason: str("reason") || "unknown" });
      onAuthOutcome?.(sessionId, "failed");
      return "published";

    case "notebooks-listed": {
      const list = Array.isArray(raw.notebooks) ? raw.notebooks : [];

      // **The shape here is the snapshot's shape, and that is the whole point.**
      //
      // This used to emit `{notebooks: [{name, url}, …]}`. The client reads
      // `{state, items: string[]}` — the same shape `GET /api/session/status` already
      // returns for this field — so every notebook was parsed into an empty list:
      //
      //     data.state → undefined → "loaded"
      //     data.items → absent   → []
      //
      // No error, no warning, three notebooks found by the runner and nothing on
      // screen. Found by clicking the button: the api logged `202` and the runner
      // logged `Found 3 notebooks!`, and the user reported the button did nothing.
      //
      // The fix belongs here rather than in the client because **this** was the
      // deviant: the api already publishes one shape for this field on the REST route
      // and a second on the event stream, and a contract with two versions is not a
      // contract. Now there is one, and it is the one the client already parses.
      //
      // `items` are **names**, because that is what `POST /api/export` takes — a
      // notebook name — and what the client's `NotebookList.items` is typed as. The
      // runner's `url` is deliberately not forwarded: nothing reads it, and inventing
      // a field would make the next reader hunt for a consumer that does not exist.
      const items: string[] = [];
      for (const entry of list) {
        const n = (typeof entry === "object" && entry !== null ? entry : {}) as Record<
          string,
          unknown
        >;
        const name = typeof n.name === "string" ? n.name.trim() : "";
        // A nameless notebook cannot be exported by name and cannot be shown, so it
        // is dropped here rather than rendered as a blank row the user cannot click.
        if (name !== "") items.push(name);
      }
      sse.emit(sessionId, "notebooks-listed", { state: "loaded", items });
      onNotebooksListed?.(sessionId, items);
      return "published";
    }

    case "notebooks-failed":
      sse.emit(sessionId, "error", { message: "notebook listing failed", reason: str("reason") });
      return "published";

    case "export-started":
    case "export-progress":
    case "export-log":
    case "export-done":
    case "export-partial":
    case "export-aborted": {
      const type = raw.type;
      const id = str("id");
      if (id === "") return "dropped";
      if (type === "export-progress") {
        const p = (
          typeof raw.progress === "object" && raw.progress !== null ? raw.progress : {}
        ) as Record<string, unknown>;
        sse.emit(sessionId, "export-progress", {
          id,
          progress: {
            pages: typeof p.pages === "number" ? (p.pages as number) : 0,
            sections: typeof p.sections === "number" ? (p.sections as number) : 0,
            assets: typeof p.assets === "number" ? (p.assets as number) : 0,
          },
        });
      } else if (type === "export-done") {
        sse.emit(sessionId, "export-done", {
          id,
          notebook: str("notebook"),
          pages: num("pages"),
          sections: num("sections"),
          assets: num("assets"),
        });
        // **This call is the fix.** Before it, `export-done` was published to the
        // hub and nothing else happened: no zip, no finalise, no row written. The
        // session therefore reported `running` with `finishedAt: null` forever,
        // and `artifact.available` stayed false, because both are read from the
        // database and this event never reached it.
        //
        // The counts are forwarded rather than re-derived, so what the user is
        // shown is what the exporter actually walked.
        onExportFinished?.({
          sessionId,
          artifactId: id,
          partial: false,
          partialReason: null,
          notebook: str("notebook"),
          progress: progress(),
          finishedAt: now(),
        });
      } else if (type === "export-log") {
        sse.emit(sessionId, "export-log", { id, line: str("line") });
      } else if (type === "export-partial") {
        sse.emit(sessionId, "export-partial", { id, reason: str("reason") || "aborted" });
        // A partial vault is still a vault the user may want — §8.2 preserves what
        // is on disk — so it is **published, labelled partial**, rather than skipped.
        // The label is the orchestrator's to write and it cannot verify this bit,
        // which is exactly why it is forwarded from the side that watched the walk.
        onExportFinished?.({
          sessionId,
          artifactId: id,
          partial: true,
          partialReason: partialReason(),
          notebook: str("notebook"),
          progress: progress(),
          finishedAt: now(),
        });
      } else if (type === "export-aborted") {
        sse.emit(sessionId, "export-aborted", { id });
      } else {
        sse.emit(sessionId, "export-started", { id });
      }
      return "published";
    }

    case "error":
      sse.emit(sessionId, "error", { message: str("message") || "runner error" });
      return "published";

    default:
      // An event type this process has never heard of. Dropped, because
      // forwarding it would put a name on the wire that no frontend has a
      // renderer for — and the hub's type union is closed on purpose.
      return "dropped";
  }
}

/** classify turns a non-2xx runner response into a named failure. */
async function classify(status: number, text: string): Promise<RunnerCallError> {
  let parsed: { error?: unknown } = {};
  try {
    parsed = JSON.parse(text) as { error?: unknown };
  } catch {
    parsed = {};
  }
  const error = typeof parsed.error === "string" ? parsed.error : "";

  switch (status) {
    case 401:
      return new RunnerCallError("unauthorised", "the runner refused the token");
    case 409:
      // The three 409 bodies the runner sends, kept apart because they call for
      // different behaviour: two are "come back later", one is "this session is
      // not ready and waiting will not fix it".
      if (error === "no_auth") {
        return new RunnerCallError(
          { kind: "not-ready", reason: "no_auth" },
          "the runner has no auth state for this session",
        );
      }
      if (error === "busy") {
        return new RunnerCallError("busy", "the runner is holding another job");
      }
      if (error === "no_output") {
        return new RunnerCallError(
          { kind: "not-ready", reason: "no_output" },
          "the runner has nothing to archive",
        );
      }
      return new RunnerCallError(
        { kind: "not-ready", reason: "conflict" },
        `the runner refused the request: ${error || "conflict"}`,
      );
    default:
      return new RunnerCallError(
        { kind: "rejected", status, error: error || text.slice(0, 200) },
        `the runner answered ${status}`,
      );
  }
}

/** sleep that resolves early on abort, so a stopping pump does not wait. */
function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}