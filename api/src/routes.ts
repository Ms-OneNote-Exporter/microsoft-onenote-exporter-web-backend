/**
 * The routes.
 *
 * Registered on the Fastify instance built in server.ts. Every mutating route has
 * already been authenticated and CSRF-checked by the `onRequest` hook, so a
 * handler here can read `request.ctx.session` without repeating those checks —
 * and cannot accidentally skip them.
 *
 * Two rules the handlers follow:
 *
 *   - A handler never returns a field the plan does not name. The snapshot shape
 *     is `SessionSnapshot` in auth.ts, which is the single definition of the
 *     cross-component contract.
 *   - A handler that cannot do its job returns 501 rather than pretending. The
 *     routes that need the runner or the artifact pipeline are not wired yet, and
 *     a 501 says that honestly where a stub returning `{}` would look like a bug.
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Readable } from "node:stream";

import type { ApiConfig } from "./config.js";
import type { Db, SessionRow } from "./db.js";
import type { OrchestratorApi } from "./orchestrator-client.js";
import type { SseHub } from "./sse.js";
import type { RateLimiter } from "./rate-limit.js";
import {
  API_BUILD,
  PROTOCOL_VERSION,
  buildSnapshot,
  sanitiseExportError,
  GENERIC_EXPORT_ERROR,
} from "./auth.js";
import { serialiseCookie, sessionCookie } from "./cookies.js";
import { header as headerValue } from "./server.js";
import { ACCOUNT_HEADER, MAX_ACCOUNT_CHARS } from "./credentials-header.js";
import {
  deriveCsrfToken,
  generateArtifactId,
  generateCsrfKey,
  hashSecret,
} from "./session.js";
import {
  checkFraming,
  capStream,
  contentTypeIsAcceptable,
  MAX_CREDENTIAL_BYTES,
} from "./credential.js";
import { resolveClientAddress } from "./client-ip.js";
import { readJsonObject } from "./server.js";
import { expireCookieHeaders, runErase, type EraseDeps } from "./erase.js";
import type { RunnerAdapter } from "./runner-adapter.js";
import type { PoolBinder } from "./sweep.js";

/**
 * Where a session's runner is.
 *
 * Null means no runner is bound to that session, which is a normal state: a
 * session that has not logged in yet, or whose runner has been released.
 */
export type RunnerAddressLookup = (sessionId: string) => string | null;

/**
 * Dependencies the routes need beyond config.
 *
 * Mutable only so `buildServer` can assemble it conditionally under
 * `exactOptionalPropertyTypes`; nothing mutates it afterwards.
 */
export interface RouteDeps {
  readonly db: Db;
  readonly orchestrator: OrchestratorApi;
  readonly sse: SseHub;
  readonly limiter: RateLimiter;
  knownProxies?: ReadonlySet<string>;
  eraseRunner?: EraseDeps["runner"];
  /**
   * The route to a runner container. Supplied by the entrypoint, or by a mock —
   * see runner-adapter.ts. Absent means 501.
   */
  runner?: RunnerAdapter;
  /**
   * Where a bound session's runner is, if it is known.
   *
   * The adapter reads this rather than deriving an address, because the
   * orchestrator named the runner and only the orchestrator knows how. It is a
   * separate dependency from `runner` so a test can drive the adapter's HTTP
   * surface while asserting that the address comes from the claim response.
   */
  runnerAddresses?: RunnerAddressLookup;
  /**
   * Binds a session to a container on demand.
   *
   * Absent until the entrypoint wires it, and absent whenever the pool manager
   * should not be claiming anything — the unwired state answers 409, unchanged.
   */
  poolBinder?: PoolBinder;
  now?: () => number;
}

/**
 * EXPORT_STATES is the export state union, validated on read.
 *
 * Checking membership rather than trusting the column means a corrupt or
 * hand-edited value cannot put the client in a state it has no rendering for —
 * the same reason the snapshot's parser tolerates garbage.
 */
const EXPORT_STATES = new Set(["none", "queued", "running", "done", "partial", "failed"]);


/**
 * parseJsonObject reads a body as a plain object with unknown fields rejected.
 *
 * Unknown fields are refused rather than ignored so a caller cannot come to
 * believe it set something the server read. This is the same rule the
 * orchestrator applies, for the same reason.
 */
async function parseJsonObject(
  request: FastifyRequest,
  limitBytes = 64 * 1024,
  allowedKeys?: readonly string[],
): Promise<Record<string, unknown> | null> {
  const parsed = await readJsonObject(request.body as Readable, limitBytes);
  if (parsed === null || allowedKeys === undefined) return parsed;

  // Unknown fields are refused rather than ignored, for the same reason the
  // orchestrator does it: a caller that sends `image` and gets a 201 would
  // reasonably conclude it was set. The route names the keys it reads, and this
  // checks the body against that list.
  for (const key of Object.keys(parsed)) {
    if (!allowedKeys.includes(key)) return null;
  }
  return parsed;
}

/** asString returns a field as a string, or undefined. */
function asString(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * artifactIdFromHeader extracts an artifact id from an original-request URI.
 *
 * This is untrusted input. The header arrives from a proxy, but a proxy is not the
 * only thing that can set a header — and the point of the endpoint is to decide
 * whether bytes leave the disk, so a permissive parse here is the whole risk.
 *
 * Therefore: the path must be exactly `/files/<id>` with nothing else, and the id
 * must be exactly the 43 base64url characters `generateArtifactId` produces. No
 * prefix matching, no "take the last segment", no `decodeURIComponent` — a
 * traversal survives all three and none of them is needed here.
 *
 * Returns null for anything else, and the caller denies.
 */
export function artifactIdFromHeader(originalUri: string | undefined): string | null {
  if (originalUri === undefined) return null;

  // Caddy may be configured to send an absolute URI rather than a path. The path
  // is what matters, and reading it off a parsed URL is safer than slicing.
  let path = originalUri;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(originalUri)) {
    try {
      path = new URL(originalUri).pathname;
    } catch {
      return null;
    }
  }

  // A query string is not part of the identity and a fragment never is.
  const queryAt = path.indexOf("?");
  if (queryAt !== -1) path = path.slice(0, queryAt);
  const hashAt = path.indexOf("#");
  if (hashAt !== -1) path = path.slice(0, hashAt);

  const match = /^\/files\/([A-Za-z0-9_-]{43})$/.exec(path);
  return match?.[1] ?? null;
}

/**
 * classifyExportFailure maps a thrown error onto one of the classifications
 * `sanitiseExportError` knows.
 *
 * It reads a `reason` property when the runner adapter provides one, and otherwise
 * returns null — which becomes the generic message. That default is deliberate: a
 * vague message, not a guessed one. Guessing `disk` from a string that merely
 * contains the word "space" would tell a user to free disk when the real problem
 * was a quota, and "free some space and try again" is precisely the advice that
 * wastes a user's time when it is wrong.
 *
 * Kept beside the route rather than in auth.ts because this is the only place that
 * knows what an adapter throws — and adding a classification here is a decision to
 * show that cause to a user.
 */
function classifyExportFailure(error: unknown): string | null {
  if (error === null || typeof error !== "object") return null;
  const reason = (error as { reason?: unknown }).reason;
  return typeof reason === "string" ? reason : null;
}

/** registerRoutes attaches every route to the instance. */
export function registerRoutes(app: FastifyInstance, config: ApiConfig, deps: RouteDeps): void {
  const now = deps.now ?? (() => Date.now());
  const knownProxies = deps.knownProxies ?? new Set<string>();
  const ttlSeconds = config.sessionTtlHours * 3600;

  // ---- GET /api/public/version -------------------------------------------

  // §7.2: the protocol handshake. Named in server.ts's PUBLIC_PATHS so the hook
  // leaves it unauthenticated — a client checks the version before it has a
  // session, and refusing it would break the thing that diagnoses a version skew.
  app.get("/api/public/version", async (_request, reply) =>
    reply.send({ protocol: PROTOCOL_VERSION, build: API_BUILD }),
  );

  // ---- POST /api/session --------------------------------------------------

  // Exempt from the authentication hook, because there is no session yet. The
  // hook skips it by exact path.
  app.post("/api/session", async (request, reply) => {
    // Through `header()`, not `request.headers.origin` directly. A repeated
    // Origin arrives as `string[]`, and `has(array)` is false — which fails
    // closed but disagrees with the deliberate repeated-header handling in the
    // hook. mac caught the inconsistency.
    const origin = headerValue(request, "origin");
    if (origin !== undefined && !config.allowedOrigins.has(origin)) {
      return reply.code(403).send({ error: "forbidden" });
    }

    const body = await parseJsonObject(request, 64 * 1024, ["guid", "secret"]);
    if (body === null) {
      return reply.code(400).send({ error: "malformed request body" });
    }

    const guid = asString(body.guid);
    const secret = asString(body.secret);

    // Validated mechanically rather than trusted. Under the split the secret is
    // generated by Component A, and a compromised frontend could generate a weak
    // one (PLAN-v3 §4, T9).
    if (guid === undefined || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(guid)) {
      return reply.code(400).send({ error: "guid must be a lowercase uuid" });
    }
    if (secret === undefined || !/^[A-Za-z0-9_-]{43}$/.test(secret)) {
      return reply
        .code(400)
        .send({ error: "secret must be exactly 43 base64url characters" });
    }

    // Rate limited per address: three sessions an hour stops an address farming
    // sessions to burn the runner pool.
    const client = resolveClientAddress({
      peerAddress: request.ip,
      forwardedFor: typeof request.headers["x-forwarded-for"] === "string"
        ? request.headers["x-forwarded-for"]
        : undefined,
      knownProxies,
    });
    const limited = deps.limiter.checkNewSession(client.address);
    if (!limited.allowed) {
      reply.header("retry-after", String(limited.retryAfterSeconds));
      return reply.code(429).send({ error: limited.reason, retryAfterSeconds: limited.retryAfterSeconds });
    }

    // The session already exists and this is a restore, not a creation: the
    // frontend generates the GUID and the secret once and may reload into the
    // same session. Re-creating would throw away a live auth.json, so an existing
    // valid row is left alone and its cookies re-issued.
    const existing = deps.db.getSession(guid);
    const timestamp = now();

    if (existing !== undefined && existing.expires_at > timestamp && existing.secret_hash !== null) {
      // Verify the presented secret against the existing row before re-issuing
      // cookies, or this becomes a way to take over a session by guessing its GUID.
      if (existing.secret_hash !== hashSecret(secret)) {
        return reply.code(401).send({ error: "unauthorised" });
      }
      const existingToken =
        existing.csrf_key === null ? "" : deriveCsrfToken(existing.csrf_key, guid);
      return reply
        .code(200)
        .header("set-cookie", [serialiseCookie(sessionCookie(`${guid}:${secret}`, ttlSeconds))])
        // The token comes back in the body, not in a readable cookie. See the
        // file header in cookies.ts for why: the frontend is on a different host,
        // so `document.cookie` there cannot see a cookie set by this origin.
        .send({ protocol: PROTOCOL_VERSION, csrfToken: existingToken });
    }

    const csrfKey = generateCsrfKey();
    const expiresAt = timestamp + ttlSeconds * 1000;

    try {
      deps.db.createSession({
        guid,
        // Only the hash is stored. The secret is never written, logged or echoed
        // beyond the cookie the browser already holds (PLAN-v3 §4).
        secretHash: hashSecret(secret),
        csrfKey,
        now: timestamp,
        expiresAt,
      });
    } catch {
      // A row that appeared between the read and the insert. Re-read and answer
      // as a restore, which is the same situation by another name.
      return reply.code(409).send({ error: "session already exists" });
    }

    deps.sse.emit(guid, "session-status", { state: "created" });

    // Derived rather than random, so there is no server-side token table to keep
    // consistent with the session table (PLAN-v3 §3.3).
    const csrfToken = deriveCsrfToken(csrfKey, guid);

    return reply
      .code(201)
      // One cookie, not two. The CSRF token travels in the body because a cookie
      // set by this origin is invisible to `document.cookie` on the frontend's
      // host — see the file header in cookies.ts. mac found this during review:
      // every mutating route 403'd on a token no page could read.
      .header("set-cookie", [serialiseCookie(sessionCookie(`${guid}:${secret}`, ttlSeconds))])
      .send({
        protocol: PROTOCOL_VERSION,
        expiresAt: new Date(expiresAt).toISOString(),
        csrfToken,
      });
  });

  // ---- GET /api/session/status -------------------------------------------

  app.get("/api/session/status", async (request, reply) => {
    const session = request.ctx.session;
    if (session === null) {
      return reply.code(401).send({ error: "unauthorised" });
    }

    // A session whose auth expired is still readable, so the frontend can render
    // "please log in again" rather than a bare 401 (§13.2's accepted risk).
    const snapshot = buildSnapshot(
      session,
      now(),
      { state: "idle", items: notebooksFor(session) },
      config.publicOrigin,
    );

    // The CSRF token comes back on every mount, not just at creation. This is
    // what replaces the readable cookie across the split: §7.5's restore flow
    // calls this endpoint on mount anyway, so the frontend re-arms its header from
    // here after a refresh, when its in-memory copy is gone.
    //
    // Safe because CORS is not reflection: an attacker page can cause this request
    // — the SameSite=None session cookie rides along — but cannot read the
    // response, because ACAO is emitted only for an allowlisted origin.
    const csrfToken = deriveCsrfToken(session.csrf_key ?? "", session.guid);

    return reply.send({ ...snapshot, csrfToken });
  });

  // ---- GET /api/session/events -------------------------------------------

  app.get("/api/session/events", async (request, reply) => {
    const session = request.ctx.session;
    if (session === null) {
      return reply.code(401).send({ error: "unauthorised" });
    }

    /*
     * The streaming headers, set with `reply.header` and never with
     * `res.writeHead(200, {...})`.
     *
     * Node's `writeHead` with an explicit headers object **replaces** the whole
     * header set rather than merging into it. Calling it here therefore discarded
     * everything the onRequest hook had already applied — `vary: Origin`, and the
     * ACAO/ACAC for an allowlisted origin. mac found this against a real
     * deployment: the browser refused the EventSource for a missing ACAO, while the
     * 401 on this same route had one, which is the signature of headers being
     * dropped between the hook and a streaming success.
     *
     * `reply.header` keeps them in Fastify's own store, which is what gets flushed
     * when the raw response is written below.
     */
    reply.header("content-type", "text/event-stream");
    // §6: an EventSource from the frontend origin is cross-origin, and
    // `withCredentials` is what makes the cookie ride along. Without it every
    // reconnect silently 401s and the UI shows "reconnecting…" forever — the
    // failure mac predicted, and the one worth guarding.
    reply.header("access-control-allow-credentials", "true");
    // Without this a reverse proxy may buffer and deliver the stream in one lump at
    // close, which looks exactly like a broken event stream.
    reply.header("x-accel-buffering", "no");
    // `no-store` because the stream is a live session event feed: a cached 200 here
    // would be a stream of somebody else's events.
    reply.header("cache-control", "no-store");

    /*
     * Take over the raw response and flush.
     *
     * `hijack` stops Fastify from trying to send a reply of its own once the
     * handler returns, and `flushHeaders` emits the status line plus every header
     * in the store — the SSE ones just added *and* the CORS ones the hook set.
     * Calling writeHead with a headers object instead would replace both sets.
     */
    reply.hijack();

    // Copy Fastify's accumulated header store onto the raw response explicitly.
    //
    // `reply.header()` does *not* reach `res.setHeader` until Fastify sends a
    // reply, and after `hijack()` it never will — so on its own it sets nothing on
    // the wire and the stream goes out with no CORS headers and no
    // x-accel-buffering. `getHeaders()` is the store; `setHeader` accumulates on
    // the response; and `writeHead(200)` with no headers object then emits the
    // union. Nothing is replaced, which is the entire point.
    for (const [key, value] of Object.entries(reply.getHeaders())) {
      if (value !== undefined) reply.raw.setHeader(key, value as string | number | string[]);
    }

    // `reply.raw` is the ServerResponse; `request.raw` is the IncomingMessage,
    // which has neither of these methods.
    reply.raw.writeHead(200);
    reply.raw.flushHeaders();

    // Nagle would coalesce small frames, so a log line and the next event would
    // arrive together.
    reply.raw.socket?.setNoDelay?.(true);

    const lastEventIdHeader = request.headers["last-event-id"];
    const lastEventId =
      typeof lastEventIdHeader === "string" && lastEventIdHeader !== ""
        ? Number(lastEventIdHeader)
        : null;
    const resumeFrom =
      lastEventId !== null && Number.isInteger(lastEventId) && lastEventId >= 0
        ? lastEventId
        : null;

    // The response stream, not the request. The SSE hub writes frames to a
    // ServerResponse; `reply.raw` on a GET is typed as the IncomingMessage until
    // Fastify has committed a response, and this route bypasses that entirely.
    const stream = reply.raw as unknown as import("node:http").ServerResponse;

    const attached = deps.sse.attach(session.guid, stream, resumeFrom);

    if (attached.replayed === null) {
      // A gap, or a fresh connection. Either way a snapshot is the honest
      // answer; the alternative is a client that believes it is up to date.
      deps.sse.sendSnapshot(
        session.guid,
        attached.subscriberId,
        buildSnapshot(
          session,
          now(),
          { state: "idle", items: notebooksFor(session) },
          config.publicOrigin,
        ),
        attached.hub.nextId,
      );
    } else {
      for (const event of attached.replayed) {
        deps.sse.sendSnapshot(session.guid, attached.subscriberId, event.data, event.id);
      }
    }

    request.raw.on("close", () => {
      deps.sse.detach(session.guid, attached.subscriberId);
    });

    // The response never ends on its own; the socket stays open until the client
    // closes it or the process does.
    return reply;
  });

  // ---- POST /api/session/credential ---------------------------------------

  app.post("/api/session/credential", async (request, reply) => {
    const session = request.ctx.session;
    if (session === null) {
      return reply.code(401).send({ error: "unauthorised" });
    }

    // Framing was already checked in onRequest, before a byte was read. Checked
    // again here because the handler must not depend on a hook having run: a
    // route added later would otherwise forward a credential with no cap.
    const framed = checkFraming(
      typeof request.headers["content-length"] === "string"
        ? request.headers["content-length"]
        : undefined,
    );
    if (!framed.ok) {
      return reply
        .code(framed.refusal === "content-length-too-large" ? 413 : 411)
        .send({ error: framed.refusal });
    }
    if (
      !contentTypeIsAcceptable(
        typeof request.headers["content-type"] === "string"
          ? request.headers["content-type"]
          : undefined,
      )
    ) {
      return reply.code(415).send({ error: "unsupported content-type" });
    }

    /**
     * The Microsoft account, in a header rather than in the body.
     *
     * mac's design, and his reasoning for it is the reason I agreed rather than
     * proposing the obvious alternative: the body stays byte-identical. Splitting
     * "account\npassword" in one body would mean a delimiter, and a delimiter is
     * another place for a truncation bug — a bug class this pair has now shipped
     * twice from opposite ends (his client JSON-encoding the password, my
     * `capStream` ending the body before it began), with the same user-visible
     * symptom both times.
     *
     * An email address or a username, because Microsoft accepts either and telling
     * someone to "enter your email" when their account is a username is a dead
     * end. So: validated as a non-empty bounded string, not as an email.
     *
     * Not a secret, but still an identifier, so it is never logged — see the
     * no-header-logging assertion in CI.
     */
    const account = headerValue(request, ACCOUNT_HEADER);
    if (account === undefined || account.trim() === "") {
      return reply.code(400).send({ error: "microsoft account required" });
    }
    if (account.length > MAX_ACCOUNT_CHARS) {
      return reply.code(400).send({ error: "microsoft account too long" });
    }

    // A 501 must not claim a slot. The container is the expensive thing to leak
    // and there is nothing here to hand the credential to, so the order is:
    // refuse first, bind second. The stream is still created and destroyed so the
    // 4 KB cap holds in the unwired state too.
    if (deps.runner === undefined) {
      capStream(request.body as Readable, MAX_CREDENTIAL_BYTES).destroy();
      return reply.code(501).send({ error: "credential forwarding not wired yet" });
    }

    // The credential reaches the runner through the orchestrator's claim, so a
    // session needs a container before it can accept one. Binding is lazy —
    // here, at login — rather than at session creation, so a session that is
    // created and abandoned never holds a slot, and the §2.1 pool stays available
    // to a session that is actually about to use it.
    //
    // It runs *after* the framing checks above on purpose: a request that is
    // oversized, unframed or the wrong content type must not create a container.
    if (session.runner_id === null) {
      if (deps.poolBinder === undefined) {
        // No pool manager wired, which is the unwired state. Honest, and the
        // same 409 as before.
        return reply.code(409).send({ error: "no runner bound to this session" });
      }

      const bound = await deps.poolBinder.claimForLogin(session);
      if (!bound.ok) {
        // §2.6: name the cause rather than showing a countdown to a slot that
        // will not move. "Every session is busy" and "the control plane cannot
        // start runners" are different advice, and the user cannot tell them apart.
        //
        // Four outcomes now, and `retryable` is the honest answer for each:
        //
        //   busy             -> wait; a slot frees up
        //   pool cannot fill -> wait does NOT help; something is misconfigured
        //   control plane unreachable -> transient, retry
        //   slot conflict    -> this process and the orchestrator disagree about the
        //                       pool, which is an operator problem, not a user's
        request.log.info(
          { reason: bound.reason, fillError: bound.fillError ?? null },
          "runner claim failed",
        );
        const cannotFill = bound.reason === "pool-exhausted" && bound.fillError !== undefined;
        // A conflict means every slot this process offered was refused, after the
        // retries. It is **not** unreachability: the orchestrator answered, clearly, and
        // the answer was "no". Reporting it as an unreachable control plane told the
        // user to retry a login that could not succeed, and told whoever read the log
        // that a component was down while it was answering a 409 in milliseconds.
        //
        // Reported as 409 rather than 5xx because nothing about a retry fixes it. The
        // pool has to be reconciled, and that is the api's problem to resolve — see
        // `claimForLogin`'s retry, which handles the drift case, and the boot fix in
        // the orchestrator that removes the cause.
        if (bound.reason === "slot-conflict") {
          return reply.code(409).send({
            error: "the service's view of its runner pool is out of date",
            retryable: false,
            cause: "pool-diverged",
          });
        }
        return reply
          .code(bound.reason === "pool-exhausted" ? 503 : 502)
          .send({
            error: cannotFill
              ? "the service cannot start a browser right now"
              : bound.reason === "pool-exhausted"
                ? "every session is busy"
                : "runner control plane unreachable",
            // Still retryable: a misconfiguration gets fixed and the pool refills.
            // But a client that has been told "busy" and is still failing after a
            // few attempts now has something to escalate with.
            retryable: true,
            ...(cannotFill ? { cause: "pool-unfillable" } : {}),
          });
      }
    }

    deps.sse.emit(session.guid, "login-started", {});

    // The capped stream is created here so the guarantee holds regardless of what
    // happens next: a caller who understates Content-Length and sends 4 MB has it
    // cut off at 4 KB whether or not anything consumes it. The handler below
    // independently re-checks framing — that redundancy is load-bearing, and one
    // refactor away from becoming a 4 KB → 256 KB hole.
    const forwardable = capStream(request.body as Readable, MAX_CREDENTIAL_BYTES);

    try {
      // Hands the stream over. Never buffers it, never decodes it, never logs it:
      // the adapter reads the bytes and the password stops here.
      await deps.runner.submitCredential({
        sessionId: session.guid,
        stream: forwardable,
        correlationId: session.guid,
        account,
      });
    } catch (error) {
      // A transport failure, not a login failure. The login outcome arrives over
      // SSE; this is only "the credential never got there".
      request.log.error({ session: session.guid }, "credential handoff failed");
      deps.sse.emit(session.guid, "error", { message: "credential handoff failed" });
      return reply.code(502).send({ error: "credential handoff failed" });
    }

    // Accepted, not succeeded. The outcome is a `challenge` / `login-success` /
    // `login-failed` event on the session's stream.
    return reply.code(202).send({ accepted: true });
  });

  // ---- POST /api/session/erase -------------------------------------------

  app.post("/api/session/erase", async (request, reply) => {
    const session = request.ctx.session;
    if (session === null) {
      return reply.code(401).send({ error: "unauthorised" });
    }

    if (deps.eraseRunner === undefined) {
      return reply.code(501).send({ error: "erase not wired yet" });
    }

    const outcome = await runErase(
      {
        db: deps.db,
        orchestrator: {
          remove: async (slotId: string) => deps.orchestrator.remove(slotId),
          // The erase machine only needs to know whether the orchestrator is
          // reachable, so a typed failure is flattened rather than propagated —
          // the machine reports "pool stats unavailable", not a TS error.
          stats: async () => {
            const result = await deps.orchestrator.stats();
            return { ok: result.ok, value: { size: result.ok ? result.value.size : 0 } };
          },
        },
        runner: deps.eraseRunner,
        sse: deps.sse,
      } satisfies EraseDeps,
      session.guid,
    );

    // The cookie is expired whether or not the machine succeeded. A stale tab
    // holding a cookie for a deleted row is exactly what T7 describes, and a
    // failed erase that deleted the row still needs the cookie gone.
    const headers = expireCookieHeaders();

    if (!outcome.ok) {
      return reply
        .code(500)
        .header("set-cookie", headers)
        .send({ error: "erase_failed", failedAt: outcome.failedAt });
    }

    // The address's counters are dropped so a legitimate user who erases and
    // retries is not throttled as if they had never cleaned up.
    const client = resolveClientAddress({
      peerAddress: request.ip,
      forwardedFor:
        typeof request.headers["x-forwarded-for"] === "string"
          ? request.headers["x-forwarded-for"]
          : undefined,
      knownProxies,
    });
    deps.limiter.forgetAddress(client.address);

    return reply
      .code(200)
      .header("set-cookie", headers)
      .send({ erased: true });
  });

  // ---- POST /api/session/notebooks ---------------------------------------

  // Named `/api/session/notebooks` rather than `/api/notebooks` to match the
  // other session sub-resources. Listing is an action — it runs a CLI in a
  // container — so it is a POST, and there is deliberately no GET that mutates
  // server state.
  app.post("/api/session/notebooks", async (request, reply) => {
    const session = request.ctx.session;
    if (session === null) {
      return reply.code(401).send({ error: "unauthorised" });
    }

    const body = await parseJsonObject(request);
    // An empty body is valid: the route takes no parameters, so there is nothing
    // to send. A non-empty body must still be an object with no unknown fields.
    if (body !== null && Object.keys(body).length > 0) {
      return reply.code(400).send({ error: "this route takes no parameters" });
    }

    // Listing needs an authenticated session, because the CLI reads auth.json.
    if (session.auth_state !== "valid") {
      return reply.code(409).send({ error: "not authenticated" });
    }

    if (session.runner_id === null) {
      return reply.code(409).send({ error: "no runner bound to this session" });
    }

    deps.sse.emit(session.guid, "auth-state", { state: "authenticating" });

    if (deps.runner === undefined) {
      return reply.code(501).send({ error: "notebook listing not wired yet" });
    }

    try {
      // Asynchronous by design: the CLI runs in a container, and the result
      // arrives as a `notebooks-listed` event rather than in this response.
      await deps.runner.listNotebooks(session.guid);
    } catch (error) {
      request.log.error({ session: session.guid }, "notebook listing failed");
      deps.sse.emit(session.guid, "error", { message: "notebook listing failed" });
      return reply.code(502).send({ error: "notebook listing failed" });
    }

    deps.sse.emit(session.guid, "session-status", { state: "authenticated" });
    return reply.code(202).send({ listing: true });
  });

  // ---- POST /api/export ---------------------------------------------------

  app.post("/api/export", async (request, reply) => {
    const session = request.ctx.session;
    if (session === null) {
      return reply.code(401).send({ error: "unauthorised" });
    }

    const body = await parseJsonObject(request, 64 * 1024, ["notebook"]);
    if (body === null) {
      return reply.code(400).send({ error: "malformed request body" });
    }
    const notebook = asString(body.notebook);
    if (notebook === undefined) {
      return reply.code(400).send({ error: "notebook is required" });
    }

    if (session.auth_state !== "valid") {
      return reply.code(409).send({ error: "not authenticated" });
    }

    // §8.1: one active export per session. Driven from the stored state rather
    // than from anything the client sent, so a second tab cannot start a second
    // export by lying about the first.
    const stored = session.export_state;
    if (stored !== null) {
      try {
        const parsed = JSON.parse(stored) as { state?: string };
        if (parsed.state !== undefined && EXPORT_STATES.has(parsed.state)) {
          if (parsed.state === "queued" || parsed.state === "running") {
            return reply.code(409).send({ error: "an export is already running" });
          }
        }
      } catch {
        // A corrupt column must not block an export; it is treated as no export.
      }
    }

    // The global cap is the backstop. §8.1 has no queue in v1, so the over-cap
    // case is a refusal with retry guidance.
    const slot = deps.limiter.acquireExportSlot();
    if (!slot.allowed) {
      reply.header("retry-after", String(slot.retryAfterSeconds));
      return reply.code(429).send({ error: slot.reason, retryAfterSeconds: slot.retryAfterSeconds });
    }
    // Released if the route bails below, so a failed start does not consume a
    // global slot indefinitely.
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      deps.limiter.releaseExportSlot();
    };

    if (session.runner_id === null) {
      release();
      return reply.code(409).send({ error: "no runner bound to this session" });
    }

    const exportId = generateArtifactId();
    deps.db.run(
      `UPDATE sessions SET state = 'exporting', notebook = ?, export_state = ? WHERE guid = ?`,
      notebook,
      JSON.stringify({
        state: "queued",
        partialReason: null,
        id: exportId,
        notebook,
        progress: { pages: 0, sections: 0, assets: 0 },
        startedAt: now(),
        finishedAt: null,
      }),
      session.guid,
    );
    deps.sse.emit(session.guid, "export-queued", { id: exportId, notebook });

    if (deps.runner === undefined) {
      // No slot leaked: the global slot taken above is returned, because nothing
      // is going to run.
      release();
      return reply.code(501).send({ error: "export execution not wired yet" });
    }

    // The abort controller lives for the duration of the run. §8.2: abort
    // preserves what is on disk and marks the artifact partial, so the only thing
    // cancellation has to do is stop the traversal.
    const controller = new AbortController();
    deps.db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({
        state: "running",
        partialReason: null,
        id: exportId,
        notebook,
        progress: { pages: 0, sections: 0, assets: 0 },
        startedAt: now(),
        finishedAt: null,
      }),
      session.guid,
    );

    try {
      await deps.runner.startExport({
        sessionId: session.guid,
        exportId,
        notebook,
        signal: controller.signal,
      });
    } catch (error) {
      release();
      deps.db.run(
        `UPDATE sessions SET export_state = ? WHERE guid = ?`,
        JSON.stringify({
          state: "failed",
          partialReason: null,
          // The reason a user can be shown, and the reason it survives a refresh.
          // `sanitiseExportError` returns null for an unclassifiable failure, so
          // the generic message is the fallback — the user always gets a reason,
          // and never a path from the exporter's own error text.
          error: sanitiseExportError(classifyExportFailure(error)) ?? GENERIC_EXPORT_ERROR,
          id: exportId,
          notebook,
          progress: null,
          startedAt: now(),
          finishedAt: now(),
        }),
        session.guid,
      );
      deps.sse.emit(session.guid, "error", {
        id: exportId,
        message: "export failed to start",
      });
      // The full error goes to the log, not to the browser: it is the operator's
      // to read and may contain a path.
      request.log.error({ session: session.guid, err: error }, "export start failed");
      return reply.code(502).send({ error: "export failed to start" });
    }

    // The slot is released when the run finishes rather than being held for the
    // export's duration — §2.1: "Export running — no idle kill", and throughput
    // is bounded by concurrency rather than by how long exports take.
    release();
    return reply.code(202).send({ id: exportId, state: "running" });
  });

  // ---- GET /internal/authorize-download -----------------------------------

  /**
   * The forward_auth endpoint Caddy calls before serving any artifact.
   *
   * ## What it is for
   *
   * Caddy serves `/files/*` itself, with sendfile, so a multi-gigabyte download
   * never passes through Node. But something has to decide *whether* — and the
   * something is this, reached only by Caddy on the internal network.
   *
   * ## How it is reached, and why that is the security
   *
   * Caddy calls it with `copy_headers Cookie` and `uri /internal/authorize-download`,
   * passing the original path in a header. The request is a GET, so the auth hook
   * in server.ts has already required a valid session cookie, and §3.3's CSRF
   * layer correctly does not apply — there is no browser and no token here, only
   * a proxy relaying a cookie it already holds.
   *
   * That means this route needed **no exemption at all**. It is worth saying
   * plainly, because the obvious way to build it would have been to add
   * `/internal/*` to a bypass list — which is precisely the shape of bug found in
   * review, an auth bypass in the component that holds the session secret. The
   * route is instead an ordinary authenticated read.
   *
   * It is not reachable from outside because Caddy never routes `/internal/*` to
   * the api. A client that reaches the api another way can forge the header, and
   * gains nothing: it still needs a session cookie, and it can only ever authorize
   * an artifact that session already owns.
   */
  app.get("/internal/authorize-download", async (request, reply) => {
    const session = request.ctx.session;
    // The auth hook guarantees this, but a null here would mean the hook and this
    // route disagree about what protects it. Denying is the only safe reading of
    // that, and the log says so loudly.
    if (session === null) {
      request.log.error("authorize-download reached with no session — hook mismatch");
      return reply.code(403).send({ error: "forbidden" });
    }

    const artifactId = artifactIdFromHeader(
      headerValue(request, "x-original-uri") ?? headerValue(request, "x-forwarded-uri"),
    );

    if (artifactId === null) {
      // A request with no parseable artifact id is not a request for a known
      // artifact, so it is refused. Never "allowed because we could not tell".
      request.log.warn(
        { session: session.guid },
        "authorize-download with no parseable artifact id",
      );
      return reply.code(403).send({ error: "forbidden" });
    }

    const owner = deps.db.findByArtifact(artifactId);

    /**
     * The one branch, deliberately.
     *
     * "No such artifact" and "not yours" must be indistinguishable from outside,
     * or this endpoint becomes an oracle: anyone with a stolen or guessed id could
     * learn whether an export exists, which is a fact about another user's data.
     * Both answer 403 with the same body.
     *
     * The comparison is on the session guid rather than a count, so an artifact
     * id cannot authorize a different session's download even if the id leaked
     * through a Referer, a shared link or browser history.
     */
    if (owner === undefined || owner.guid !== session.guid) {
      request.log.info(
        { session: session.guid },
        owner === undefined ? "authorize-download: unknown artifact" : "authorize-download: wrong session",
      );
      return reply.code(403).send({ error: "forbidden" });
    }

    // 204 rather than 200: Caddy only checks for a 2xx, and an empty body keeps
    // this endpoint from ever becoming a place a response body could leak.
    //
    // The header is the server-enforced half of §5's rule that a partial vault
    // must not be mistakable for a complete one. Caddy copies it onto the
    // download response, so the fact comes from the database rather than from a
    // frontend that might forget to check.
    if (owner.artifact_partial === 1) {
      reply.header("X-Artifact-Partial", "1");
    }
    return reply.code(204).send();
  });

  // ---- POST /api/export/:id/abort ----------------------------------------

  app.post("/api/export/:id/abort", async (request, reply) => {
    const session = request.ctx.session;
    if (session === null) {
      return reply.code(401).send({ error: "unauthorised" });
    }

    const { id } = request.params as { id?: string };
    if (id === undefined || !/^[A-Za-z0-9_-]{43}$/.test(id)) {
      return reply.code(400).send({ error: "invalid export id" });
    }

    // The id is validated for shape and then matched against what the session
    // actually owns. Shape alone is not authorisation: one session must not be
    // able to abort another's export, however it learned the id.
    const stored = session.export_state;
    if (stored === null) {
      return reply.code(404).send({ error: "no export" });
    }
    let owned = false;
    try {
      owned = (JSON.parse(stored) as { id?: string }).id === id;
    } catch {
      owned = false;
    }
    if (!owned) {
      return reply.code(404).send({ error: "no such export" });
    }

    // §8.2: abort preserves what is on disk and marks the artifact partial. The
    // state change is recorded here so a client that refreshes sees "partial"
    // rather than a running export that will never finish.
    deps.db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({
        state: "partial",
        // mac's pushback: "you stopped this" is false for a quota or disk abort.
        partialReason: "aborted",
        id,
        notebook: session.notebook,
        progress: null,
        startedAt: null,
        finishedAt: now(),
      }),
      session.guid,
    );
    deps.sse.emit(session.guid, "export-aborted", { id });
    deps.sse.emit(session.guid, "export-partial", { id });

    if (deps.runner === undefined) {
      return reply.code(501).send({ error: "abort not wired yet" });
    }

    try {
      await deps.runner.abortExport({ sessionId: session.guid, exportId: id });
    } catch (error) {
      // The state change above already recorded the partial, which is the part a
      // refresh would read. A failed cancellation means the run may continue and
      // write more into an artifact the user believes is finished — worth saying
      // so, rather than reporting a success that did not happen.
      request.log.error({ session: session.guid, exportId: id }, "abort handoff failed");
      return reply.code(502).send({ error: "abort handoff failed" });
    }

    return reply.code(202).send({ id, state: "partial" });
  });

  // ---- GET /files/:artifactId --------------------------------------------

  // Not served here. Caddy serves it with `forward_auth` to an internal endpoint,
  // so a multi-gigabyte vault never passes through Node (PLAN-v2 §8.3, PLAN-v3
  // §5). The authorisation decision is made here from SQLite; the bytes are not.
  app.get("/files/:artifactId", async (request, reply) =>
    reply.code(501).send({ error: "artifacts are served by Caddy, not by the api" }),
  );

  // ---- GET /healthz -------------------------------------------------------

  app.get("/healthz", async (_request, reply) =>
    reply.send({ ok: true, protocol: PROTOCOL_VERSION, build: API_BUILD }),
  );
}

/** notebooksFor reads the notebook list stored on the session, if any. */
function notebooksFor(session: SessionRow): string[] {
  if (session.notebook === null) return [];
  // One notebook is recorded per export; the full list arrives over SSE and is
  // not persisted here yet. Returning an array keeps the snapshot's shape stable
  // so the client's `items` is never null.
  return session.notebook === "" ? [] : [session.notebook];
}