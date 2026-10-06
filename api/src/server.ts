/**
 * The api's HTTP surface.
 *
 * Three things in this file are security controls rather than wiring, and all
 * three were flagged by review before they were written:
 *
 * **No body interpretation, anywhere.** Fastify ships built-in parsers for
 * `application/json` and `text/plain` and registers them at instance
 * construction. They run before any route handler and before any
 * route-scoped opt-out, so leaving them in place means "this route does not parse
 * its body" is true only until somebody adds a global hook. They are therefore
 * removed with `removeAllContentTypeParsers()` and replaced by a single
 * catch-all that hands the handler the *raw stream* and interprets nothing. A
 * route that wants JSON parses its own bytes, with its own cap. The credential
 * route then has no parser reachable from anywhere in the stack, which is the
 * property that actually matters (PLAN-v3 §3.1).
 *
 * **Cross-origin checks run in `onRequest`.** That hook fires before body
 * parsing, so it fires before any byte is read. A stream that starts and is then
 * 403'd is worse than one that never starts — the runner may already have acted
 * on a prefix. The Origin allowlist, the CSRF header and the credential
 * Content-Length cap are enforced here, in that order (PLAN-v3 §3.3).
 *
 * **The client address is never trusted from a header.** `trustProxy` is off and
 * the address comes from the socket peer (§3.5), with the rightmost
 * `X-Forwarded-For` entry consulted only for a known proxy.
 */

import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from "fastify";
import type { Readable } from "node:stream";

import { ApiConfig } from "./config.js";
import { Db } from "./db.js";
import type { OrchestratorApi } from "./orchestrator-client.js";
import { SseHub } from "./sse.js";
import { RateLimiter } from "./rate-limit.js";
import type { EraseDeps } from "./erase.js";
import type { RunnerAdapter } from "./runner-adapter.js";
import type { PoolBinder } from "./sweep.js";
import { registerRoutes, type RouteDeps } from "./routes.js";
import { authenticate, authErrorBody, authStatus, PROTOCOL_VERSION, API_BUILD } from "./auth.js";
import {
  CSRF_HEADER,
  checkNonGetRequest,
  corsHeaders,
  preflightHeaders,
} from "./csrf.js";
import { getCookie } from "./cookies.js";
import { SESSION_COOKIE } from "./csrf.js";
import { isValidGuid, isValidSecret } from "./session.js";
import {
  MAX_CREDENTIAL_BYTES,
  auditFields,
  capStream,
  checkFraming,
  contentTypeIsAcceptable,
} from "./credential.js";
import { resolveClientAddress } from "./client-ip.js";

/**
 * installRawBodyParser removes every body parser and installs one that
 * interprets nothing.
 *
 * Exported so a test can assert the property against a bare instance without
 * needing a route it controls — which matters because the earlier way of doing
 * that was an authentication bypass living in production code, and mac was right
 * that a comment is not a strong enough guard on one.
 */
export function installRawBodyParser(app: FastifyInstance): void {
  // The built-in parsers are the hazard this exists to remove: Fastify registers
  // JSON and text/plain at construction, and they run before any route handler
  // and before any route-scoped opt-out. See the file header.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("*", (_request, payload, done) => {
    // Hand over the stream. Interpreting it — even into a Buffer — is the
    // decision each route makes for itself.
    done(null, payload);
  });
}

/**
 * PUBLIC_PATHS are the two reads that need no session.
 *
 * Exact matches, not prefixes. A prefix rule would open whatever else began with
 * the same characters, and the whole point of naming them is that the list is
 * short enough to read.
 *
 * Matched against the *route pattern*, not `request.url`. mac caught this: a
 * request to `/api/public/version?cb=123` carries the query in `request.url`, so a
 * `Set.has(request.url)` test fails and the handshake 401s on a cache-buster —
 * and, worse, the credential route's framing checks in this hook were being
 * skipped for the same reason.
 */
const PUBLIC_PATHS = new Set(["/api/public/version", "/healthz"]);

/**
 * MINT_PATHS are the mutating routes that create a credential, so they cannot
 * require one.
 *
 * `POST /api/session` is the only member, and being a POST it is also the one
 * route where §3.3's CSRF layer cannot apply — there is no token yet to derive
 * from a session that does not exist. What stands in its place is the Origin
 * allowlist, checked in the route's own handler, plus the fact that a successful
 * call establishes nothing an attacker could ride: the caller gets a session and
 * no one else does.
 */
const MINT_PATHS = new Set(["/api/session"]);

/**
 * requiredPreflightHeaders is what the credential route needs the browser to
 * send. Listed explicitly rather than reflected, because reflecting
 * `Access-Control-Request-Headers` would let a caller enumerate what this
 * service accepts.
 */
const requiredPreflightHeaders = ["x-csrf-token", "content-type"] as const;

/**
 * What a route finds on the request after the hooks have run.
 *
 * Mutable, because the hook fills it in progressively. Every field is non-null so
 * a handler never branches on a missing key.
 */
export interface RequestContext {
  /** The session row, once authentication succeeded. */
  session: import("./db.js").SessionRow | null;
  /** The CSRF token derived for this session. */
  csrfToken: string | null;
  /** The validated Origin, or null when there was none. */
  origin: string | null;
  /** The rate-limiting address. */
  clientAddress: string;
}

/**
 * header returns a single header value, or undefined for a repeated header.
 *
 * Node types a repeated header as `string[]`. Picking one value from a repeated
 * header is guessing, so this refuses: the caller treats undefined as "absent",
 * and each caller's absence handling is chosen to fail closed.
 *
 * `repeatedHeader` exists for the two headers where "absent" would fail *open*,
 * which is not acceptable and so is called out explicitly rather than left to a
 * reader to notice.
 */
export function header(request: FastifyRequest, name: string): string | undefined {
  const value = request.headers[name];
  return typeof value === "string" ? value : undefined;
}

/** isRepeatedHeader reports whether a header arrived more than once. */
export function isRepeatedHeader(request: FastifyRequest, name: string): boolean {
  return Array.isArray(request.headers[name]);
}

/**
 * routePath is the matched route pattern, with no query string.
 *
 * `request.url` carries the query, so `Set.has(request.url)` fails for
 * `/api/public/version?cb=123` — which made the handshake 401 on a cache-buster
 * and, more seriously, skipped the credential route's framing checks. mac found
 * this by probing fastify directly rather than trusting the docs.
 *
 * `request.routeOptions.url` is the registered pattern and is clean. It is
 * undefined when no route matched, which is exactly the signal the unmatched-path
 * log needs.
 */
function routePath(request: FastifyRequest): string | undefined {
  return request.routeOptions.url;
}

declare module "fastify" {
  interface FastifyRequest {
    ctx: RequestContext;
  }
}

/** Dependencies, injected rather than imported as singletons. */
export interface ServerDeps {
  readonly db: Db;
  readonly orchestrator: OrchestratorApi;
  /** The SSE hub. One per process; sessions are multiplexed inside it. */
  readonly sse: SseHub;
  /** The rate limiter. One per process, since its counters are per-process. */
  readonly limiter: RateLimiter;
  /**
   * Runner control for the erase machine.
   *
   * Optional because erase spans three hosts and the runner half arrives with the
   * sidecar. Without it `POST /api/session/erase` answers 501 rather than
   * pretending to have deleted anything.
   */
  readonly eraseRunner?: EraseDeps["runner"];
  /**
   * The api's route to a runner container.
   *
   * Optional, and absent in every real deployment until the runner sidecar lands
   * (§12 steps 1–2). Without it the four runner-facing routes return 501, which
   * is the current behaviour and the contract mac is building against — so adding
   * this changes no route, status code or header a browser can see.
   *
   * A mock supplies one, which is how a frontend gets a backend to develop
   * against without Docker.
   */
  readonly runner?: RunnerAdapter;
  /**
   * Binds a session to a container when it first needs one.
   *
   * Absent in the unwired state, in which case the credential route answers 409 —
   * the same as before this existed. The absence is the thing that keeps the
   * binding out of a deployment that has no pool to bind from.
   */
  readonly poolBinder?: PoolBinder;
}

/** Options for buildServer. */
export interface BuildServerOptions {
  /**
   * Addresses permitted to supply X-Forwarded-For. Empty means "no proxy", which
   * is the fail-closed default: every request resolves to its socket peer.
   */
  readonly knownProxies?: ReadonlySet<string>;
  readonly logger?: boolean;
}

/** buildServer constructs the api. */
/**
 * buildServer constructs the api with its hooks and every route.
 *
 * The single entry point. `baseServer` exists separately so a test can build the
 * hooks without the routes — useful when a test needs to register its own probe
 * route against a live instance, which Fastify only permits before `ready()`.
 */
export function buildServer(
  config: ApiConfig,
  deps: ServerDeps,
  options: BuildServerOptions = {},
): FastifyInstance {
  const app = baseServer(config, deps, options);
  // Assembled conditionally rather than with explicit `undefined`, because
  // exactOptionalPropertyTypes treats the two as different and RouteDeps' fields
  // are optional rather than nullable.
  const routeDeps: RouteDeps = {
    db: deps.db,
    orchestrator: deps.orchestrator,
    sse: deps.sse,
    limiter: deps.limiter,
  };
  if (options.knownProxies !== undefined) routeDeps.knownProxies = options.knownProxies;
  if (deps.eraseRunner !== undefined) routeDeps.eraseRunner = deps.eraseRunner;
  if (deps.runner !== undefined) routeDeps.runner = deps.runner;
  if (deps.poolBinder !== undefined) routeDeps.poolBinder = deps.poolBinder;

  registerRoutes(app, config, routeDeps);
  return app;
}

/**
 * baseServer builds the instance with hooks and the two routes that must exist
 * before the hook's own exemption list is installed.
 *
 * Split from `buildServer` so `registerRoutes` can attach the rest without
 * creating a second instance, and so a test can register probe routes on a live
 * server without re-declaring the hooks.
 */
export function baseServer(
  config: ApiConfig,
  deps: ServerDeps,
  options: BuildServerOptions = {},
): FastifyInstance {
  const knownProxies = options.knownProxies ?? new Set<string>();

  const app = Fastify({
    logger: options.logger ?? false,
    // Off by default. Fastify's own X-Forwarded-For handling would reintroduce
    // exactly the header-trusting §3.5 forbids; `trustProxy: true` is the
    // single most likely way this service would end up rate-limiting a
    // spoofable address.
    trustProxy: false,
    // A cap at the transport level, so a body larger than any route accepts is
    // refused before a handler sees it. The credential route has its own, much
    // smaller, cap and enforces it in onRequest.
    bodyLimit: 256 * 1024,
  });

  installRawBodyParser(app);

  // Fastify 5 rejects a reference-type decorator with a plain object, because a
  // shared object across requests would leak one request's session into another.
  // A getter/setter pair keeps the per-request instance owned by Fastify.
  app.decorateRequest("ctx", {
    getter(this: FastifyRequest): RequestContext {
      return (this as unknown as { _ctx: RequestContext })._ctx;
    },
    setter(this: FastifyRequest, value: RequestContext) {
      (this as unknown as { _ctx: RequestContext })._ctx = value;
    },
  });

  // ---- onRequest: CORS, auth, CSRF, client address -----------------------

  app.addHook("onRequest", async (request, reply) => {
    // Seeded here, at the top of the first hook, so every later hook and every
    // handler can rely on it existing. Nothing reads a body before this point.
    request.ctx = {
      session: null,
      csrfToken: null,
      origin: null,
      clientAddress: "unknown",
    };

    const origin = header(request, "origin");
    const path = routePath(request);

    // A repeated Origin is refused outright rather than treated as absent.
    //
    // Everywhere else, `header()` returning undefined for a repeated header means
    // "absent", and absent fails closed: a missing X-Forwarded-For falls back to
    // the socket peer, a missing CSRF token is a 403. A missing Origin is the one
    // case where "absent" is *permissive* — `isOriginAllowed(undefined)` is true,
    // because a non-browser client legitimately sends no Origin at all.
    //
    // So a duplicate Origin, which no browser produces, must not be allowed to
    // borrow that permissiveness. Only the frontend's own browser sends Origin on
    // a cross-origin request, and it sends exactly one.
    if (isRepeatedHeader(request, "origin")) {
      request.log.warn({ url: path }, "repeated Origin header refused");
      return reply.code(403).send({ error: "forbidden" });
    }

    // Vary: Origin on every response, including the ones that set nothing else.
    // A cache that served one origin's ACAO to another would turn the allowlist
    // into a suggestion.
    const cors = corsHeaders(origin, config.allowedOrigins);
    for (const [key, value] of Object.entries(cors)) {
      reply.header(key, value);
    }

    /*
     * Record the matched origin on the context, for **every** method.
     *
     * This was assigned only in the mutating-request branch further down, after
     * `if (isRead) return;`. A GET returned before reaching it, so `ctx.origin` was
     * null on every read — and `/api/session/events` is a GET whose handler
     * compensates for its own headers conditional on this field, so the
     * compensation could never fire. Assigned here instead, at the point the CORS
     * decision is actually made, so no method can be excluded from it by accident.
     *
     * Found by mac against a real deployment: the browser refused the EventSource
     * for a missing ACAO while curl, which does not enforce CORS, saw a perfectly
     * good 200.
     */
    request.ctx.origin = cors["access-control-allow-origin"] ?? null;

    // Client address, from the socket peer (§3.5).
    const client = resolveClientAddress({
      peerAddress: request.ip,
      forwardedFor: header(request, "x-forwarded-for"),
      knownProxies,
    });
    request.ctx.clientAddress = client.address;

    if (request.method === "OPTIONS") {
      const allowed = corsHeaders(origin, config.allowedOrigins)["access-control-allow-origin"];
      if (allowed === undefined) {
        // A foreign origin gets 204 with no ACAO. 403 would tell the caller the
        // path exists.
        return reply.code(204).send();
      }
      for (const [key, value] of Object.entries(
        preflightHeaders(origin, config.allowedOrigins, requiredPreflightHeaders),
      )) {
        reply.header(key, value);
      }
      return reply.code(204).send();
    }

    const isRead = request.method === "GET" || request.method === "HEAD";

    // Two paths need no session: the version handshake, because §7.2 makes
    // checking the protocol the first thing a client does and it has no cookie
    // yet; and health, because an operator's probe has none either.
    //
    // MINT_PATHS joins them for a different reason — POST /api/session *creates*
    // the credential, so it cannot require one and has no CSRF token to check.
    // Both sets are exact matches: a prefix rule would open whatever else began
    // with the same characters.
    const skipsAuth =
      PUBLIC_PATHS.has(path ?? "") || MINT_PATHS.has(path ?? "");

    let authenticated: ReturnType<typeof authenticateFromCookies> | undefined;

    if (!skipsAuth) {
      // A read still needs a session: `/api/session/status` and `/events` are the
      // two most valuable things to read without one. CORS is not an access
      // control, so nothing about a GET is exempt from authentication.
      authenticated = authenticateFromCookies(request, deps.db);
      if (!authenticated.ok) {
        // An unmatched path gets the same 401 as an unmatched credential, so the
        // response reveals nothing about which paths exist (see mac's review:
        // 404-for-unknown is a path oracle).
        //
        // The log is where the distinction is made instead, because debuggability
        // is an operator concern and losing it to a security property is a bad
        // trade. `routeOptions.url` is undefined exactly when no route matched,
        // so this line is filterable and unambiguous.
        if (path === undefined) {
          request.log.warn(
            { url: request.url, method: request.method },
            "no such route",
          );
        }
        return reply.code(authStatus(authenticated.failure)).send(authErrorBody());
      }
      request.ctx.session = authenticated.session;
      request.ctx.csrfToken = authenticated.csrfToken;
    }

    // MINT_PATHS leaves here entirely. §3.3's CSRF layer cannot apply to a route
    // that creates the credential — there is no token yet to derive from a session
    // that does not exist — and the route enforces the Origin allowlist itself.
    //
    // The test-only exemptions leave here too, for the same mechanical reason: a
    // route a test registered has no session and no token to present.
    if (MINT_PATHS.has(path ?? "")) {
      return;
    }

    // GET and HEAD have no state to change, so §3.3 layer 1 — the CSRF header —
    // does not apply to them. The ACAO emission above is what makes the browser's
    // own decision.
    if (isRead) {
      return;
    }

    if (authenticated === undefined || !authenticated.ok) {
      // A mutating route that needs a session but did not get one. The only
      // reachable case is a route that should have been named in skipsAuth and
      // was not — which would silently turn a feature into a 401 rather than a
      // clear failure, so it is logged rather than passed over.
      request.log.error(
        { url: request.url, method: request.method },
        "route requires a session but authentication did not run",
      );
      return reply.code(401).send(authErrorBody());
    }

    const check = checkNonGetRequest({
      origin,
      presentedToken: header(request, CSRF_HEADER),
      allowed: config.allowedOrigins,
      csrfKey: authenticated.csrfKey,
      sessionId: authenticated.session.guid,
    });
    if (!check.ok) {
      // One status and one body for both failures, so this endpoint cannot be
      // used to learn which origins are allowed or whether a token was close.
      request.log.warn(
        { origin: origin ?? null, failure: check.failure },
        "rejected state-changing request",
      );
      return reply.code(403).send({ error: "forbidden" });
    }
    request.ctx.origin = check.allowedOrigin;

    // The credential route's own framing checks, here so they run before any byte
    // is read. A stream that starts and is then refused is the worse failure.
    if (path === "/api/session/credential") {
      const refused = checkCredentialRequest(request, reply);
      if (refused) return refused;
    }

    return;
  });

  // ---- onSend: response hygiene ------------------------------------------

  app.addHook("onSend", async (_request, reply, payload) => {
    // Nothing from this service is cacheable: several responses carry
    // per-session state, and a shared cache would cross sessions. §3.1 requires
    // this specifically for the credential response, and applying it everywhere
    // is simpler than remembering which routes need it.
    reply.header("cache-control", "no-store");
    reply.header("x-content-type-options", "nosniff");
    reply.header("referrer-policy", "no-referrer");
    return payload;
  });

  // ---- Routes -------------------------------------------------------------

  // The remaining routes are registered by registerRoutes() from buildServer().
  //
  // The two unauthenticated reads live in routes.ts alongside everything else, so
  // the route table has one home; PUBLIC_PATHS is what tells this hook to leave
  // them alone.

  // The one mutating route that cannot use the hook above: there is no session
  // yet. It is protected by the Origin allowlist, which is the only layer
  // available before a credential exists, and it establishes nothing an attacker
  // could ride — a successful call only mints a session for the caller.
  // The routes themselves live in routes.ts, except for the credential route's
  // framing checks, which must run in `onRequest` — before a byte is read — and
  // therefore cannot live in a handler.
  return app;
}

/**
 * checkCredentialRequest applies the credential route's framing rules before any
 * body is read, returning a reply when the request must be refused.
 *
 * Returns `undefined` when the request is acceptable, so the caller can `return`
 * the result unconditionally.
 */
function checkCredentialRequest(
  request: FastifyRequest,
  reply: FastifyReply,
): FastifyReply | undefined {
  const contentType = request.headers["content-type"];
  if (!contentTypeIsAcceptable(
    typeof contentType === "string" ? contentType : undefined,
  )) {
    return reply.code(415).send({ error: "unsupported content-type" });
  }
  const declaredLength = request.headers["content-length"];
  const framed = checkFraming(
    typeof declaredLength === "string" ? declaredLength : undefined,
  );
  if (!framed.ok) {
    // 413 for an oversized declared length, 411 for a missing one. Distinct
    // because they mean different things to whoever is debugging: one is a
    // client bug, the other is a client that did not send what it said it would.
    return framed.refusal === "content-length-too-large"
      ? reply.code(413).send({ error: "credential too large" })
      : reply.code(411).send({ error: "content-length required" });
  }
  return undefined;
}

/**
 * authenticateFromCookies verifies the session cookie pair.
 *
 * The cookie value is "<guid>:<secret>". Split on the first colon: base64url has
 * none, so the first colon is the separator, and taking the *first* rather than
 * the last means a malformed value cannot smuggle a colon into the secret half.
 */
export function authenticateFromCookies(request: FastifyRequest, db: Db) {
  const raw = getCookie(request.headers.cookie, SESSION_COOKIE);

  let guid: string | undefined;
  let secret: string | undefined;
  if (raw !== undefined) {
    const at = raw.indexOf(":");
    if (at > 0) {
      guid = raw.slice(0, at);
      secret = raw.slice(at + 1);
    } else {
      // No separator: malformed rather than absent. Passed through as a bad guid
      // so the caller sees a 400 and not a 401.
      guid = raw;
      secret = undefined;
    }
  }

  return authenticate(db, { guid, secret, now: Date.now() });
}

/**
 * readJsonObject reads a raw stream and parses it, with a cap.
 *
 * Returns null on anything unparseable so each handler decides its own response
 * rather than a framework error handler deciding it. Reading through the stream
 * this module installed is what makes the parse per-route.
 */
export async function readJsonObject(
  stream: Readable,
  limitBytes = 64 * 1024,
): Promise<Record<string, unknown> | null> {
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of stream) {
      const buf = chunk as Buffer;
      total += buf.length;
      if (total > limitBytes) {
        // Destroy rather than drain, so a caller cannot make this process buffer
        // without bound.
        stream.destroy();
        return null;
      }
      chunks.push(buf);
    }
  } catch {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}