/**
 * The SSE stream must carry CORS headers, because SSE is the one route a browser
 * reads cross-origin in a way it cannot retry visibly.
 *
 * ## How this bug was found
 *
 * mac ran his frontend against a real deployment. Everything passed over curl
 * except the EventSource, which the browser refused:
 *
 *     Access to resource at '.../api/session/events' from origin
 *     'https://microsoft-onenote-exporter.phttp.com' has been blocked by CORS
 *     policy: No 'Access-Control-Allow-Origin' header is present.
 *
 * with the diagnosis that the **401** on the same route *did* have ACAO and the
 * **200** did not. That is the shape of the two defects below, and it is why the
 * gap in the existing suite matters more than the bug: T-C1 asserted ACAO was
 * *absent* for a foreign origin and nothing ever asserted it was *present* on a
 * streaming 200. Both facts can hold while every cross-origin consumer is broken.
 *
 * ## The two causes, both of which had to be true
 *
 * 1. `ctx.origin` was assigned only in the mutating-request branch of the onRequest
 *    hook. A GET returns at `if (isRead) return;` before reaching it, so for SSE it
 *    stayed `null` — and the route's hand-rolled compensation is conditional on it
 *    being non-null, so it could never fire.
 *
 * 2. The route then called `reply.raw.writeHead(200, { ... })`. Node's
 *    `writeHead` with an explicit headers object **replaces** the header set
 *    rather than merging it, which discarded the `corsHeaders` the hook had
 *    already applied with `reply.header()`.
 *
 * So cause 1 emptied the compensation and cause 2 removed the fallback. Fixing
 * either alone would still leave the other.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { buildServer, type ServerDeps } from "../src/server.js";
import { ApiConfig, validateOrigins } from "../src/config.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { FakeOrchestrator } from "../mock/fake-orchestrator.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";

const ORIGIN = "https://microsoft-onenote-exporter.phttp.com";
const SECRET = "A".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

const config: ApiConfig = {
  allowedOrigins: validateOrigins(ORIGIN),
  csrfKey: "C".repeat(43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  publicOrigin: "https://one-backend.phttp.com",
  orchestratorUrl: "http://mock:9100",
  orchestratorSecret: "B".repeat(43),
  orchestratorReplayWindowSeconds: 60,
  logLevel: "silent",
  listen: "127.0.0.1:0",
  databasePath: ":memory:",
  sseBufferEvents: 500,
  sseKeepaliveMs: 15_000,
};

let db: Db;
let app: FastifyInstance;

beforeEach(async () => {
  db = new Db(":memory:");
  db.createSession({
    guid: GUID,
    secretHash: hashSecret(SECRET),
    csrfKey: generateCsrfKey(),
    now: Date.now(),
    expiresAt: Date.now() + 43_200_000,
  });
  const deps: ServerDeps = {
    db,
    sse: new SseHub({ now: () => Date.now() }),
    limiter: new RateLimiter({ logSalt: "t" }),
    orchestrator: new FakeOrchestrator({ size: 1 }),
  };
  app = buildServer(config, deps);
  await app.ready();
});

afterEach(async () => {
  await app.close();
  db.close();
});

function cookie(): string {
  return `${SESSION_COOKIE}=${GUID}:${SECRET}`;
}

/**
 * Opens the stream over a real socket, reads the response headers, then aborts.
 *
 * `app.inject` waits for the response to *complete*, and an SSE stream does not
 * complete until it is closed — so inject hangs for the full timeout. A real
 * `fetch` with an AbortController gets the headers as soon as they arrive, which is
 * also exactly what a browser does: it decides on the headers, before a single
 * frame has been parsed.
 */
async function openStream(
  headers: Record<string, string>,
): Promise<{ status: number; headers: Record<string, string> }> {
  const address = await app.listen({ host: "127.0.0.1", port: 0 });
  const controller = new AbortController();
  try {
    const response = await fetch(`${address}/api/session/events`, {
      headers,
      signal: controller.signal,
    });
    // Headers are available now; abort so the socket closes.
    const out: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      out[key.toLowerCase()] = value;
    });
    controller.abort();
    return { status: response.status, headers: out };
  } finally {
    controller.abort();
    await app.close();
  }
}

/*
 * Cause 1 (`ctx.origin` unset on reads) is not asserted directly. It cannot be,
 * without a way to observe a handler's context — and it does not need to be: if
 * `ctx.origin` is unset, or if `writeHead` clobbers the header, then the ACAO
 * assertion below fails. Both causes have to be true for the bug, and the symptom
 * test fails if either is reintroduced, which is the property worth having.
 */
describe("GET /api/session/events", () => {
  it("carries ACAO and ACAC on the streaming 200, not just on the 401", async () => {
    // The regression. The 401 has always had them; the 200 never did.
    const unauthorized = await app.inject({
      method: "GET",
      url: "/api/session/events",
      headers: { origin: ORIGIN },
    });
    expect(unauthorized.statusCode).toBe(401);
    // If this ever stops being true the test below stops being meaningful, so it is
    // asserted here rather than assumed.
    expect(unauthorized.headers["access-control-allow-origin"]).toBe(ORIGIN);

    const response = await openStream({ origin: ORIGIN, cookie: cookie() });

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toMatch(/text\/event-stream/);
    // The whole point. A browser refuses a cross-origin EventSource without these.
    expect(response.headers["access-control-allow-origin"]).toBe(ORIGIN);
    // credentials: true is required for withCredentials to send the cookie at all,
    // so an EventSource would 401 on every reconnect without it.
    expect(response.headers["access-control-allow-credentials"]).toBe("true");
    // Vary: Origin must survive too, or a cache would serve this ACAO to another
    // origin and turn the allowlist into a suggestion.
    expect(response.headers["vary"]).toMatch(/origin/i);
  });

  it("still emits the streaming headers the proxy and the EventSource need", async () => {
    // The fix must not cost anything that was already working: X-Accel-Buffering
    // stops Caddy buffering the stream into one lump at close, which looks exactly
    // like a broken event stream.
    const response = await openStream({ origin: ORIGIN, cookie: cookie() });
    expect(response.headers["x-accel-buffering"]).toBe("no");
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it("gives a foreign origin no ACAO on the stream, and still 200s", async () => {
    // The negative half, which the old suite did assert. Kept because the fix
    // makes ACAO present on this path for the first time, so the way to get that
    // wrong is to emit it unconditionally.
    const response = await openStream({ origin: "https://evil.test", cookie: cookie() });
    expect(response.status).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    // Vary regardless: the absence of ACAO is itself origin-dependent.
    expect(response.headers["vary"]).toMatch(/origin/i);
  });

  it("keeps ACAO off a same-origin request with no Origin header", async () => {
    const response = await openStream({ cookie: cookie() });
    expect(response.status).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

});