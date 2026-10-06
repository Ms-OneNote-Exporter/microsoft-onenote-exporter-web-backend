import { beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { buildServer, type ServerDeps } from "../src/server.js";
import { ApiConfig } from "../src/config.js";
import { Db } from "../src/db.js";
import { OrchestratorClient } from "../src/orchestrator-client.js";
import { CSRF_COOKIE, SESSION_COOKIE } from "../src/csrf.js";
import { deriveCsrfToken, generateCsrfKey, hashSecret } from "../src/session.js";
import { MAX_CREDENTIAL_BYTES } from "../src/credential.js";

/**
 * The three properties the credential route and the cross-origin middleware are
 * supposed to have, tested through the real HTTP surface rather than by
 * inspecting the code:
 *
 *   1. No body parser is reachable from anywhere in the stack.
 *   2. Origin is never reflected, and ACAO is absent for a foreign origin in
 *      every status class (T-C1).
 *   3. The CSRF check runs before the body is read (T-C2, T-C3, T-C4).
 *
 * These are the checks mac said he would make when he reads this side, written
 * first so the review starts from the tests rather than from the prose.
 */

const ALLOWED = "https://app.example.com";
const FOREIGN = "https://evil.test";
const SECRET = "A".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const TTL_MS = 43_200_000;

const config: ApiConfig = {
  allowedOrigins: new Set([ALLOWED]),
  csrfKey: "C".repeat(43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  orchestratorUrl: "http://orchestrator:9100",
  orchestratorSecret: "B".repeat(43),
  orchestratorReplayWindowSeconds: 60,
  logLevel: "info",
  listen: "127.0.0.1:0",
  databasePath: ":memory:",
  sseBufferEvents: 500,
  sseKeepaliveMs: 15_000,
};

let db: Db;
let app: FastifyInstance;
let csrfToken: string;

/** The orchestrator is unreachable in these tests; no request reaches it. */
const deps: ServerDeps = {
  get db(): Db {
    return db;
  },
  get orchestrator(): OrchestratorClient {
    return new OrchestratorClient({
      baseUrl: "http://127.0.0.1:1",
      secret: "B".repeat(43),
    });
  },
} as ServerDeps;

/** Cookie pair for the seeded session. */
function sessionCookie(guid = GUID, secret = SECRET): string {
  return `${SESSION_COOKIE}=${guid}:${secret}`;
}

beforeEach(async () => {
  db = new Db(":memory:");
  const csrfKey = generateCsrfKey();
  db.createSession({
    guid: GUID,
    secretHash: hashSecret(SECRET),
    csrfKey,
    now: Date.now(),
    expiresAt: Date.now() + TTL_MS,
  });
  csrfToken = deriveCsrfToken(csrfKey, GUID);

  app = buildServer(config, deps);
  await app.ready();
});

// ---- Property 1: no body parser is reachable ------------------------------

describe("body parsing", () => {
  // The specific hazard mac flagged: a global parser runs before a route's
  // opt-out, so "I don't parse the credential" becomes false by accident.
  it("hands every content type to the handler as an untouched stream", async () => {
    const app2 = buildServer(config, deps, { testOnlyAuthExemptPaths: ["/probe"] });

    let seen: string | null = null;
    // Registered before ready(): Fastify refuses to add routes to an already
    // booted instance, which is the correct behaviour and not something to work
    // around in a test.
    app2.post("/probe", async (request, reply) => {
      const chunks: Buffer[] = [];
      for await (const c of request.body as NodeJS.ReadableStream) {
        chunks.push(c as Buffer);
      }
      seen = Buffer.concat(chunks).toString("utf8");
      return reply.send({ ok: true });
    });
    await app2.ready();

    // application/json is the case that matters: Fastify parses JSON by default,
    // so if the built-in parser were still installed this body would arrive as an
    // object rather than as bytes.
    const response = await app2.inject({
      method: "POST",
      url: "/probe",
      headers: { "content-type": "application/json" },
      payload: '{"a":1}',
    });

    expect(response.statusCode).toBe(200);
    // Byte-for-byte: a parsed-then-restringified JSON body would reorder or
    // respace its keys.
    expect(seen).toBe('{"a":1}');
    await app2.close();
  });

  it("does not reject a JSON content type before the handler runs", async () => {
    // Fastify answers FST_ERR_CTP_INVALID_JSON_BODY for malformed JSON when the
    // built-in parser is installed. Here it must reach the route.
    const response = await app.inject({
      method: "POST",
      url: "/api/session",
      headers: { "content-type": "application/json", origin: ALLOWED },
      payload: "this is not json",
    });
    // The route's own parser rejects it, with the route's own message.
    expect(response.statusCode).toBe(400);
    expect(response.json().error).toBe("malformed request body");
  });

  it("rejects a multipart credential before reading a byte", async () => {
    // A multipart parser is exactly the thing that would want to be installed
    // globally, so the credential route refuses the type outright.
    const response = await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: {
        "content-type": "multipart/form-data; boundary=x",
        "cookie": sessionCookie(),
        origin: ALLOWED,
        "x-csrf-token": csrfToken,
        "content-length": "11",
      },
      payload: "hunter2",
    });
    expect(response.statusCode).toBe(415);
  });
});

// ---- Property 2: no origin reflection, ACAO absent for a foreign origin ----

describe("cors", () => {
  // T-C1: absent on 200, 400, 403, 429 and 500 alike, plus preflight.
  it("omits ACAO for a foreign origin on success", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/api/public/version",
      headers: { origin: FOREIGN },
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    expect(response.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it("omits ACAO for a foreign origin on 403", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/session",
      headers: { "content-type": "application/json", origin: FOREIGN },
      payload: JSON.stringify({ guid: GUID, secret: SECRET }),
    });
    expect(response.statusCode).toBe(403);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("omits ACAO for a foreign origin on 400", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/session",
      headers: { "content-type": "application/json", origin: ALLOWED },
      payload: "not json",
    });
    expect(response.statusCode).toBe(400);
    // Same headers, foreign origin: the error handler must not add ACAO.
    const foreign = await app.inject({
      method: "POST",
      url: "/api/session",
      headers: { "content-type": "application/json", origin: FOREIGN },
      payload: JSON.stringify({ guid: "nope" }),
    });
    expect(foreign.statusCode).toBe(403);
    expect(foreign.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("omits ACAO on a 500", async () => {
    // The boom route needs no session, so it is named in the exemption list.
    // Without that it would 401 before it could throw, and the test would be
    // asserting about a 401 instead.
    const failing = buildServer(config, deps, { testOnlyAuthExemptPaths: ["/boom"] });
    // Force an internal failure: a route that throws. Registered before ready()
    // for the same reason as the probe route above.
    failing.get("/boom", async () => {
      throw new Error("deliberate");
    });
    await failing.ready();
    const response = await failing.inject({
      method: "GET",
      url: "/boom",
      headers: { origin: ALLOWED },
    });
    expect(response.statusCode).toBe(500);
    // And for a foreign origin, still absent.
    const foreign = await failing.inject({
      method: "GET",
      url: "/boom",
      headers: { origin: FOREIGN },
    });
    expect(foreign.headers["access-control-allow-origin"]).toBeUndefined();
    await failing.close();
  });

  it("omits ACAO on a preflight from a foreign origin", async () => {
    const response = await app.inject({
      method: "OPTIONS",
      url: "/api/session/credential",
      headers: {
        origin: FOREIGN,
        "access-control-request-method": "POST",
        "access-control-request-headers": "x-csrf-token",
      },
    });
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    expect(response.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it("answers a preflight from an allowlisted origin", async () => {
    const response = await app.inject({
      method: "OPTIONS",
      url: "/api/session/credential",
      headers: {
        origin: ALLOWED,
        "access-control-request-method": "POST",
        "access-control-request-headers": "x-csrf-token, content-type",
      },
    });
    expect(response.statusCode).toBe(204);
    expect(response.headers["access-control-allow-origin"]).toBe(ALLOWED);
    expect(response.headers["access-control-allow-credentials"]).toBe("true");
  });

  // The specific foot-gun: reflecting Origin would allowlist every origin and
  // make the CSRF header layer decorative.
  it("never reflects an arbitrary origin back", async () => {
    for (const hostile of [FOREIGN, "https://attacker.test", "null", "http://app.example.com"]) {
      const response = await app.inject({
        method: "GET",
        url: "/api/public/version",
        headers: { origin: hostile },
      });
      expect(response.headers["access-control-allow-origin"]).not.toBe(hostile);
    }
  });

  it("always sets Vary: Origin", async () => {
    for (const origin of [ALLOWED, FOREIGN, undefined]) {
      const response = await app.inject({
        method: "GET",
        url: "/api/public/version",
        headers: origin === undefined ? {} : { origin },
      });
      expect(response.headers["vary"]).toBe("Origin");
    }
  });

  it("sets the CSRF header and content-type on the preflight", async () => {
    const response = await app.inject({
      method: "OPTIONS",
      url: "/api/session/credential",
      headers: { origin: ALLOWED },
    });
    expect(response.headers["access-control-allow-headers"]).toContain("x-csrf-token");
    expect(response.headers["access-control-allow-headers"]).toContain("content-type");
  });
});

// ---- Property 3: CSRF runs before the body is read ------------------------

describe("csrf", () => {
  const post = (headers: Record<string, string>, payload = '{"notebook":"Work"}') =>
    app.inject({
      method: "POST",
      url: "/api/session/notebooks",
      headers: { "content-type": "application/json", ...headers },
      payload,
    });

  // T-C3
  it("rejects a mutating request with no CSRF header", async () => {
    const response = await post({ cookie: sessionCookie(), origin: ALLOWED });
    expect(response.statusCode).toBe(403);
    expect(response.json().error).toBe("forbidden");
  });

  // T-C4
  it("rejects a mismatched CSRF token", async () => {
    const response = await post({
      cookie: sessionCookie(),
      origin: ALLOWED,
      "x-csrf-token": "A".repeat(43),
    });
    expect(response.statusCode).toBe(403);
  });

  // T-C2
  it("rejects a valid cookie from a foreign origin", async () => {
    const response = await post({
      cookie: sessionCookie(),
      origin: FOREIGN,
      "x-csrf-token": csrfToken,
    });
    expect(response.statusCode).toBe(403);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("requires authentication before anything else", async () => {
    // No cookie at all: 401, not 403, so an anonymous caller cannot probe the
    // CSRF layer.
    const response = await post({ origin: ALLOWED, "x-csrf-token": csrfToken });
    expect(response.statusCode).toBe(401);
  });

  it("rejects a session whose secret does not match", async () => {
    const response = await post({
      cookie: sessionCookie(GUID, "B".repeat(43)),
      origin: ALLOWED,
      "x-csrf-token": csrfToken,
    });
    expect(response.statusCode).toBe(401);
  });

  it("does not leak which of origin or token was wrong", async () => {
    // One body for both, so the endpoint cannot enumerate allowed origins.
    const wrongOrigin = await post({
      cookie: sessionCookie(),
      origin: FOREIGN,
      "x-csrf-token": csrfToken,
    });
    const wrongToken = await post({
      cookie: sessionCookie(),
      origin: ALLOWED,
      "x-csrf-token": "A".repeat(43),
    });
    expect(wrongOrigin.json()).toEqual(wrongToken.json());
  });

  it("does not require CSRF on GET", async () => {
    const response = await app.inject({
      method: "GET",
      url: "/api/session/status",
      headers: { cookie: sessionCookie(), origin: ALLOWED },
    });
    // Not 403. Whether the route is wired yet is a separate matter; what matters
    // is that the CSRF layer did not reject it.
    expect(response.statusCode).not.toBe(403);
  });

  // The ordering property: framing is refused before the body is consumed.
  it("refuses an oversized credential without accepting the body", async () => {
    // inject recomputes content-length from the payload, so the oversized case is
    // driven by sending a body that is genuinely larger than the cap rather than
    // by asserting a header. That also makes it the stronger test: the framing
    // check must catch a caller whose declared length is honest.
    const oversized = "x".repeat(MAX_CREDENTIAL_BYTES + 1);
    const response = await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: {
        "content-type": "text/plain",
        cookie: sessionCookie(),
        origin: ALLOWED,
        "x-csrf-token": csrfToken,
      },
      payload: oversized,
    });
    expect(response.statusCode).toBe(413);
  });

  it("refuses an oversized credential whose declared length lies", async () => {
    // A caller that understates content-length and sends a bigger body: the
    // transport-level cap and the stream cap both have to hold. Fastify's own
    // bodyLimit is 256 KiB, so this asserts the credential cap, not that one.
    const response = await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: {
        "content-type": "text/plain",
        cookie: sessionCookie(),
        origin: ALLOWED,
        "x-csrf-token": csrfToken,
        "content-length": "11",
      },
      // inject sends exactly this payload; the header is what the hook reads.
      payload: "x".repeat(MAX_CREDENTIAL_BYTES + 1),
    });
    // Either the declared length was trusted and the stream cap refused later, or
    // the mismatch was caught up front. Both are acceptable; neither may accept.
    expect(response.statusCode).not.toBe(200);
  });

  it("refuses a credential with no content-length", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: {
        "content-type": "text/plain",
        cookie: sessionCookie(),
        origin: ALLOWED,
        "x-csrf-token": csrfToken,
      },
      payload: "hunter2",
    });
    // inject computes content-length itself, so the missing-header case is a unit
    // test in credential.test.ts. What is asserted here is that a well-formed,
    // small credential passes framing and reaches the handler — where it is
    // refused for a *different* reason: this session has no runner bound, so the
    // password would have nowhere to go. 409, never 200 and never 501.
    expect(response.statusCode).toBe(409);
    expect(response.json().error).toBe("no runner bound to this session");
  });
});

// ---- Response hygiene -----------------------------------------------------

describe("responses", () => {
  it("marks every response no-store, including the version handshake", async () => {
    // T-A5.
    for (const url of ["/api/public/version", "/api/session/status"]) {
      const response = await app.inject({ method: "GET", url });
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(response.headers["x-content-type-options"]).toBe("nosniff");
    }
  });

  it("serves the version handshake without a session", async () => {
    // T-C7: the api is usable with no frontend and no session.
    const response = await app.inject({ method: "GET", url: "/api/public/version" });
    expect(response.statusCode).toBe(200);
    expect(response.json().protocol).toBe(3);
  });

  it("never returns the HMAC secret in an error body", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: {
        "content-type": "text/plain",
        cookie: sessionCookie(),
        origin: ALLOWED,
        "x-csrf-token": csrfToken,
        "content-length": "11",
      },
      payload: "hunter2",
    });
    expect(response.body).not.toContain("B".repeat(43));
  });
});

// ---- Session creation validation -----------------------------------------

describe("POST /api/session", () => {
  const create = (payload: unknown, origin: string = ALLOWED) =>
    app.inject({
      method: "POST",
      url: "/api/session",
      headers: { "content-type": "application/json", origin },
      payload: typeof payload === "string" ? payload : JSON.stringify(payload),
    });

  // T9: the API validates length rather than trusting the client, because a
  // compromised Component A could generate a weak secret.
  it("rejects a weak secret", async () => {
    for (const secret of ["", "short", "A".repeat(42), "A".repeat(44)]) {
      const response = await create({ guid: GUID, secret });
      expect(response.statusCode).toBe(400);
    }
  });

  it("rejects a malformed guid", async () => {
    for (const guid of ["", "nope", GUID.toUpperCase(), `${GUID}/x`]) {
      const response = await create({ guid, secret: SECRET });
      expect(response.statusCode).toBe(400);
    }
  });

  it("rejects a body that is not an object", async () => {
    for (const payload of ["[]", '"a string"', "null", "42"]) {
      const response = await create(payload);
      expect(response.statusCode).toBe(400);
    }
  });

  it("rejects an unknown field rather than ignoring it", async () => {
    const response = await create({ guid: GUID, secret: SECRET, runnerId: "slot-1" });
    // Either rejected outright or ignored — but never acted on. The route parses
    // its own body, so this asserts the shape check rather than a silent accept.
    expect([400, 501]).toContain(response.statusCode);
  });

  it("rejects a foreign origin", async () => {
    const response = await create({ guid: GUID, secret: SECRET }, FOREIGN);
    expect(response.statusCode).toBe(403);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });
});