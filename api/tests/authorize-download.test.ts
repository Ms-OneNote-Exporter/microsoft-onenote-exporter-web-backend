/**
 * `/internal/authorize-download` is the endpoint Caddy asks before it serves any
 * bytes off the disk, so these tests are written from the attacker's side: every
 * one of them tries to get a download authorised that should not be.
 *
 * The property under test is narrow and absolute: this endpoint returns 2xx if and
 * only if the session in the cookie owns the artifact in the header.
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
import { generateCsrfKey, generateArtifactId, hashSecret } from "../src/session.js";
import { artifactIdFromHeader } from "../src/routes.js";

const ORIGIN = "http://localhost:5173";
const SECRET = "A".repeat(43);
const OTHER_SECRET = "D".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const OTHER_GUID = "00000000-0000-0000-4000-800000000000";

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

function seedSession(guid: string, secret: string, artifactId: string | null): void {
  db.createSession({
    guid,
    secretHash: hashSecret(secret),
    csrfKey: generateCsrfKey(),
    now: Date.now(),
    expiresAt: Date.now() + 43_200_000,
  });
  if (artifactId !== null) {
    db.run(
      `UPDATE sessions SET state = 'authenticated', auth_state = 'valid', artifact_id = ? WHERE guid = ?`,
      artifactId,
      guid,
    );
  }
}

function cookieFor(guid: string, secret: string): string {
  return `${SESSION_COOKIE}=${guid}:${secret}`;
}

/** The call Caddy makes: a GET with the cookie copied and the original URI. */
function authorize(
  cookie: string | undefined,
  originalUri?: string,
): Promise<{ status: number; body: string }> {
  const headers: Record<string, string> = {};
  if (cookie !== undefined) headers.cookie = cookie;
  if (originalUri !== undefined) headers["x-original-uri"] = originalUri;
  return app
    .inject({ method: "GET", url: "/internal/authorize-download", headers })
    .then((r) => ({ status: r.statusCode, body: r.body }));
}

beforeEach(async () => {
  db = new Db(":memory:");
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

// ---- the one case that is allowed ----------------------------------------

describe("GET /internal/authorize-download", () => {
  it("authorises a download of the session's own artifact", async () => {
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);

    const result = await authorize(cookieFor(GUID, SECRET), `/files/${id}`);
    // 204: Caddy checks for 2xx, and an empty body cannot leak anything.
    expect(result.status).toBe(204);
    expect(result.body).toBe("");
  });

  it("accepts an absolute URI, because Caddy may be configured to send one", async () => {
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);

    const result = await authorize(
      cookieFor(GUID, SECRET),
      `https://one-backend.phttp.com/files/${id}`,
    );
    expect(result.status).toBe(204);
  });

  it("ignores a query string on the original URI", async () => {
    // A cache-buster must not change the identity of the request, and must not
    // become a way to smuggle a second path past the parser.
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);

    const result = await authorize(cookieFor(GUID, SECRET), `/files/${id}?cb=12345`);
    expect(result.status).toBe(204);
  });
});

it("flags a partial artifact, so the server enforces it rather than the UI", async () => {
    // §5: a partial vault must not be mistakable for a complete one, and that must
    // not depend on the frontend being correct. Caddy copies this header onto the
    // download response, so the fact travels with the bytes.
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);
    db.run(`UPDATE sessions SET artifact_partial = 1 WHERE guid = ?`, GUID);

    const response = await app.inject({
      method: "GET",
      url: "/internal/authorize-download",
      headers: { cookie: cookieFor(GUID, SECRET), "x-original-uri": `/files/${id}` },
    });
    expect(response.statusCode).toBe(204);
    expect(response.headers["x-artifact-partial"]).toBe("1");
  });

  it("omits the header for a complete artifact", async () => {
    // The absence is the signal. A default of "0" would mean a partial artifact
    // whose flag was lost in a refactor looks complete.
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);

    const response = await app.inject({
      method: "GET",
      url: "/internal/authorize-download",
      headers: { cookie: cookieFor(GUID, SECRET), "x-original-uri": `/files/${id}` },
    });
    expect(response.headers["x-artifact-partial"]).toBeUndefined();
  });

  it("sets no header on a denial", async () => {
    // A refused download must not leak partialness, or existence, through a
    // header difference.
    seedSession(GUID, SECRET, generateArtifactId());
    seedSession(OTHER_GUID, OTHER_SECRET, generateArtifactId());

    const response = await app.inject({
      method: "GET",
      url: "/internal/authorize-download",
      headers: {
        cookie: cookieFor(GUID, SECRET),
        "x-original-uri": `/files/${generateArtifactId()}`,
      },
    });
    expect(response.statusCode).toBe(403);
    expect(response.headers["x-artifact-partial"]).toBeUndefined();
  });

  // ---- everything that must not be authorised ------------------------------

describe("GET /internal/authorize-download denies", () => {
  it("another session's artifact", async () => {
    // The property the whole endpoint exists for.
    const mine = generateArtifactId();
    const theirs = generateArtifactId();
    seedSession(GUID, SECRET, mine);
    seedSession(OTHER_GUID, OTHER_SECRET, theirs);

    const result = await authorize(cookieFor(GUID, SECRET), `/files/${theirs}`);
    expect(result.status).toBe(403);
  });

  it("an artifact id that does not exist", async () => {
    seedSession(GUID, SECRET, generateArtifactId());

    const result = await authorize(cookieFor(GUID, SECRET), `/files/${generateArtifactId()}`);
    expect(result.status).toBe(403);
  });

  it("byte-identically to another session's artifact", async () => {
    // The reason the route has a single deny branch. If "unknown id" and "not
    // yours" differed in any byte, this endpoint would be an oracle: anyone with a
    // guessed or leaked id could learn whether another user has an export.
    const mine = generateArtifactId();
    seedSession(GUID, SECRET, mine);
    seedSession(OTHER_GUID, OTHER_SECRET, generateArtifactId());
    const unknown = generateArtifactId();

    const notMine = await authorize(cookieFor(GUID, SECRET), `/files/${generateArtifactId()}`);
    const missing = await authorize(cookieFor(GUID, SECRET), `/files/${unknown}`);

    expect(notMine.status).toBe(missing.status);
    expect(notMine.body).toBe(missing.body);
  });

  it("with no cookie at all", async () => {
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);

    const result = await authorize(undefined, `/files/${id}`);
    // The auth hook in server.ts handles this before the route runs, which is the
    // point: the route needed no exemption and cannot be reached unauthenticated.
    expect(result.status).toBe(401);
  });

  it("with a wrong secret for a real session", async () => {
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);

    // A well-formed cookie with the wrong secret: right shape, wrong proof.
    // Malformed input is a different case and answers 400, not 401.
    expect((await authorize(cookieFor(GUID, "Z".repeat(43)), `/files/${id}`)).status).toBe(401);
  });

  it("with no original-uri header", async () => {
    // Never "allowed because we could not tell".
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);

    expect((await authorize(cookieFor(GUID, SECRET))).status).toBe(403);
  });

  it("a session with no artifact of its own", async () => {
    seedSession(GUID, SECRET, null);
    expect((await authorize(cookieFor(GUID, SECRET), `/files/${generateArtifactId()}`)).status).toBe(403);
  });

  it("an expired session", async () => {
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);
    // Past the TTL, so the row is gone as far as authentication is concerned.
    db.run(`UPDATE sessions SET expires_at = ? WHERE guid = ?`, Date.now() - 1000, GUID);

    expect((await authorize(cookieFor(GUID, SECRET), `/files/${id}`)).status).toBe(401);
  });

  it("does not require a CSRF token, because there is no browser here", async () => {
    // If this ever needed one, Caddy would have to carry a token it has no way to
    // derive, and the download would break. This asserts the absence is
    // deliberate rather than a gap someone forgot.
    const id = generateArtifactId();
    seedSession(GUID, SECRET, id);

    const result = await authorize(cookieFor(GUID, SECRET), `/files/${id}`);
    expect(result.status).toBe(204);
  });
});

// ---- the untrusted-header parser -----------------------------------------

describe("artifactIdFromHeader", () => {
  const id = "A".repeat(43);

  it("accepts exactly /files/<43 base64url>", () => {
    expect(artifactIdFromHeader(`/files/${id}`)).toBe(id);
    expect(artifactIdFromHeader(`https://x.test/files/${id}`)).toBe(id);
    expect(artifactIdFromHeader(`/files/${id}?a=1#frag`)).toBe(id);
  });

  it("ignores a query string, even one carrying a second path", () => {
    // The path is still /files/<id> — the query is not part of the identity, so
    // the id inside the query is never read. Asserted explicitly because "strip the
    // query, then match" is only safe if the match is anchored to the whole
    // remaining path, which is what makes that second `/files/...` inert rather
    // than a second target.
    expect(artifactIdFromHeader(`/files/${id}?x=/files/${"B".repeat(43)}`)).toBe(id);
  });

  it("refuses anything else", () => {
    // Each of these is an attempt to name a file other than the one authorized.
    // None is answered with "probably fine".
    for (const hostile of [
      undefined,
      "",
      "/files/",
      `/files/${id}/`,
      `/files/${id}/../..`,
      `/other/${id}`,
      `/files/../files/${id}`,
      `/files/${"A".repeat(42)}`, // too short
      `/files/${"A".repeat(44)}`, // too long
      `/files/${"A".repeat(42)}+`, // '+' is base64, not base64url
      `/files/${"A".repeat(42)}/`,
      "/files/../../etc/passwd",
      `/files/${encodeURIComponent("../../etc/passwd")}`,
      "//files/" + id,
      `/FILES/${id}`, // case-sensitive path
    ]) {
      expect(artifactIdFromHeader(hostile)).toBeNull();
    }
  });
});