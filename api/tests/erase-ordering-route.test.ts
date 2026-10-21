/**
 * The route half of the erase/cookie ordering: `POST /api/session` must not
 * answer while a session it presents the cookie of is being erased.
 *
 * The module's own contract is in `erase-ordering.test.ts`; the race, measured
 * on the deployed host, is in `api/src/erase-ordering.ts`'s header.
 *
 * These cases are behavioural on purpose — they drive the routes over HTTP and
 * watch the **responses**, not the registry's internals, because a test that
 * reaches into the implementation proves the implementation rather than the
 * behaviour.
 */
import { describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { buildServer, type ServerDeps } from "../src/server.js";
import { ApiConfig } from "../src/config.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { deriveCsrfToken, generateCsrfKey, hashSecret } from "../src/session.js";
import { FakeOrchestrator } from "../mock/fake-orchestrator.js";

const ALLOWED = "https://app.example.com";
const SECRET = "A".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const NEW_GUID = "4f2504e0-4f89-11d3-9a0c-0305e82c3301";
const TTL = 43_200_000;

const config: ApiConfig = {
  allowedOrigins: new Set([ALLOWED]),
  csrfKey: "C".repeat(43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  publicOrigin: "https://one-backend.example.com",
  orchestratorUrl: "http://orchestrator:9100",
  orchestratorSecret: "B".repeat(43),
  orchestratorReplayWindowSeconds: 60,
  logLevel: "info",
  listen: "127.0.0.1:0",
  databasePath: ":memory:",
  sseBufferEvents: 500,
  sseKeepaliveMs: 15_000,
};

/** A tick, for letting a pending promise have its chance to settle. */
const tick = () => new Promise((resolve) => setTimeout(resolve, 25));

describe("POST /api/session — a create is ordered against the erase it presents", () => {
  /**
   * The fixture: a session with a runner, an erase whose machine is held open
   * until the test releases it, and the ability to make a create that presents
   * the erasing session's cookie.
   */
  async function fixture() {
    const db = new Db(":memory:");
    const sse = new SseHub();
    const limiter = new RateLimiter({ logSalt: "t" });
    const orchestrator = new FakeOrchestrator({ size: 1 });

    const csrfKey = generateCsrfKey();
    db.createSession({
      guid: GUID,
      secretHash: hashSecret(SECRET),
      csrfKey,
      now: Date.now(),
      expiresAt: Date.now() + TTL,
    });
    db.run(
      `UPDATE sessions SET state = 'authenticated', runner_id = 'slot-1', auth_state = 'valid' WHERE guid = ?`,
      GUID,
    );
    db.registerRunner("slot-1", "container-1", "active");
    db.run(`UPDATE runners SET session_guid = ? WHERE id = 'slot-1'`, GUID);

    // The erase's runner: held open until the test lets it go.
    let releaseRunner: (() => void) | null = null;
    const held = new Promise<void>((resolve) => {
      releaseRunner = resolve;
    });
    const eraseRunner = {
      async abort() {
        await held;
      },
      async freeze() {
        await held;
      },
      async shredDirectory() {
        await held;
      },
    };

    const deps: ServerDeps = {
      db,
      sse,
      limiter,
      orchestrator,
      eraseRunner,
    };
    const app: FastifyInstance = buildServer(config, deps);
    await app.ready();

    const cookie = `${SESSION_COOKIE}=${GUID}:${SECRET}`;
    const csrf = deriveCsrfToken(csrfKey, GUID);

    return {
      app,
      db,
      cookie,
      csrf,
      releaseRunner: () => releaseRunner?.(),
    };
  }

  /** Starts an erase and does not wait for it. */
  function startErase(f: Awaited<ReturnType<typeof fixture>>) {
    return f.app.inject({
      method: "POST",
      url: "/api/session/erase",
      headers: { cookie: f.cookie, "x-csrf-token": f.csrf, origin: ALLOWED },
    });
  }

  /** A create that presents the erasing session's cookie. */
  function createPresenting(f: Awaited<ReturnType<typeof fixture>>) {
    return f.app.inject({
      method: "POST",
      url: "/api/session",
      headers: { cookie: f.cookie, origin: ALLOWED },
      payload: { guid: NEW_GUID, secret: SECRET },
    });
  }

  /**
   * B5: a create that presents the erasing session's cookie is **held** until
   * the erase's response has been flushed, and answers afterwards.
   */
  it("holds a create that presents the erasing session's cookie until the erase's response is flushed", async () => {
    const f = await fixture();

    // The erase is in flight: its machine is held open.
    const erasing = startErase(f);
    await tick();

    // The create presents the erasing session's cookie.
    let createAnswered = false;
    const creating = createPresenting(f).then((res) => {
      createAnswered = true;
      return res;
    });

    await tick();
    await tick();
    // The erase is still running, so the create must not have answered: the
    // erase's response has not been flushed, and it would expire the cookie the
    // create is about to set.
    expect(createAnswered).toBe(false);

    // The erase finishes.
    f.releaseRunner();
    const eraseResponse = await erasing;
    expect(eraseResponse.statusCode).toBe(200);

    // And now the create answers.
    const createResponse = await creating;
    expect(createResponse.statusCode).toBe(201);

    await f.app.close();
    f.db.close();
  });

  /**
   * B6: a **restore** is neither held nor delayed. It re-issues the cookies for
   * a session that already exists, and the erase's response will expire them —
   * which is the erase's intent, not a reason to make the restore wait.
   */
  it("does not hold a restore while the session it restores is being erased", async () => {
    const f = await fixture();

    const erasing = startErase(f);
    await tick();

    // The same guid and secret: that is a restore, not a creation.
    let restoreAnswered = false;
    const restoring = f.app
      .inject({
        method: "POST",
        url: "/api/session",
        headers: { cookie: f.cookie, origin: ALLOWED },
        payload: { guid: GUID, secret: SECRET },
      })
      .then((res) => {
        restoreAnswered = true;
        return res;
      });

    await tick();
    await tick();
    expect(restoreAnswered).toBe(true);

    const restoreResponse = await restoring;
    expect(restoreResponse.statusCode).toBe(200);

    f.releaseRunner();
    await erasing;

    await f.app.close();
    f.db.close();
  });

  /**
   * The negative control: a create that presents **no** cookie is not held —
   * the wait is scoped to the cookie's session.
   */
  it("does not hold a create that presents no cookie", async () => {
    const f = await fixture();

    const erasing = startErase(f);
    await tick();

    let answered = false;
    const creating = f.app
      .inject({
        method: "POST",
        url: "/api/session",
        headers: { origin: ALLOWED },
        payload: { guid: NEW_GUID, secret: SECRET },
      })
      .then((res) => {
        answered = true;
        return res;
      });

    await tick();
    await tick();
    expect(answered).toBe(true);
    expect((await creating).statusCode).toBe(201);

    f.releaseRunner();
    await erasing;

    await f.app.close();
    f.db.close();
  });
});
