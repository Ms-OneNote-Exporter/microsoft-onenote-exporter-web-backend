/**
 * The mock server: a real `api` with a fake orchestrator and a scripted runner.
 *
 * `npm run mock` starts this instead of `npm start`.
 *
 * ## What it is for
 *
 * Letting the frontend be written, reviewed and demonstrated against a backend
 * that behaves like the real one, on a machine with no Docker socket, no Chromium
 * download and no Microsoft account.
 *
 * ## What it is not
 *
 * It is **not** evidence that the service works. Specifically:
 *
 *   - It does not read the credential bytes. It drains and discards them, because
 *     the api's guarantee is that a password is never accumulated anywhere, and a
 *     dev tool that inspected one would be a second handler for it.
 *   - It does not run any `@msout/*` package, so it tells you nothing about
 *     whether a real login or export would succeed.
 *   - It makes **no** capability claim. `T-X1`, `T-N1`, `T-X2` and `T-N4` are
 *     about what a running container can see, and nothing here changes that.
 *   - The artifacts it reports do not exist on disk. `GET /files/*` is still
 *     Caddy's job.
 *
 * ## How it stays honest
 *
 * It calls the **real** `buildServer`, with the **real** database, cookies, CSRF,
 * CORS, rate limiter, SSE hub and route handlers. Only two dependencies are
 * replaced: the orchestrator client and the runner adapter. So a status code, a
 * header, a cookie attribute or a payload shape a client depends on is produced
 * by the same code that will produce it in production.
 *
 * That is the whole reason to do it this way rather than write a standalone mock
 * server. A hand-written mock drifts, and a drifted mock is worse than none — it
 * is a contract the client builds against that the real server does not honour.
 * The CSRF-cookie blocker found in review is exactly that failure mode.
 *
 * ## Why the dev controls are a second server
 *
 * The mock wants routes the real api has no business having: "make the next login
 * ask for an MFA code", "show me what the in-memory database holds". The obvious
 * way to add them is an auth exemption, and that is exactly the shape of bug
 * found in review — an auth bypass guarded by a comment, in the component that
 * holds the session secret. It would also be shipped: `buildServer` is production
 * code, and any exemption inside it is an exemption in production.
 *
 * So the controls live in their own Fastify instance on their own loopback port,
 * with no auth because they hold no session state and no secrets — only the
 * runner's next scripted behaviour. The api port carries nothing but the real
 * route table, so `/__mock__` on it answers 401 like any other unknown path, which
 * is the honest answer and incidentally keeps the no-path-oracle property intact.
 */

import Fastify, { type FastifyInstance } from "fastify";

import { NO_PROXIES } from "../src/client-ip.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter, DEFAULT_LIMITS } from "../src/rate-limit.js";
import { buildServer } from "../src/server.js";
import { PoolBinder, syncPool } from "../src/sweep.js";
import type { ApiConfig } from "../src/config.js";
import { FakeOrchestrator } from "./fake-orchestrator.js";
import { MockRunner, type LoginScript } from "./mock-runner.js";

/**
 * Origin the mock believes the frontend runs on.
 *
 * Overridable, because CORS is an exact allowlist and a developer pointing at a
 * `localhost` frontend needs their own origin in it.
 */
const MOCK_ORIGINS = (process.env.MOCK_ALLOWED_ORIGINS ??
  "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173")
  .split(",")
  .map((s) => s.trim())
  .filter((s) => s !== "");

/**
 * The listen address.
 *
 * Loopback-only, and asserted rather than trusted: this process holds a
 * credential-shaped endpoint and a scripted runner that accepts anything.
 */
const HOST = process.env.MOCK_HOST ?? "127.0.0.1";
const PORT = Number(process.env.MOCK_PORT ?? 3000);

/** The dev control plane's port. Separate, because it has no auth by design. */
const CONTROL_PORT = Number(process.env.MOCK_CONTROL_PORT ?? PORT + 1);

/** Scripted-delay multiplier. `MOCK_SPEED=0` makes everything instant. */
const SPEED = Number(process.env.MOCK_SPEED ?? 1);

/**
 * Pool size.
 *
 * Small by default so `MOCK_POOL_SIZE=1` can demonstrate the exhausted-pool 503
 * without filling a table — which is the state worth being able to see, because it
 * is the one a user hits on a busy server.
 */
const POOL_SIZE = Number(process.env.MOCK_POOL_SIZE ?? 2);

/**
 * isLoopbackHostname reports whether a hostname can only resolve to this machine.
 *
 * Loopback names, not "private ranges": 10/8 and 192.168/16 are reachable over a
 * real network, and a mock reachable there is a service that accepts any password
 * and reports success.
 */
function isLoopbackHostname(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
  );
}

if (!isLoopbackHostname(HOST)) {
  // Not a warning: exiting. The two ports together are a service that accepts any
  // credential, reports success, and lets a caller pick the outcome.
  console.error(
    `refusing to bind ${HOST}: the mock server is loopback-only.\n` +
      "It accepts any credential and reports success, so exposing it is worse\n" +
      "than exposing nothing.",
  );
  process.exit(1);
}

/**
 * The config.
 *
 * Real validation, not a bypassed one: `ALLOWED_ORIGINS` still has to be exact
 * origins and `CSRF_KEY` still has to be 43 base64url characters. A mock that
 * skipped config validation would stop exercising the thing that catches a
 * misconfigured deployment.
 *
 * The secret is a fixed placeholder rather than a per-run random value, because
 * every run of the mock must be reachable by a frontend started separately and
 * both must agree on it. It is a development placeholder with a documented shape,
 * not a key to anything, and it is deliberately obvious in source.
 */
const config: ApiConfig = {
  // The mock is reached directly by a developer on localhost, so there is no proxy
  // in front of it and nothing to believe. Named `NO_PROXIES` rather than left as an
  // empty collection, so it says which of "no proxy" and "not configured" this is —
  // they are the same to the limiter, and telling them apart is the whole bug.
  trustedProxies: NO_PROXIES,
  allowedOrigins: new Set(
    MOCK_ORIGINS.map((entry) => {
      // The mock's origins are http, because a development frontend is served over
      // http on localhost. That is the one place the production rule is relaxed,
      // and it is relaxed only for loopback — config.ts enforces that too, so a
      // hostile entry here would have been rejected before it got this far.
      const url = new URL(entry);
      if (url.protocol === "http:" && !isLoopbackHostname(url.hostname)) {
        throw new Error(
          `MOCK_ALLOWED_ORIGINS: ${entry} is http on a non-loopback host. ` +
            "The mock must not be reachable from a network.",
        );
      }
      return url.origin;
    }),
  ),
  csrfKey: process.env.CSRF_KEY ?? "mock".padEnd(43, "0").slice(0, 43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  orchestratorUrl: "http://mock:9100",
  orchestratorSecret: "mock".padEnd(43, "0").slice(0, 43),
  orchestratorReplayWindowSeconds: 60,
  // Present so the config shape matches production and a field added later does
  // not break the mock's build. Never read: the mock has no runner, and a
  // plausible-looking value here would suggest otherwise.
  runnerToken: "mock".padEnd(43, "0").slice(0, 43),
  logLevel: process.env.LOG_LEVEL === "debug" ? "debug" : "info",
  listen: `${HOST}:${PORT}`,
  // The mock serves both ports, and a download pointed at the control port would
  // be a 501. The api port is the one the api origin names.
  publicOrigin: `http://${HOST}:${PORT}`,
  databasePath: process.env.MOCK_DB ?? ":memory:",
  sseBufferEvents: 500,
  sseKeepaliveMs: 15_000,
  // The mock is a development server, so it keeps the committed default rather
  // than the raised live value. A developer looping on the chain locally is the
  // case the small number suits; a deployment that proves the chain repeatedly
  // raises it in its own environment.
  sessionsPerHour: DEFAULT_LIMITS.sessionsPerWindow.max,
};

/**
 * The dev control plane.
 *
 * Its own Fastify instance, its own port, no auth, no session, no cookies. It can
 * only do two things: choose the next scripted login outcome, and show what the
 * in-memory database holds. Neither is reachable from the api port.
 */
function buildControlPlane(
  runner: MockRunner,
  orchestrator: FakeOrchestrator,
  db: Db,
): FastifyInstance {
  const control = Fastify({ logger: { level: config.logLevel } });

  control.get("/", async (_request, reply) =>
    reply.send({
      mock: true,
      whatThisIs:
        "Dev controls for a mock api. No session state and no secrets here — it " +
        "can only pick the next scripted login outcome and dump the in-memory db.",
      api: { listen: `${HOST}:${PORT}`, allowedOrigins: [...config.allowedOrigins] },
      faked: [
        "the Docker socket (an in-process pool, not a daemon)",
        "the runner (no @msout package runs)",
      ],
      discarded: "the credential bytes, without being read",
      notProven: [
        "T-X1 / T-N1 / T-X2 / T-N4 — those need a real stack",
        "that a real login or export would succeed",
        "that /files/* works — that is Caddy's job",
      ],
      nextLogin: runner.peekNextLogin(),
      pool: { size: orchestrator.poolSize, free: orchestrator.freeSlots, slotIds: orchestrator.slotIds() },
      database: config.databasePath,
      scripts: {
        success: "logs in immediately",
        "mfa-code": "emits a `challenge` of kind `code`, then stops",
        "mfa-number": "emits a `challenge` of kind `number-match`, then stops",
        "bad-password": "emits `login-failed` with code bad_credentials",
        timeout: "hangs, then emits `challenge-expired` (PLAN-v2 §6.1)",
      },
    }),
  );

  control.post<{ Params: { script: string } }>("/login/:script", async (request, reply) => {
    const valid: LoginScript[] = [
      "success",
      "mfa-code",
      "mfa-number",
      "bad-password",
      "timeout",
    ];
    const script = request.params.script;
    if (!valid.includes(script as LoginScript)) {
      return reply.code(400).send({ error: "unknown script", valid });
    }
    runner.setNextLogin(script as LoginScript);
    request.log.info({ script }, "mock: next login behaviour set");
    return reply.send({ nextLogin: script });
  });

  control.get("/sessions", async (_request, reply) =>
    reply.send({
      sessions: db.all(
        `SELECT guid, state, auth_state, notebook, artifact_id, export_state FROM sessions`,
      ),
    }),
  );

  return control;
}

async function main(): Promise<void> {
  const db = new Db(config.databasePath);
  const sse = new SseHub({
    bufferEvents: config.sseBufferEvents,
    keepaliveMs: config.sseKeepaliveMs,
  });
  sse.startKeepalive();

  const limiter = new RateLimiter({ logSalt: "mock" });
  const orchestrator = new FakeOrchestrator({ size: POOL_SIZE });
  const runner = new MockRunner({ db, sse, speed: SPEED });

  // Seed the api's `runners` table with the orchestrator's slot ids.
  //
  // This is a boot step the real entrypoint will also need, and it is the step
  // whose absence is invisible until a login 503s: `runners` starts empty,
  // `claimRunner` only ever moves a row, so nothing is ever inserted and the pool
  // reads as permanently exhausted.
  //
  // The ids come from the orchestrator because `sessions.runner_id` holds one and
  // `release`/`recycle` take it back as a `slotId`. The real `/stats` returns
  // counts only, so this is the one place the production wiring needs a change I
  // have not made — see `syncPool`'s comment.
  const pool = syncPool(db, orchestrator.slotIds());

  // The real pool binder, so the lazy claim on login runs the production code —
  // SQLite claim, orchestrator claim, compensation on failure. Faking it would
  // mean the mock exercised a path the deployment does not take.
  const poolBinder = new PoolBinder({ db, orchestrator, sse, now: () => Date.now() });

  // The real api, on the real port, with the real route table and nothing added.
  const api = buildServer(config, {
    db,
    sse,
    limiter,
    orchestrator,
    runner,
    eraseRunner: runner,
    poolBinder,
  });

  // The dev controls, on their own port, with no auth by design.
  const control = buildControlPlane(runner, orchestrator, db);

  await api.listen({ host: HOST, port: PORT });
  await control.listen({ host: HOST, port: CONTROL_PORT });

  const line = "─".repeat(72);
  console.log(`
${line}
  MOCK API — not the service.

  api        http://${HOST}:${PORT}          the real handlers, real cookies, real CSRF
  controls   http://${HOST}:${CONTROL_PORT}          GET / for what is faked

  pool       ${pool.total} slot(s), seeded at boot
  origins    ${[...config.allowedOrigins].join(", ")}
  database   ${config.databasePath}

  Faked:      the Docker socket, and the runner (no @msout package runs).
  Discarded:  the credential bytes, without being read.
  Not proven: T-X1, T-N1, T-X2, T-N4 — those need a real stack.

  Point the frontend at the api port. The controls port has no auth.
${line}
`);

  const shutdown = async (signal: string): Promise<void> => {
    console.log(`\n${signal} received, shutting the mock down`);
    sse.stopKeepalive();
    await Promise.allSettled([api.close(), control.close()]);
    db.close();
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

// A stray rejection in a dev tool should print, not vanish.
process.on("unhandledRejection", (reason) => {
  console.error("mock server: unhandled rejection", reason);
});

main().catch((error: unknown) => {
  console.error("mock server failed to start:", error);
  process.exit(1);
});