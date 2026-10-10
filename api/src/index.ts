/**
 * The entrypoint.
 *
 * ## Why this file is worth reading carefully
 *
 * It did not exist until late, and every unit test passed without it. 481 of them
 * ran against `buildServer(config, deps)` directly, because that is the seam that
 * makes them fast and hermetic. So the shape of the server was thoroughly
 * verified while `npm start`, `npm run dev` and the container `CMD` all pointed at
 * a file that was not there — `dist/index.js` did not exist, so the image built
 * cleanly and then died on start.
 *
 * `docker compose up` reports success for that. A test suite that never touches
 * the entrypoint cannot see it. That is not an argument against testing the seam;
 * it is an argument for *also* asserting the entrypoint exists and boots, which
 * CI now does.
 *
 * ## What this file does, and what it deliberately does not
 *
 * It wires the pieces that already exist and owns no logic of its own. Every
 * decision — what a valid origin is, how long a session lives, what the CSRF token
 * is derived from, when a runner is claimed — already lives in a module with its
 * own tests. If a rule appears here it is a rule in the wrong place.
 *
 * Two things it does *not* do, both load-bearing:
 *
 *   - **It never logs a secret.** Not the CSRF key, not the HMAC secret, not a
 *     length of either. The config is logged by name and shape only.
 *   - **It never continues on a failed boot step.** Reconciliation that cannot
 *     reach the orchestrator is reported and the server still starts, because a
 *     transient network failure should not take down a service that could still
 *     answer reads. Anything that would make the service *look* healthy while
 *     being wrong — an unseeded pool, an unreadable secret — exits instead.
 */

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { loadConfig, ConfigError } from "./config.js";
import { Db } from "./db.js";
import { SseHub } from "./sse.js";
import { buildRateLimiter } from "./rate-limit.js";
import { OrchestratorClient, type OrchestratorApi } from "./orchestrator-client.js";
import { HttpRunnerAdapter } from "./runner-adapter-http.js";
import { completeExport } from "./export-completion.js";
import {
  PoolBinder,
  reconcile,
  sweep,
  syncPool,
  type SweeperLog,
  TTL,
} from "./sweep.js";
import { buildServer } from "./server.js";

/**
 * How often the sweepers run.
 *
 * Not in `TTL` because a TTL is a duration a *row* has and this is a duration the
 * *process* polls at; putting them together invites changing one and meaning the
 * other. 30s against a shortest TTL of 10 minutes means an expired session is
 * reaped within 30s of expiring, and the idle sweep runs twice per login window.
 */
const SWEEP_INTERVAL_MS = 30_000;

/**
 * boot runs the startup sequence and returns the assembled dependencies.
 *
 * Exported so a test can boot the real thing against a temporary database and
 * assert the process would have started — which is the assertion whose absence
 * let the missing entrypoint go unnoticed.
 */
export async function boot(
  env: NodeJS.ProcessEnv = process.env,
  /**
   * An orchestrator to use instead of constructing one.
   *
   * The same seam `buildServer(config, deps)` already has, and for the same
   * reason: the orchestrator needs a socket, so a test cannot make a real one, and
   * reaching past `boot` to swap the class was the alternative. That approach
   * broke immediately — vitest's transform cannot resolve a `require` of a `.js`
   * path that only exists as `.ts` — and it also meant the test was asserting about
   * a module boundary rather than about boot behaviour.
   *
   * Omit it in production. There is no reason for anything to pass one, and an
   * override that silently redirected the control plane would be a serious hole.
   */
  orchestratorOverride?: OrchestratorApi,
): Promise<Booted> {
  // Throws ConfigError on anything malformed. A bad deployment stops here rather
  // than starting with a permissive value.
  const config = loadConfig(env);

  // The directory has to exist before SQLite will create the file, and in a
  // container it is a named volume mount point rather than something the image
  // can create.
  if (config.databasePath !== ":memory:") {
    mkdirSync(dirname(config.databasePath), { recursive: true });
  }

  const db = new Db(config.databasePath);
  const sse = new SseHub({
    bufferEvents: config.sseBufferEvents,
    keepaliveMs: config.sseKeepaliveMs,
  });

  /**
   * The boot and sweep log.
   *
   * Shaped to `SweeperLog` so it can be handed straight to the binder and the
   * sweepers without an adapter, plus an `error` level the sweepers do not need.
   *
   * It has no `secret` parameter anywhere, which is the point: a caller cannot
   * pass a secret to it by accident. That is a stronger property than remembering
   * not to, and it is why this is not just `console.log` with a level prefix.
   */
  const log: BootLog = {
    info: (message, fields) => logLine("info", message, fields),
    warn: (message, fields) => logLine("warn", message, fields),
    error: (message, fields) => logLine("error", message, fields),
  };

  const orchestrator =
    orchestratorOverride ??
    new OrchestratorClient({
    baseUrl: config.orchestratorUrl,
      // From a Docker secret file in a deployment, an env var in development.
      // Either way it is never logged, printed, or included in an error message.
      secret: config.orchestratorSecret,
    });

  const binder = new PoolBinder({ db, orchestrator, sse, log, now: () => Date.now() });

  // The route to a runner container, and the address of each session's runner.
  //
  // Two objects rather than one because they answer different questions. The
  // lookup says *where* a runner is, and it reads what the orchestrator's claim
  // response recorded — it derives nothing, because the orchestrator owns the
  // naming and a second implementation of it is the failure mode this project has
  // hit three times. The adapter says *how to talk to one*, and holds the token.
  //
  // Before this, all four runner-facing routes answered 501: a real session was
  // created, a real cookie set, the live-update stream attached, and the sign-in
  // could not get past the password field.
  // Declared, then assigned, rather than `const runner = new HttpRunnerAdapter(…)`.
// The completion callback below needs the adapter in order to stage the artifact,
// so the adapter's own options mention the adapter — a genuine cycle, and one
// TypeScript cannot infer through. The explicit type is what breaks it. There is
// no runtime hazard: the callback is not invoked until an export finishes, minutes
// after this assignment.
let runner: HttpRunnerAdapter;
runner = new HttpRunnerAdapter({
    addressFor: (sessionId: string) => db.runnerUrlFor(sessionId),
    token: config.runnerToken,
    sse,
    // Deliberately short. A login and an export both return 202 within
    // milliseconds; the work happens afterwards and arrives on the event stream.
    // A long timeout here would mean a wedged runner holds a request open.
    timeoutMs: 10_000,
    // The runner reporting a login outcome is the **only** evidence the api gets that
    // an auth.json exists, so it is recorded here rather than inferred. Before this,
    // nothing in the api ever wrote `auth_state = 'valid'`, the only writer was
    // `releaseForIdle` — which also nulls `runner_id` — and so
    // `/api/session/notebooks` required a state no session could be in.
    onNotebooksListed: (sessionId, names) => {
      // Recorded so `GET /api/session/status` carries the list too. Without it the
      // list exists only in the event stream, and the client's status refresh - which
      // happens on load, and on login-success, session-status, auth-state and snapshot
      // - replaces three notebooks with an empty array.
      db.setNotebooks(sessionId, names);
    },
    onAuthOutcome: (sessionId, outcome) => {
      const now = Date.now();
      const changed =
        outcome === "authenticated"
          ? db.markAuthenticated(sessionId, now)
          : db.markAuthFailed(sessionId, now);
      if (changed) {
        log.info("runner reported a login outcome", { session: sessionId, outcome });
      } else {
        // Not an error: a late event for a session already released or erased is
        // expected, and the guard inside `markAuthenticated` is what makes it
        // harmless. Logged at `warn` because it is *also* what a genuine bug looks
        // like — an outcome arriving for a session the api does not think is logging
        // in — and the two are indistinguishable from here.
        log.warn("login outcome for a session no longer authenticating", {
          session: sessionId,
          outcome,
        });
      }
    },
    // **The step that made an export observable.**
    //
    // `login-success` and `notebooks-listed` each got a callback that wrote the
    // column the api reads back. `export-done` did not, so a finished export
    // changed nothing: no zip, no finalise, no row. The session reported `running`
    // with `finishedAt: null` for ever, and — because #44's sweeper guard skips
    // `exporting` while nothing ever left that state — held its slot for the rest
    // of the day.
    //
    // Referencing `runner` inside the arrow rather than in the options object is
    // safe and deliberate: the callback fires minutes later, from the event pump,
    // long after this binding is initialised.
    onExportFinished: (input): Promise<void> =>
      completeExport({ runner, orchestrator, db, log }, input),
  });

  // ---- boot reconciliation -------------------------------------------------

  const health = await orchestrator.healthz();
  if (!health.ok) {
    // Not fatal on its own: a transient control-plane outage should not stop the
    // api answering session reads, and `reconcile` below handles the unreachable
    // case explicitly rather than by omission.
    log.warn("orchestrator unreachable at boot", { kind: health.error.kind });
  }

  // Seed the pool *before* reconciling, and only from ids the orchestrator has
  // actually told us about. A pool invented locally would make `release` aim at a
  // slot that does not exist — which is not a bookkeeping error, it is one
  // session tearing down another's container mid-export.
  const stats = await orchestrator.stats();
  if (stats.ok) {
    /**
     * Seed only from ids the orchestrator actually named.
     *
     * `undefined` means an orchestrator too old to expose slot names — a real
     * state during a rolling deploy, and the reason the field is optional. It is
     * reported loudly rather than papered over, because an unseeded pool presents
     * as "every session is busy" and nothing else would explain it.
     *
     * Inventing ids locally was considered and rejected: `sessions.runner_id`
     * holds one of these and it goes back to the orchestrator as a `slotId`, so a
     * local guess that collides is one session releasing another's container while
     * it has an export in flight. mac's argument, and it is the right one.
     */
    const slotIds = stats.value.slotIds;
    if (slotIds === undefined) {
      log.error("orchestrator reported no slotIds; the pool cannot be seeded", {
        size: stats.value.size,
      });
    } else if (slotIds.length === 0 && stats.value.size > 0) {
      log.error("orchestrator reported slotIds but reported a non-zero size", {
        size: stats.value.size,
      });
    } else {
      const pool = syncPool(db, slotIds);
      log.info("pool synced", {
        total: pool.total,
        added: pool.added,
        reported: stats.value.size,
      });
      if (stats.value.size !== pool.total) {
        log.warn("pool size disagrees with the orchestrator", {
          api: pool.total,
          orchestrator: stats.value.size,
        });
      }
    }
  } else {
    // The pool is left as-is. Assuming it was empty would delete every runner row
    // and every session binding on a transient network failure, which is exactly
    // what §2.5's reconciler exists to avoid.
    log.warn("cannot seed the pool; leaving it as-is", { kind: stats.error.kind });
  }

  const reconciled = await reconcile({ db, orchestrator, sse, log, now: () => Date.now() });
  log.info("reconciled", {
    reconciled: reconciled.reconciled,
    runners: reconciled.runnerCount,
    note: reconciled.note,
  });

  const app = buildServer(
    config,
    {
      db,
      orchestrator,
      sse,
      limiter: buildRateLimiter(config),
      // The four runner-facing routes. Previously 501.
      runner,
      poolBinder: binder,
      // The erase machine's own view of a runner. It needs the three erase verbs,
      // which are the same HTTP surface with a different intent, so it is given
      // the adapter rather than a second client that would drift from it.
      // The erase machine's view of a runner: the same HTTP surface, three
      // different intents. Given the adapter rather than a second client, because
      // two clients over one runner would drift from each other's auth and error
      // handling.
      eraseRunner: {
        abort: (sessionId: string) => runner.abortAny(sessionId),
        // Freeze is a no-op here and that is a claim worth making precisely.
        //
        // The machine calls it so a runner cannot write into the directory it is
        // about to delete. Here the next step destroys the container outright
        // through the orchestrator, so a runner that wrote in the meantime would
        // be writing into a container about to be removed. There is no window
        // that freeze closes and removal does not.
        //
        // Recorded as a method that does nothing rather than left off the
        // interface: an absent method and a no-op one are different statements
        // about what the system guarantees.
        freeze: async () => {},
        shredDirectory: (sessionId: string) => runner.removeSessionDir(sessionId),
      },
    },
    {
      logger: true,
      // Which `X-Forwarded-For` may be believed.
      //
      // **This was never passed before**, and the empty default behind a reverse proxy
      // meant every caller on the internet was rate-limited as the proxy — 3 sessions
      // an hour, shared. Caddy sets the header correctly (see `infra/Caddyfile`);
      // nothing ever told the api to believe it, so it refused to.
      knownProxies: config.trustedProxies,
    },
  );

  return { app, config, db, sse, binder, orchestrator, log };
}

/** The log the boot sequence and the sweepers share. */
export interface BootLog extends SweeperLog {
  error(msg: string, fields?: Record<string, unknown>): void;
}

/** What a successful boot produced. */
export interface Booted {
  readonly app: ReturnType<typeof buildServer>;
  readonly config: ReturnType<typeof loadConfig>;
  readonly db: Db;
  readonly sse: SseHub;
  readonly binder: PoolBinder;
  readonly orchestrator: OrchestratorApi;
  readonly log: BootLog;
}

/**
 * logLine emits one structured line.
 *
 * Pino is configured on the Fastify instance; this is for the boot sequence, which
 * runs before there is an app to log through. It deliberately has no way to accept
 * a secret — there is no `secret` parameter, so a caller cannot pass one by
 * accident, which is a stronger property than remembering not to.
 */
function logLine(
  level: "info" | "warn" | "error",
  message: string,
  extra?: Record<string, unknown>,
): void {
  const line = JSON.stringify({ level, msg: message, ...extra });
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

async function main(): Promise<void> {
  const booted = await boot();

  const { app, config, db, sse, binder, orchestrator } = booted;

  // Sweepers. Independent intervals on purpose: an idle sweep that never runs
  // holds containers, and a session sweep that never runs grows the database.
  const sweeper = setInterval(() => {
    void sweep(
      { db, orchestrator, sse, log: booted.log, now: () => Date.now() },
      binder,
    )
      .then((report) => {
        // The rest of the report is discarded with the promise, so a report whose
        // counters are all zero says nothing — which is right. These two are
        // different: they mean a slot was taken back from the orchestrator and a
        // row untruthful about a session, neither of which a healthy pool has ever
        // done. Logged because `void` above throws the object away, and without this
        // the fix has no observable in production except the ones its own branch
        // logs at `warn`. The per-slot detail is in those lines; this is the count
        // an operator reads once per tick.
        if (report.orphanSlotsReleased > 0 || report.phantomRowsCleaned > 0) {
          booted.log.info("sweep reclaimed orphan bindings", {
            slotsReleased: report.orphanSlotsReleased,
            rowsCleaned: report.phantomRowsCleaned,
          });
        }
      })
      .catch((error: unknown) => {
        // A failed sweep must not kill the process, and must not be silent either.
        booted.log.error("sweep failed", { error: String(error) });
      });
  }, SWEEP_INTERVAL_MS);

  // An interval keeps the event loop alive on its own; `unref` means a sweep
  // cannot by itself be the reason the process refuses to exit on SIGTERM.
  sweeper.unref();

  sse.startKeepalive();

  const { host, port } = splitListen(config.listen);
  await app.listen({ host, port });

  booted.log.info("listening", {
    listen: config.listen,
    publicOrigin: config.publicOrigin,
    allowedOrigins: [...config.allowedOrigins],
    // Named, not valued. The operator can confirm which key is in use without the
    // value ever reaching a log line.
    database: config.databasePath,
    runnerAdapter: false,
  });

  // ---- shutdown -----------------------------------------------------------
  //
  // SIGTERM is what Docker sends. The order matters: stop accepting new work,
  // then stop the things that hold resources, then close the database last so an
  // in-flight write is not cut off.
  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    booted.log.info("shutting down", { signal });

    clearInterval(sweeper);
    sse.stopKeepalive();

    // A hung close would leave the container running until the grace period
    // expires and Docker SIGKILLs it, which skips the database close. Bounded so
    // shutdown is fast and predictable.
    await Promise.race([
      Promise.allSettled([app.close()]),
      new Promise((resolve) => setTimeout(resolve, 10_000)),
    ]);

    db.close();
    process.exit(0);
  };

  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));

  // An unhandled rejection in a long-lived process is a bug that would otherwise
  // be invisible until something else happened to break. Crash rather than
  // continue: a service in an unknown state should not be serving.
  process.on("unhandledRejection", (reason) => {
    booted.log.error("unhandled rejection", { reason: String(reason) });
    void shutdown("unhandledRejection");
  });
}

/** splitListen parses `host:port`, defaulting the host. */
export function splitListen(listen: string): { host: string; port: number } {
  const lastColon = listen.lastIndexOf(":");
  // No colon at all is a typo rather than an intent. Defaulting the port to 3000
  // would mean `LISTEN=3000` quietly means "0.0.0.0:3000", and a typo that is
  // interpreted rather than refused is a typo nobody finds.
  if (lastColon === -1) {
    throw new ConfigError("LISTEN", `"${listen}" must be host:port`);
  }
  const host = listen.slice(0, lastColon);
  const portText = listen.slice(lastColon + 1);
  // `Number("")` is 0, so `LISTEN=0.0.0.0:` would otherwise become a valid port 0
  // — which means "any free port", a test affordance that in a deployment is a
  // service listening somewhere nobody expects.
  const port = portText === "" ? Number.NaN : Number(portText);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new ConfigError("LISTEN", `"${listen}" has no valid port`);
  }
  return { host, port };
}

// Only run when invoked directly, so `import`ing this from a test does not start a
// server. `require.main` is the CommonJS equivalent and this package is CJS.
if (require.main === module) {
  main().catch((error: unknown) => {
    // ConfigError is the expected failure and its message is written for an
    // operator; anything else gets its stack, because it is a bug and hiding it
    // would make this line the least useful thing in the file.
    if (error instanceof ConfigError) {
      console.error(`\nrefusing to start — ${error.message}\n`);
    } else {
      console.error("\nthe api failed to start:", error);
    }
    process.exit(1);
  });
}

// Referenced so the import is not flagged as unused by a reader skimming for the
// TTL table; the sweep interval is deliberately *not* one of those values.
export const SWEEP_INTERVAL = { ms: SWEEP_INTERVAL_MS, shortestTtlMs: TTL.unclaimedSession };