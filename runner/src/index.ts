/**
 * The runner's HTTP surface.
 *
 * Four things, and the set of four is the security property.
 *
 *   GET  /healthz                 liveness, for the orchestrator
 *   GET  /events                  SSE, per session
 *   POST /sessions/:guid/login    the credential, as bytes
 *   POST /sessions/:guid/artifacts  stream the vault into a staging dir
 *
 * ## The orchestrator's contract, and what it requires of this image
 *
 * `internal/pool/runner.go` builds the create request, and it had already decided
 * three things this package had not provided. None of them fails loudly: the
 * container starts, and the pool then refuses to bind it forever.
 *
 *   1. **A health check at `/app/dist/healthcheck.js`** — named in the create
 *      request's `HealthConfig.Test`. Absent, every probe fails, the container
 *      never becomes healthy, and a login waits on a slot that is never handed
 *      out. Every orchestrator check still passes.
 *   2. **`MSOUT_RUNNER_TOKEN_FILE` pointing into `/run/secrets`** — the token the
 *      orchestrator presents. `loadConfig` throws without it, deliberately.
 *   3. **`/artifacts` writable, alongside the `/data` bind mount** — where the
 *      staged archive goes. The root filesystem is read-only, so this has to be a
 *      mount; see the artifact route for why the directory is caller-named.
 *
 * All three are asserted in `tests/contract.test.ts` against this file and the
 * orchestrator's, because two implementations sharing one contract is where every
 * serious bug in this project has been.
 *
 * **There is no debug surface, and that is a control rather than a default.**
 * `--dodump` writes the authenticated DOM — live cookies, tenant hostnames.
 * `--screenshot` cannot redact a password field at all, because it is a bitmap,
 * and it shows the number-match MFA code. In a hosted service either is a
 * credential artefact. So there is no query parameter, header or environment
 * variable that turns them on, and `tests/debug-surface.test.ts` asserts that by
 * enumerating the routes this app actually registers.
 *
 * ## The credential arrives as bytes and stays bytes
 *
 * `text/plain` with `parseAs: "buffer"`. No JSON parser, no string, no trimming,
 * no length cap that shortens. See `credential.ts` for why each of those is a
 * way to change a user's password without telling them.
 *
 * ## Why the packages are called as libraries
 *
 * Not spawned as CLIs. The predecessor passed the password as `--password <value>`
 * on a command line, where it is readable in `/proc/<pid>/cmdline` by every
 * process in the container and appears in the child's own error output. Calling
 * `login()` in-process means the credential never enters argv, and it is also how
 * the typed events arrive instead of log-scraping — the package emits
 * `login-result {ok, reason}`, which is strictly better than matching a
 * `Possible cause:` line and hoping the wording held.
 *
 * The trade is stated in the PR: a crash in this process now takes the browser
 * with it, where a child crash was survivable. Given that argv exposure, that is
 * the right trade.
 */

import Fastify, { type FastifyInstance, type FastifyReply } from "fastify";
import type { Readable } from "node:stream";
import { createWriteStream, existsSync } from "node:fs";
import { mkdir, readdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import archiver from "archiver";
import { loadConfig, type RunnerConfig } from "./config.js";
import { EventHub, formatSse, SSE_KEEPALIVE, type RunnerEvent } from "./events.js";
import { JobSlot, JobBusyError, makeSessionDirs, removeSessionDirs, sessionPaths } from "./sessions.js";
import { isValidGuid, readAccount, readCredentialBytes, passwordFrom } from "./credential.js";
// A type, and only a type: `import type` is erased at emit, so this cannot become
// the static `require` the lazy `packages()` below exists to avoid. The type
// itself is hand-written in `msout.d.ts` — the packages ship no declarations.
import type { ListEvent } from "@msout/microsoft-onenote-list-notebooks";

/** How often an idle SSE stream is kept alive. */
const KEEPALIVE_MS = 15_000;

/**
 * How often an export in flight re-publishes the last counts it was told.
 *
 * Deliberately the same figure as `KEEPALIVE_MS`, and for the same reason: both
 * exist so that nothing about a running export goes quiet for longer than one
 * poll interval, and two constants for one idea is how they drift apart.
 */
const PROGRESS_HEARTBEAT_MS = 15_000;

/**
 * How long an MFA code may be, in characters.
 *
 * A shape check rather than a sanitiser, for the reason the artifact id's is: "reject
 * anything that is not a code" is smaller and more obviously complete than "strip the
 * characters that are not one". Six digits is what Microsoft sends; eight covers the
 * app-name-prefixed forms some tenants get, and 32 leaves room without being a bound
 * so loose it stops meaning anything.
 *
 * The api applies the same number, so a code that reached it intact is a code this
 * route accepts — two different limits would produce a 400 here for a body the api
 * had already called valid, with nothing in the message saying which.
 */
const MAX_CHALLENGE_CODE_CHARS = 32;

/**
 * The packages, loaded lazily.
 *
 * Lazy so that `/healthz` answers on a container whose Chromium is missing, and
 * so importing this module does not pull Playwright into a process that is only
 * running tests. A static import would make the debug-surface route enumeration
 * test load a browser to do it.
 */
/**
 * One notebook, as `@msout/microsoft-onenote-list-notebooks` returns it.
 *
 * Transcribed from the package's own return rather than invented: `listNotebooks()`
 * resolves to a **bare array** of these, and that fact is the whole reason this type
 * exists. Declaring the seam as `Promise<unknown>` and casting at the call site is what
 * allowed an array to be read as `{notebooks}` — an empty list, published on every run,
 * with the package's own log cheerfully reporting three notebooks found.
 */
export interface Notebook {
  readonly name?: string;
  readonly url?: string;
}

/** What `runExport` returns — the counts and the notebook name. */
export interface RunExportStats {
  readonly totalPages: number;
  readonly totalSections: number;
  readonly totalAssets: number;
  readonly failedSections: number;
  readonly failedPages: number;
  readonly failedGroups: number;
  readonly failedAssets: number;
  readonly notebookNotFound?: boolean;
}

async function packages(): Promise<{
  login: (options: Record<string, unknown>) => Promise<boolean>;
  answerChallenge: (code: string) => boolean;
  listNotebooks: (options: Record<string, unknown>) => Promise<Notebook[]>;
  runExport: (options: Record<string, unknown>) => Promise<RunExportStats>;
  LOGIN_REASONS: readonly string[];
}> {
  const webauth = (await import("@msout/microsoft-webauth")) as unknown as {
    login: (o: Record<string, unknown>) => Promise<boolean>;
    // Synchronous, and a **boolean**: it resolves a pending `promptUser` call and
    // reports whether one was there. The false branch is the load-bearing half —
    // "no prompt is waiting" is a different answer from "the code was wrong", and
    // only this process is in a position to tell them apart.
    answerChallenge: (code: string) => boolean;
    LOGIN_REASONS: readonly string[];
  };
  // Typed by what the package actually returns — see `Notebook` and the comment on it.
  // The old `Promise<unknown>` plus an `as {notebooks?}` cast at the call site is what
  // let a bare array be read as an object for the whole life of this route.
  const list = (await import("@msout/microsoft-onenote-list-notebooks")) as unknown as {
    listNotebooks: (o: Record<string, unknown>) => Promise<Notebook[]>;
  };
  const exporter = (await import("@msout/microsoft-onenote-export-notebook")) as unknown as {
    runExport: (o: Record<string, unknown>) => Promise<RunExportStats>;
  };
  return {
    login: webauth.login,
    answerChallenge: webauth.answerChallenge,
    LOGIN_REASONS: webauth.LOGIN_REASONS,
    listNotebooks: list.listNotebooks,
    runExport: exporter.runExport,
  };
}

/**
 * The user-facing message for an export that never started because `out/` could
 * not be prepared.
 *
 * Its own sentence, and not the api's `WALK_FAILED` ("the export stopped
 * unexpectedly partway through"), because the two are true about different worlds.
 * Here **nothing stopped partway**: no walk ran, no page was written, and the
 * session's previous vault is still on disk exactly as it was. A user told the
 * walk stopped partway would go looking for pages that were never lost, and would
 * not think to retry — the one action that does help here.
 */
const OUT_DIR_UNPREPARED = "the export directory could not be prepared, so nothing was exported.";

/**
 * Empties `out/` so that the archive a session publishes holds only what this
 * export writes.
 *
 * ## Why this is the runner's job
 *
 * The export package says so itself, in `warnIfOutputExists`
 * (`exporter.js:1492`): *"Files from a previous run that are no longer in the
 * notebook are left in place, so this is a merge, not a clean mirror. Remove the
 * folder first for a clean export."* It warns and then does nothing about it,
 * because the CLI's user is expected to notice. The runner has no user at a
 * prompt. Without this, a second export in one session ships the first one's
 * pages — including pages **deleted from OneNote in between**, which is the worst
 * version of the bug: an archive that looks current and is not.
 *
 * The runner is also the only component that can honour the instruction: the
 * session tree is created for one container and destroyed with it, so nothing
 * else writes `out/`.
 *
 * ## Async, not `rmSync`
 *
 * `rmSync` holds the event loop for the whole unlink walk. `out/` is on the
 * session bind mount, and a vault is thousands of files; blocking there stops
 * the loop from flushing the route's 202, so the api can time the export-start
 * out and retry while this process is still halfway through deleting — two
 * components disagreeing about whether the export started, with a half-emptied
 * `out/` underneath. Awaited, the reply goes out first and the loop stays free
 * to answer `/abort` while the delete runs.
 *
 * Throws on failure; the caller turns that into a terminal of its own rather than
 * letting it fall through to the walk-failed path, which would describe a walk
 * that never started.
 */
async function clearExportDir(outDir: string): Promise<{ entries: number; durationMs: number }> {
  const startedAt = Date.now();
  // One `readdir`, one level deep. The top of `out/` holds a handful of notebook
  // folders however large the vault below them is, so this is cheap, and it turns
  // "cleared out/" from a claim into a number. Its own failure is swallowed: it is
  // a figure for a log line, and the only two calls that decide whether the export
  // can run are the two below.
  const entries = await readdir(outDir).then(
    (names) => names.length,
    () => 0,
  );
  await rm(outDir, { recursive: true, force: true, maxRetries: 3 });
  // `0o700`, because `makeSessionDirs` creates it that way. A default-mode mkdir
  // would quietly widen a directory holding the whole vault, and the next export
  // would inherit the wider mode.
  await mkdir(outDir, { recursive: true, mode: 0o700 });
  return { entries, durationMs: Date.now() - startedAt };
}

/**
 * Builds the app.
 *
 * Exported so tests can drive it with `app.inject()` and no port, and so the
 * route-enumeration test can read the real route table rather than a copy of it.
 */
export function buildApp(
  config: RunnerConfig,
  /**
   * Called once per route as it is registered.
   *
   * Exists for `tests/debug-surface.test.ts`, which needs the route table as
   * data. Fastify's own `onRoute` hook cannot serve that from the outside:
   * `buildApp` registers every route while it runs, so a hook added afterwards
   * has already missed them all — which is why the first version of that test
   * saw an empty table and passed vacuously.
   *
   * It observes and changes nothing.
   */
  onRoute?: (route: { method: string | string[]; url: string }) => void,
): FastifyInstance {
  const app = Fastify({
    logger: { level: process.env.RUNNER_LOG_LEVEL ?? "info" },
    // This process handles credentials. A body arriving larger than the cap is
    // refused by the parser below, never truncated.
    bodyLimit: config.credentialBodyLimit,
  });

  if (onRoute !== undefined) {
    app.addHook("onRoute", (route) =>
      onRoute({ method: route.method as string | string[], url: route.url }),
    );
  }

  const hub = new EventHub(config.ringSize);
  const slot = new JobSlot();

  // The credential's content type. `parseAs: "buffer"` is the whole point — see
  // credential.ts. `text/plain` because that is what the api forwards, and because
  // attaching a JSON parser to it would be the first step towards the bug this
  // project has shipped twice.
  app.addContentTypeParser(
    "text/plain",
    { parseAs: "buffer", bodyLimit: config.credentialBodyLimit },
    (_req, body, done) => done(null, body),
  );

  // Bearer token, on everything except the health check. The orchestrator is the
  // only caller, and it holds the Docker socket, so the token is defence in depth
  // rather than the boundary itself.
  app.addHook("onRequest", async (req, reply) => {
    if (req.url === "/healthz") return;
    const presented = req.headers["x-runner-token"];
    if (presented !== config.token) {
      await reply.code(401).send({ error: "unauthorised" });
    }
  });

  app.get("/healthz", async () => ({
    ok: true,
    busy: slot.busy,
    job: slot.describe(),
  }));

  // ---- SSE -----------------------------------------------------------------

  app.get("/events", async (req, reply) => {
    const query = req.query as { guid?: string; since?: string };
    const guid = query.guid ?? "";
    if (!isValidGuid(guid)) return reply.code(400).send({ error: "bad guid" });
    const since = Number.parseInt(query.since ?? "0", 10) || 0;

    reply.raw.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });

    const write = (event: RunnerEvent, seq?: number): void => {
      if (reply.raw.writableEnded) return;
      reply.raw.write(formatSse(seq === undefined ? { seq: 0, event } : { seq, event }));
    };

    const { events, gap } = hub.history(guid, since);
    // Said out loud, because a replay that looks continuous but is missing the
    // middle is worse than one that admits a hole.
    if (gap) write({ type: "error", message: "gap: some events were discarded" });
    for (const entry of events) write(entry.event, entry.seq);

    const unsubscribe = hub.subscribe(guid, (entry) => write(entry.event, entry.seq));
    const keepalive = setInterval(() => {
      if (!reply.raw.writableEnded) reply.raw.write(SSE_KEEPALIVE);
    }, KEEPALIVE_MS);

    req.raw.on("close", () => {
      clearInterval(keepalive);
      unsubscribe();
    });
    return reply;
  });

  // ---- login ---------------------------------------------------------------

  app.post("/sessions/:guid/login", async (req, reply) => {
    const { guid } = req.params as { guid: string };
    const paths = sessionPaths(config.dataRoot, guid);
    if (paths === null) return reply.code(400).send({ error: "bad guid" });

    const busy = busyBody(slot);
    if (busy !== null) return reply.code(409).send(busy);

    const accepted = readCredentialBytes(req.body, config.credentialBodyLimit);
    if (!accepted.ok) return reply.code(400).send({ error: accepted.reason });

    // The account is a header, so the body stays byte-identical. See §6.
    const account = readAccount(req.headers["x-microsoft-account"]);
    if (account === null) return reply.code(400).send({ error: "missing account" });

    const claimed = slot.claim(guid, "login");
    makeSessionDirs(paths);
    hub.publish(guid, { type: "login-started" });

    // The packages are loaded inside the request rather than at boot, so a missing
    // Chromium produces a login-failed event naming the reason instead of a
    // container that never became healthy.
    const { login, LOGIN_REASONS } = await packages();

    // `onEvent` is the whole reason this is a library call and not a child
    // process: the challenge and the terminal reason arrive as typed values rather
    // than as log lines matched by their wording.
    //
    // `terminalReason` is the package's own `login-result` reason, kept here so the
    // false branch below can report it instead of inventing one.
    //
    // This is not a nicety. `login()` returns a boolean, so a caller cannot tell a
    // wrong password from Microsoft being unreachable from a host with no egress —
    // and this runner's first live run produced exactly `login-failed
    // {reason: "unknown"}`, which the api maps to its generic message. The package
    // had said `network`. Without this the reason is lost between two components
    // that both had it.
    let terminalReason: string | null = null;

    const forward = (type: string, payload: Record<string, unknown>): void => {
      switch (type) {
        case "challenge":
          hub.publish(guid, {
            type: "challenge",
            kind: String(payload.kind ?? "code"),
            label: String(payload.label ?? ""),
            number: typeof payload.number === "string" ? payload.number : null,
            // The package gives a duration; only this process can put it on a wall
            // clock, because only this process knows when it received the event.
            expiresAt:
              typeof payload.timeoutMs === "number"
                ? new Date(Date.now() + payload.timeoutMs).toISOString()
                : null,
          });
          break;
        case "challenge-expired":
          // Deliberately not forwarded as `challenge-expired`: the api already
          // emits that name for its own 15-minute TTL, and one name carrying two
          // deadlines is a trap. The login-result reason carries it instead.
          break;
        case "challenge-seen":
          // No session claim. See events.ts.
          break;
        case "login-result":
          // The terminal event, and the only place the package states *why*.
          terminalReason = reasonFromLoginResult(payload, LOGIN_REASONS);
          break;
        default:
          break;
      }
    };

    void (async () => {
      try {
        const ok = await login({
          email: account,
          password: passwordFrom(accepted.bytes),
          authFile: paths.authFile,
          onEvent: (event: { type: string; [k: string]: unknown }) =>
            forward(event.type, event as Record<string, unknown>),
        });

        if (ok) {
          hub.publish(guid, { type: "login-success" });
        } else {
          // `login()` resolves a boolean, so the return value cannot say why. The
          // reason comes from the package's own terminal `login-result`, captured
          // in `forward` above — which is the only component that had it.
          //
          // Still `unknown` if that event never arrived: a package that failed
          // before emitting one, or an exception thrown before the emit. That is
          // the honest answer rather than a guess, and the api maps `unknown` to
          // its generic message.
          hub.publish(guid, { type: "login-failed", reason: terminalReason ?? "unknown" });
        }
      } catch (cause) {
        // An error thrown *around* `login()` rather than by it — Chromium missing,
        // the module failing to import. `cause.name` is a JS error name, which is
        // not a member of LOGIN_REASONS, so it is reported as `unknown` rather
        // than inventing a reason the api has no message for.
        //
        // The alternative — passing the name through — would put a value like
        // "TypeError" into the api's reason field, where it maps to the generic
        // message anyway, and would look like a mapped reason to anyone reading
        // the log. The specific error goes in the container's own logs.
        void cause;
        hub.publish(guid, {
          type: "login-failed",
          reason: terminalReason ?? "unknown",
        });
      } finally {
        claimed.release();
      }
    })();

    // 202: the login runs for minutes. The outcome arrives on the event stream.
    return reply.code(202).send({ accepted: true });
  });

  // ---- mfa ----------------------------------------------------------------

  /**
   * Hands a typed MFA code to the login that is waiting for one.
   *
   * ## Why this route exists at all
   *
   * `@msout/microsoft-webauth` asks for a code by calling `promptUser`, which reads
   * `process.stdin`. **In a container there is no stdin to read**: the prompt is a
   * promise that nothing will ever resolve, so a `challenge` of kind `code` became a
   * login that sat until the package's own timeout and then failed, with a message
   * that named a timeout rather than a missing way to answer.
   *
   * `answerChallenge` (0.1.12) is the out-of-band half of that: it resolves the
   * pending `promptUser` call from outside the process. This route is the outside.
   *
   * ## It deliberately does not claim the job slot
   *
   * The login holds the slot for its whole duration — including the minutes it is
   * waiting for this code — so a `busyBody` check here would refuse every code the
   * route exists to deliver, and `slot.claim` would throw for the same reason. The
   * work this route performs is not a job: it is a value handed to one that is
   * already running.
   *
   * ## 409 is an answer, not a failure
   *
   * `false` from the package means no prompt was pending — the challenge expired, or
   * it was a push-approval that needs no code. Saying so is the difference between a
   * user who typed a code too late and a user told "sign-in failed" with a login that
   * never had anything to answer.
   */
  app.post("/sessions/:guid/mfa", async (req, reply) => {
    const { guid } = req.params as { guid: string };
    // The guid is still validated: this route does no filesystem work, but every
    // other `/sessions/:guid` route validates it, and a session route that accepts
    // anything is the first step towards one that does something with it.
    if (sessionPaths(config.dataRoot, guid) === null) {
      return reply.code(400).send({ error: "bad guid" });
    }

    const body = req.body as { code?: unknown } | undefined;
    const code = typeof body?.code === "string" ? body.code : "";
    // Whitespace-only is refused, and the value is **not** trimmed on the way out:
    // what the user typed is what the package receives. Refusing a blank is a shape
    // check, and trimming would be a transformation of a value nobody can inspect
    // again once it has been handed over.
    if (code.trim() === "") return reply.code(400).send({ error: "missing code" });
    if (code.length > MAX_CHALLENGE_CODE_CHARS) {
      return reply.code(400).send({ error: `code must be at most ${MAX_CHALLENGE_CODE_CHARS} characters` });
    }

    // Loaded here for the same reason the login route loads `login` here: a container
    // whose Chromium is missing must fail on the request that needs it, not at boot.
    const { answerChallenge } = await packages();

    if (!answerChallenge(code)) {
      return reply.code(409).send({ error: "no challenge is waiting for a code" });
    }

    // 202, not 200: the code has been handed over, not verified. A wrong code is
    // discovered by the login, which answers `login-failed` on the event stream.
    return reply.code(202).send({ accepted: true });
  });

  // ---- notebooks -----------------------------------------------------------

  app.post("/sessions/:guid/notebooks", async (req, reply) => {
    const { guid } = req.params as { guid: string };
    const paths = sessionPaths(config.dataRoot, guid);
    if (paths === null) return reply.code(400).send({ error: "bad guid" });
    if (!existsSync(paths.authFile)) {
      return reply.code(409).send({ error: "no_auth" });
    }
    const busy = busyBody(slot);
    if (busy !== null) return reply.code(409).send(busy);

    const claimed = slot.claim(guid, "list");
    const { listNotebooks } = await packages();

    void (async () => {
      try {
        // **`listNotebooks()` returns a bare array.** It did not return an object with a
        // `notebooks` property, ever.
        //
        // The old code was:
        //
        //     const result = (await listNotebooks(...)) as { notebooks?: ... };
        //     notebooks: (result.notebooks ?? []).map(...)
        //
        // `result.notebooks` on an array is `undefined`, so `?? []` made it an empty
        // list — **and the runner published an empty notebook list every single time.**
        // The package's own log said `Found 3 notebooks!` and `3 of 3 notebooks
        // resolved to a link`, because those come from the package. The names died at
        // this line.
        //
        // The `as` cast is what made it compile. An array is not `{notebooks?}`, and
        // saying so with a cast is a way of telling the compiler to stop checking. The
        // seam is typed `Promise<Notebook[]>` above, so the next mistake here is an
        // error rather than an empty array.
        //
        // Observed end to end on the deployed host: the api persisted `[]` after a
        // listing that the runner had logged as finding three.
        const notebooks = await listNotebooks({
          authFile: paths.authFile,
          keepOpen: false,
          // The listing's own output, forwarded as it happens. The same inline
          // shape the login and the export use, and for the same reason: a
          // listing that produces nothing for thirty seconds is a listing nobody
          // can tell from a hung one. `ListEvent` is the package's own vocabulary
          // — one name, frozen in `LIST_EVENT_TYPES` — so there is nothing to
          // translate and the type does the filtering a `switch` would otherwise
          // do.
          //
          // Forwarded verbatim: the package already redacts its auth-file paths
          // and emits the line undecorated (no timestamp, no colour), so there is
          // nothing here to strip and nothing that could carry a secret.
          onEvent: (event: ListEvent) => hub.publish(guid, event),
        });

        hub.publish(guid, {
          type: "notebooks-listed",
          notebooks: notebooks.map((n) => ({
            name: String(n.name ?? ""),
            url: String(n.url ?? ""),
          })),
        });
      } catch {
        hub.publish(guid, { type: "notebooks-failed", reason: "unknown" });
      } finally {
        claimed.release();
      }
    })();

    return reply.code(202).send({ accepted: true });
  });

  // ---- export --------------------------------------------------------------

  app.post("/sessions/:guid/exports", async (req, reply) => {
    const { guid } = req.params as { guid: string };
    const body = req.body as { id?: unknown; notebookUrl?: unknown; notebook?: unknown } | undefined;
    const paths = sessionPaths(config.dataRoot, guid);
    if (paths === null) return reply.code(400).send({ error: "bad guid" });
    if (!existsSync(paths.authFile)) return reply.code(409).send({ error: "no_auth" });

    const id = typeof body?.id === "string" && body.id !== "" ? body.id : null;
    if (id === null) return reply.code(400).send({ error: "missing id" });
    const url = typeof body?.notebookUrl === "string" ? body.notebookUrl : null;
    const name = typeof body?.notebook === "string" ? body.notebook : null;
    if (url === null && name === null) {
      return reply.code(400).send({ error: "missing notebook or notebookUrl" });
    }

    const busy = busyBody(slot);
    if (busy !== null) return reply.code(409).send(busy);

    const controller = new AbortController();
    const claimed = slot.claim(guid, "export", controller);
    makeSessionDirs(paths);
    const { runExport } = await packages();
    let packageTerminalEmitted = false;
    let exportDoneNotebook: string | undefined;
    /**
     * The last counts the package reported, and the heartbeat's whole vocabulary.
     *
     * `null` until the first `export-progress`, and the heartbeat publishes
     * **nothing** until then. That is the line this whole mechanism must not
     * cross: before any frame there are no measured counts, and publishing
     * `{0, 0, 0}` on a timer would be inventing a measurement the exporter never
     * made — the exact lie the api's `progress: null` ("unknown") exists to avoid
     * being confused with.
     */
    let lastProgress: { pages: number; sections: number; assets: number } | null = null;

    /**
     * The heartbeat: re-publish the last known counts while the walk runs.
     *
     * ## What it is for, stated honestly
     *
     * The exporter announces **once per section** (`exporter.js:1339`, after
     * every page in that section — "the counts move a lot inside a long
     * section"). So a notebook of one section produces exactly one frame,
     * seconds before its terminal, and a notebook of many produces one per
     * section with silence between them.
     *
     * This keeps the walk *visibly* alive across those gaps and keeps the api's
     * snapshot fresh, using the api's own existing vocabulary — no new route, no
     * new event type, no package change.
     *
     * ## What it cannot do
     *
     * **It cannot invent counts inside a section.** It re-publishes what the
     * exporter last said, so a single-section notebook still shows one real
     * update however long the section takes. Making *that* live is a per-page
     * cadence in `@msout/microsoft-onenote-export-notebook` — a publish cycle,
     * not a fix, and explicitly out of scope here.
     *
     * The api's coalescing writer treats a repeated frame as news-free and skips
     * the database write, which is the correct reading: the numbers did not
     * move. The heartbeat's value is on the wire and in the liveness signal, not
     * in the row.
     */
    const heartbeat = setInterval(() => {
      if (lastProgress === null) return;
      hub.publish(guid, { type: "export-progress", id, progress: lastProgress });
    }, PROGRESS_HEARTBEAT_MS);
    // `unref` so a heartbeat cannot by itself be the reason the process refuses to
    // exit. `clearInterval` below is what actually stops it; this is the belt to
    // that braces, and it is the same reasoning as the sweeper interval's.
    heartbeat.unref();

    void (async () => {
      try {
        // ---- the vault starts empty -----------------------------------------
        //
        // Inside this `try` and after `packages()`, both deliberately. A throw
        // here has to be caught — before the try it escapes a detached promise,
        // and there is no `unhandledRejection` handler in this process
        // (`RestartPolicy: "no"`), so the container would die holding the job
        // slot. Before `packages()` it would leak that slot with no export and no
        // terminal, and the session would sit at `exporting` until the cap.
        //
        // After the wipe and not before: an export that cannot clear `out/` must
        // not then *merge into it*. Running against the leftovers is how a vault
        // gets published that is silently the union of two notebooks.
        try {
          const wiped = await clearExportDir(paths.outDir);
          // Logged before anything can erase it. The runner's stdout is a
          // json-file with a size cap and the container is destroyed at session
          // end, so this line is the only record that a wipe happened at all —
          // without it, a zip holding the wrong pages has no explanation anywhere.
          app.log.info({ ...wiped, outDir: paths.outDir }, "cleared out/ for a fresh export");
        } catch (cause) {
          app.log.error({ err: cause, outDir: paths.outDir }, "could not clear out/; no export was run");
          hub.publish(guid, {
            type: "export-done",
            id,
            // The notebook name from the request, for the same reason the catch
            // below does: the package's `export-done`, its only carrier of it,
            // was never emitted.
            notebook: name ?? "",
            pages: 0,
            sections: 0,
            assets: 0,
            failedSections: 0,
            failedPages: 0,
            failedGroups: 0,
            notebookNotFound: false,
            // `walkFailed` stays true, and that is not a fallback to the generic
            // path — it is the one signal the api reads to skip staging entirely.
            // A false here with all-zero counts classifies as **done**, and the
            // api would publish whatever survived the failed wipe as this
            // export's vault. `failure` is what makes this terminal its own
            // rather than the walk-failed one.
            walkFailed: true,
            failure: "export_dir_unprepared",
            message: OUT_DIR_UNPREPARED,
          });
          // `finally` still runs: the heartbeat stops and the slot is released,
          // exactly as it would have been had the walk finished.
          return;
        }

        const stats = await runExport({
          authFile: paths.authFile,
          exportDir: paths.outDir,
          id,
          signal: controller.signal,
          // Unattended, so a password-protected section is skipped rather than
          // waiting for a keypress that cannot arrive. Set here rather than left
          // to a flag the caller could omit — and note it is *not* a spread of the
          // request body: the body is read field by field above, because spreading
          // it would hand a caller any flag the packages accept, including the
          // dump and screenshot ones.
          nonInteractive: true,
          // ...and the flag the package actually reads. `nonInteractive` is not
          // consulted by 0.5.0, so relying on it alone leaves a
          // password-protected section waiting for a keypress that can never
          // arrive in a container. Both are set because they answer different
          // questions: one refuses a missing target, the other skips a locked
          // section.
          nopassasked: true,
          // Exactly one of the two targets, chosen rather than spread, so a caller
          // cannot supply both and have the runner pick for them.
          ...(url !== null ? { notebookLink: url } : { notebook: name as string }),
          onEvent: (event: { type: string; [k: string]: unknown }) => {
            const e = event as Record<string, unknown>;
            switch (event.type) {
              case "export-started":
                hub.publish(guid, { type: "export-started", id });
                break;
              case "export-progress":
                // Recorded before publishing, so the heartbeat's very first tick
                // — which can land while a section is still running — has
                // something measured to re-publish rather than nothing.
                lastProgress = (e.progress ?? { pages: 0, sections: 0, assets: 0 }) as {
                  pages: number;
                  sections: number;
                  assets: number;
                };
                hub.publish(guid, {
                  type: "export-progress",
                  id,
                  progress: lastProgress as never,
                });
                break;
              case "export-log":
                hub.publish(guid, { type: "export-log", id, line: String(e.line ?? "") });
                break;
              case "export-done":
                // The package emits `export-done` on every normal completion.
                // Suppress it because we will publish a terminal after `await`
                // with the counts from `stats` (which use different field names).
                // Capture the notebook name from the event (stats.notebook is
                // undefined).
                exportDoneNotebook = String(e.notebook ?? "");
                // Do NOT set packageTerminalEmitted: export-done must be
                // replaced with our own terminal carrying counts.
                break;
              case "export-partial":
                hub.publish(guid, { type: "export-partial", id, reason: String(e.reason ?? "aborted") });
                packageTerminalEmitted = true;
                break;
              case "export-aborted":
                hub.publish(guid, { type: "export-aborted", id });
                packageTerminalEmitted = true;
                break;
              default:
                break;
            }
          },
        });

        // The package may have emitted a terminal event.
        // - export-partial / export-aborted: already relayed, do not add another
        // - export-done: suppressed, but we must publish our own with counts
        if (!packageTerminalEmitted) {
          hub.publish(guid, {
            type: "export-done",
            id,
            notebook: exportDoneNotebook ?? "",
            pages: stats.totalPages,
            sections: stats.totalSections,
            assets: stats.totalAssets,
            failedSections: stats.failedSections,
            failedPages: stats.failedPages,
            failedGroups: stats.failedGroups,
            notebookNotFound: stats.notebookNotFound ?? false,
            walkFailed: false,
          });
        }
      } catch (cause) {
        // An error thrown *around* `runExport` rather than by it — Chromium missing,
        // the module failing to import, or any other runtime exception.
        //
        // A terminal is published here because without one the session sits at
        // `exporting` with a live runner and no outcome until the absolute cap. The
        // notebook name comes from the request rather than from `stats`: the
        // package's `export-done` is the only carrier of it, and on this path it was
        // never emitted — so `""` would record an unnamed export into `export_state`.
        hub.publish(guid, {
          type: "export-done",
          id,
          notebook: name ?? "",
          pages: 0,
          sections: 0,
          assets: 0,
          failedSections: 0,
          failedPages: 0,
          failedGroups: 0,
          notebookNotFound: false,
          walkFailed: true,
        });
      } finally {
        // Stopped with the export, never left running: a heartbeat that outlived
        // its walk would re-publish the final counts every fifteen seconds for
        // the rest of the session — a live-looking card over an export that
        // finished minutes ago, indistinguishable from one still going.
        clearInterval(heartbeat);
        claimed.release();
      }
    })();

    return reply.code(202).send({ accepted: true, id });
  });

  // ---- abort ---------------------------------------------------------------

  app.post("/sessions/:guid/exports/:id/abort", async (req, reply) => {
    const { guid } = req.params as { guid: string };
    const { id } = req.params as { id: string };
    const paths = sessionPaths(config.dataRoot, guid);
    if (paths === null) return reply.code(400).send({ error: "bad guid" });

    const active = slot.describe();
    if (active === null || active.kind !== "export") {
      return reply.code(409).send({ error: "no export running" });
    }
    // `abort()` is idempotent and the run keeps what it wrote, so this is safe to
    // call twice; the second call finds the job already finished.
    slot.abortNow();

    hub.publish(guid, { type: "export-aborted", id });
    hub.publish(guid, { type: "export-partial", id, reason: "aborted" });

    // Nothing deleted. §8.2: an abort preserves the artefact.
    void paths;
    return reply.code(202).send({ aborted: true, id });
  });

  // ---- artifacts -----------------------------------------------------------

  /**
   * Streams the session's vault into a staging directory the orchestrator then
   * finalises under an `artifactId`.
   *
   * ## Why the caller supplies the id and the runner does not generate one
   *
   * PLAN-v3 §2.2: *"the streaming zip is written by the runner into its artifact
   * dir and finalised under an `artifactId` by the orchestrator."* The split is
   * deliberate and it is why the directory is named by the caller:
   *
   * - §5 makes artifact ids **opaque** — `crypto.randomBytes(32)` → base64url —
   *   because a download path containing the session GUID or the notebook name
   *   leaks both into Caddy's access logs and into any `Referer`. A runner that
   *   generated the id would be deriving it from the GUID it already knows, which
   *   is the leak the design removes.
   * - `ArtifactStat` in the orchestrator looks for a **directory** at
   *   `<ArtifactRoot>/<artifactId>` containing a finalised zip. So a runner that
   *   writes `<guid>.zip` is not merely unidiomatic: the stat never finds it, and
   *   every download 404s.
   *
   * ## Why it is staged, not written in place
   *
   * A zip written directly into its final name is readable while it is being
   * written. A download that arrives mid-write gets a truncated archive with a
   * 200 and no error, and the user cannot tell it from a complete one. The
   * orchestrator's finalise is what moves this into place, and it is the only
   * component with both the artifact volume and the authority to publish.
   */
  app.post("/sessions/:guid/artifacts", async (req, reply) => {
    const { guid } = req.params as { guid: string };
    const body = req.body as { artifactId?: unknown } | undefined;
    const paths = sessionPaths(config.dataRoot, guid);
    if (paths === null) return reply.code(400).send({ error: "bad guid" });

    const artifactId = body?.artifactId;
    // Validated by shape, not sanitised. The same argument as the guid: "reject
    // anything that is not exactly 43 base64url characters" is smaller and more
    // obviously complete than "strip the bad characters", and this string reaches
    // `path.join` to name a directory the orchestrator will then serve.
    if (typeof artifactId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(artifactId)) {
      return reply.code(400).send({ error: "artifactId must be 43 base64url characters" });
    }
    if (!existsSync(paths.outDir)) return reply.code(409).send({ error: "no output" });

    // `<artifactRoot>/.staging/<artifactId>` — a dot directory, so a directory
    // listing of the artifact root never shows an unfinished archive as if it
    // were a publishable one, and so the orchestrator's own scan skips it.
    const staging = join(config.artifactRoot, ".staging", artifactId);
    await mkdir(staging, { recursive: true });
    const target = join(staging, "vault.zip");

    // Streaming, not a system `zip`: a second full copy of the data is the disk
    // spike §8.3 warns about, and a vault can be several gigabytes.
    try {
      await new Promise<void>((resolvePromise, rejectPromise) => {
        const output = createWriteStream(target);
        const zip = archiver("zip", { zlib: { level: 6 } });
        output.on("close", resolvePromise);
        output.on("error", rejectPromise);
        zip.on("warning", rejectPromise);
        zip.on("error", rejectPromise);
        zip.pipe(output);
        // `false` disables the size cap: the quota is enforced before the export
        // starts, and a cap here would abort a nearly-complete archive without
        // telling anyone why.
        zip.directory(paths.outDir, false);
        void zip.finalize();
      });
    } catch (cause) {
      // The partial directory is left, not cleaned: it is inside `.staging`, so
      // nothing treats it as an artifact, and removing it would risk deleting a
      // partially-written archive the orchestrator is in the middle of claiming.
      return reply.code(500).send({
        error: "archive failed",
        detail: cause instanceof Error ? cause.message : "unknown",
      });
    }

    const { size } = await stat(target);

    // 201 with the staging path, not the final one: the orchestrator finalises,
    // and telling the caller where it ended up would invite api to build a
    // download URL from a staging path.
    return reply.code(201).send({
      artifactId,
      stagedAt: join(".staging", artifactId),
      bytes: size,
    });
  });

  app.delete("/sessions/:guid", async (req, reply) => {
    const { guid } = req.params as { guid: string };
    const paths = sessionPaths(config.dataRoot, guid);
    if (paths === null) return reply.code(400).send({ error: "bad guid" });
    removeSessionDirs(paths);
    hub.forget(guid);
    return reply.code(204).send();
  });

  // Convenience for the orchestrator, and the only route that touches the token
  // from outside. Nothing else in the stack calls it.
  app.post("/shutdown", async () => {
    setTimeout(() => process.exit(0), 10).unref();
    return { ok: true };
  });

  return app;
}

/**
 * reasonFromLoginResult reads the package's terminal `login-result` into a reason
 * this process is willing to forward.
 *
 * ## Why this is checked against the union rather than trusted
 *
 * The reason goes to the api, which maps it to a message. A value outside
 * `LOGIN_REASONS` has no mapping and arrives as the generic message — so forwarding
 * an unchecked string would replace "the wrong reason" with "a reason that looks
 * plausible and is not in the table", which is harder to notice and just as wrong.
 *
 * The union is passed in rather than imported: `packages()` loads it lazily so that
 * `/healthz` answers on a container whose Chromium is missing, and this function is
 * called from a request handler that has already loaded them. Importing at module
 * scope would undo that.
 *
 * Returns null for success, where `reason` is deliberately null in the package —
 * every value in the union names something that went wrong.
 */
export function reasonFromLoginResult(
  payload: Record<string, unknown>,
  reasons: readonly string[],
): string | null {
  if (payload.ok === true) return null;
  const reason = payload.reason;
  if (typeof reason === "string" && reasons.includes(reason)) return reason;
  return "unknown";
}

/** A 409 body naming the job holding the slot, or null when the slot is free. */
function busyBody(slot: JobSlot): { error: string; guid: string; kind: string; since: string } | null {
  const active = slot.describe();
  if (active === null) return null;
  return { error: "busy", guid: active.guid, kind: active.kind, since: active.since };
}

/** Started by `main` when run directly. Kept out of `buildApp` so tests never exit. */
export async function main(): Promise<void> {
  const config = loadConfig();
  const app = buildApp(config);
  await app.listen({ host: "0.0.0.0", port: Number(process.env.PORT ?? 3100) });
}

/**
 * Runs `main` only when this file is the process's entry point.
 *
 * Written as a comparison against `process.argv[1]` rather than the idiomatic
 * `require.main === module`, because this file is compiled to CommonJS but loaded
 * as ESM by tsx and by Vitest, and `require` is not defined in the ESM case —
 * a top-level `require.main` reference throws `ERR_AMBIGENT_MODULE_SYNTAX` before
 * a single test in the file runs. That is the same shape of mistake as the
 * Docker CMD naming a file that did not exist: correct-looking, and does not run.
 */
function isEntryPoint(): boolean {
  const invoked = process.argv[1];
  if (invoked === undefined) return false;
  return /(?:^|[\\/])(?:index|runner)\.(?:js|ts)$/.test(invoked);
}

if (isEntryPoint()) {
  void main().catch((cause: unknown) => {
    // The message is printed and nothing else: a config error here must not dump
    // the environment, which is where the token's path and the quota live.
    process.stderr.write(
      `runner failed to start: ${cause instanceof Error ? cause.message : String(cause)}\n`,
    );
    process.exit(1);
  });
}

export { JobBusyError };
