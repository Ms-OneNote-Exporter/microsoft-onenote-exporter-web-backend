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
import { mkdir, stat } from "node:fs/promises";
import { join } from "node:path";
import archiver from "archiver";
import { loadConfig, type RunnerConfig } from "./config.js";
import { EventHub, formatSse, SSE_KEEPALIVE, type RunnerEvent } from "./events.js";
import { JobSlot, JobBusyError, makeSessionDirs, removeSessionDirs, sessionPaths } from "./sessions.js";
import { isValidGuid, readAccount, readCredentialBytes, passwordFrom } from "./credential.js";

/** How often an idle SSE stream is kept alive. */
const KEEPALIVE_MS = 15_000;

/**
 * The packages, loaded lazily.
 *
 * Lazy so that `/healthz` answers on a container whose Chromium is missing, and
 * so importing this module does not pull Playwright into a process that is only
 * running tests. A static import would make the debug-surface route enumeration
 * test load a browser to do it.
 */
async function packages(): Promise<{
  login: (options: Record<string, unknown>) => Promise<boolean>;
  listNotebooks: (options: Record<string, unknown>) => Promise<unknown>;
  runExport: (options: Record<string, unknown>) => Promise<unknown>;
  LOGIN_REASONS: readonly string[];
}> {
  const webauth = (await import("@msout/microsoft-webauth")) as unknown as {
    login: (o: Record<string, unknown>) => Promise<boolean>;
    LOGIN_REASONS: readonly string[];
  };
  const list = (await import("@msout/microsoft-onenote-list-notebooks")) as unknown as {
    listNotebooks: (o: Record<string, unknown>) => Promise<unknown>;
  };
  const exporter = (await import("@msout/microsoft-onenote-export-notebook")) as unknown as {
    runExport: (o: Record<string, unknown>) => Promise<unknown>;
  };
  return {
    login: webauth.login,
    LOGIN_REASONS: webauth.LOGIN_REASONS,
    listNotebooks: list.listNotebooks,
    runExport: exporter.runExport,
  };
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
    const { login } = await packages();

    // `onEvent` is the whole reason this is a library call and not a child
    // process: the challenge and the terminal reason arrive as typed values rather
    // than as log lines matched by their wording.
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
          // `login()` still resolves a boolean, so a caller cannot tell a wrong
          // password from a Microsoft outage. The reason is in the log, and the
          // log is on disk inside the session — this response says only that it
          // failed, because the api maps the reason it learns from the package's
          // own `login-result`, and a reason invented here would be a guess.
          hub.publish(guid, { type: "login-failed", reason: "unknown" });
        }
      } catch (cause) {
        hub.publish(guid, {
          type: "login-failed",
          reason: cause instanceof Error ? cause.name : "unknown",
        });
      } finally {
        claimed.release();
      }
    })();

    // 202: the login runs for minutes. The outcome arrives on the event stream.
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
        const result = (await listNotebooks({
          authFile: paths.authFile,
          keepOpen: false,
        })) as { notebooks?: ReadonlyArray<{ name?: string; url?: string }> };

        hub.publish(guid, {
          type: "notebooks-listed",
          notebooks: (result.notebooks ?? []).map((n) => ({
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

    void (async () => {
      try {
        await runExport({
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
                hub.publish(guid, {
                  type: "export-progress",
                  id,
                  progress: (e.progress ?? { pages: 0, sections: 0, assets: 0 }) as never,
                });
                break;
              case "export-log":
                hub.publish(guid, { type: "export-log", id, line: String(e.line ?? "") });
                break;
              case "export-done":
                hub.publish(guid, {
                  type: "export-done",
                  id,
                  notebook: String(e.notebook ?? ""),
                  pages: Number(e.pages ?? 0),
                  sections: Number(e.sections ?? 0),
                  assets: Number(e.assets ?? 0),
                });
                break;
              case "export-partial":
                hub.publish(guid, { type: "export-partial", id, reason: String(e.reason ?? "aborted") });
                break;
              case "export-aborted":
                hub.publish(guid, { type: "export-aborted", id });
                break;
              default:
                break;
            }
          },
        });
      } catch (cause) {
        hub.publish(guid, {
          type: "error",
          message: cause instanceof Error ? cause.message : "export failed",
        });
      } finally {
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
