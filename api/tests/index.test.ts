/**
 * Does the entrypoint actually work?
 *
 * ## Why this file exists
 *
 * `src/index.ts` was missing for the whole life of the project, and 481 tests
 * passed without it. They test `buildServer(config, deps)` directly, because that
 * is the seam that makes them fast and hermetic — which is the right way to test
 * them.
 *
 * The consequence was that `npm start`, `npm run dev` and the container `CMD` all
 * pointed at a file that was not there. `dist/index.js` did not exist, so the
 * Docker image built cleanly and then died on start, and `docker compose up`
 * reported success while doing it.
 *
 * Nothing in the suite could have caught that, because nothing in the suite
 * touched the entrypoint. This file is the answer to that: boot the real thing,
 * against a temporary database, and assert the process would have started.
 *
 * It boots the real config loader, the real database, the real SSE hub and the
 * real binder, and stubs only the orchestrator — the one dependency that would
 * otherwise need a socket.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { boot, createAuthOutcomeHandler, splitListen, SWEEP_INTERVAL, type BootLog, type Booted } from "../src/index.js";
import { FakeOrchestrator } from "../mock/fake-orchestrator.js";
import { OrchestratorApi } from "../src/orchestrator-client.js";
import { ConfigError } from "../src/config.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";

let dir: string;
let booted: Booted | undefined;

/**
 * Builds a valid environment pointing at a temporary database.
 *
 * Secrets are written to files and passed by path, because that is what a real
 * deployment does and the `_FILE` path is the one compose takes. Writing them
 * inline would test the branch a deployment never uses.
 */
function envFor(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  const csrfKey = join(dir, "csrf_key");
  const hmac = join(dir, "hmac");
  const runnerToken = join(dir, "runner_token");
  writeFileSync(csrfKey, `${"A".repeat(43)}\n`, { mode: 0o400 });
  writeFileSync(hmac, `${"B".repeat(43)}\n`, { mode: 0o400 });
  // A file rather than an env var, so this test exercises the `_FILE` path the
  // deployment uses. The value is a bearer token with the runner's 16-character
  // minimum, not 43 like the other two secrets.
  writeFileSync(runnerToken, "runner-token-for-tests\n", { mode: 0o400 });

  return {
    ALLOWED_ORIGINS: "https://app.example.com",
    PUBLIC_ORIGIN: "https://one-backend.example.com",
    CSRF_KEY_FILE: csrfKey,
    ORCHESTRATOR_HMAC_SECRET_FILE: hmac,
    RUNNER_TOKEN_FILE: runnerToken,
    ORCHESTRATOR_URL: "http://orchestrator:9100",
    DATABASE_PATH: join(dir, "api.db"),
    LOG_LEVEL: "error",
    ...overrides,
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "msout-boot-"));
});

afterEach(async () => {
  if (booted !== undefined) {
    await booted.app.close();
    booted.db.close();
    booted = undefined;
  }
  rmSync(dir, { recursive: true, force: true });
});

describe("the entrypoint", () => {
  it("exists, and the build produces the file the CMD runs", async () => {
    // The literal assertion that was missing. `dist/index.js` is what
    // package.json's `start` and the Dockerfile's CMD both name, so its absence
    // means the container builds and then dies.
    const { existsSync } = await import("node:fs");
    const entry = new URL("../src/index.ts", import.meta.url);
    expect(existsSync(entry), "src/index.ts must exist").toBe(true);

    // And the module actually exports something runnable, so an empty file or one
    // that only declares types would fail here rather than at container start.
    const module = await import("../src/index.js");
    expect(typeof module.boot).toBe("function");
  });

  it("boots the real process against a temporary database", async () => {
    // The orchestrator is the only thing stubbed, and only because it would need a
    // socket. Config, database, hub, limiter, binder and server are all real.
    booted = await boot(envFor(), new FakeOrchestrator({ size: 2 }));

    // It answered without throwing, which is the whole claim.
    expect(booted).toBeDefined();
    expect(booted!.config.publicOrigin).toBe("https://one-backend.example.com");
  });

  it("creates the database directory rather than failing on a missing path", async () => {
    // In a container DATABASE_PATH is a named volume mount point. If the directory
    // is absent, SQLite cannot create the file and the process dies at boot — for
    // a reason that has nothing to do with the code.
    const nested = join(dir, "a", "b", "c", "api.db");
    booted = await boot(envFor({ DATABASE_PATH: nested }), new FakeOrchestrator({ size: 1 }));

    const { existsSync } = await import("node:fs");
    expect(existsSync(nested)).toBe(true);
  });

  it("seeds the pool from the orchestrator's slot ids", async () => {
    const orchestrator = new FakeOrchestrator({ size: 3 });
    booted = await boot(envFor(), orchestrator);

    // Without this the pool is empty and every login reports "every session is
    // busy" — the bug the mock found. Asserted here because the entrypoint is
    // where the seeding actually happens; the syncPool unit test only proves the
    // function works when called.
    const rows = booted!.db.listRunners();
    expect(rows).toHaveLength(3);
    expect(rows.every((r) => r.status === "idle")).toBe(true);
    expect(rows.map((r) => r.id).sort()).toEqual(orchestrator.slotIds().sort());
  });

  it("refuses to start on a bad configuration, rather than defaulting", async () => {
    // No PUBLIC_ORIGIN. If this resolved to something, every artifact download
    // URL in every snapshot would be built from a guess.
    await expect(
      boot(envFor({ PUBLIC_ORIGIN: "" }), new FakeOrchestrator({ size: 1 })),
    ).rejects.toThrow(ConfigError);
  });

  it("refuses to start when a secret file is missing, naming the variable", async () => {
    await expect(
      boot(
        envFor({ CSRF_KEY_FILE: join(dir, "does-not-exist") }),
        new FakeOrchestrator({ size: 1 }),
      ),
    ).rejects.toThrow(/CSRF_KEY_FILE/);
  });

  it("reports an orchestrator with no slot ids rather than inventing them", async () => {
    // A rolling deploy: a new api can briefly talk to an orchestrator that does
    // not expose slot names. Inventing ids locally was rejected because a guess
    // that collides is one session releasing another's container mid-export, so
    // the correct response is to seed nothing and say so.
    const orchestrator = new FakeOrchestrator({ size: 2 });
    const withoutIds = {
      stats: async () => ({
        ok: true as const,
        value: { size: 2, byState: { idle: 2 }, runnerTtlSeconds: 300 },
      }),
      healthz: orchestrator.healthz.bind(orchestrator),
      claim: orchestrator.claim.bind(orchestrator),
      release: orchestrator.release.bind(orchestrator),
      recycle: orchestrator.recycle.bind(orchestrator),
      remove: orchestrator.remove.bind(orchestrator),
      stat: orchestrator.stat.bind(orchestrator),
    } as unknown as OrchestratorApi;

    booted = await boot(envFor(), withoutIds);

    // It booted — an unreachable control plane must not stop the api answering
    // reads — and seeded nothing, rather than making ids up.
    expect(booted!.db.listRunners()).toHaveLength(0);
  });
});

describe("splitListen", () => {
  it("parses host:port", () => {
    expect(splitListen("0.0.0.0:3000")).toEqual({ host: "0.0.0.0", port: 3000 });
    expect(splitListen(":8080")).toEqual({ host: "", port: 8080 });
    expect(splitListen("127.0.0.1:0")).toEqual({ host: "127.0.0.1", port: 0 });
  });

  it("rejects a port that is not a port", () => {
    // A typo in LISTEN would otherwise become a listen on a random port, or on
    // none at all.
    for (const bad of ["0.0.0.0:notaport", "0.0.0.0:", "0.0.0.0:99999", "3000"]) {
      expect(() => splitListen(bad), bad).toThrow(ConfigError);
    }
  });
});

describe("the sweep interval", () => {
  it("is far shorter than the shortest TTL", () => {
    // Otherwise an expired session could outlive its TTL by a long margin, and
    // §2.5's rule — an expired session is never resurrected — would be true on
    // paper and late in practice.
    expect(SWEEP_INTERVAL.ms).toBeLessThan(SWEEP_INTERVAL.shortestTtlMs);
  });
});

/**
 * Issue #49: the api has to *say* a login was refused.
 *
 * ## Why this file rather than `auth-state.test.ts`
 *
 * That file drives the adapter's own callback and asserts what lands in the
 * database — correctly, because the adapter is transport and stores nothing. But
 * the callback the adapter actually receives is wired in `boot`, and for fifteen
 * minutes of a user's life it wrote the refusal to the database and emitted
 * nothing. The database is the authority; the browser is SSE-only. So the gap is
 * not in a module, it is in the wiring, and wiring is what this file exists to
 * cover.
 *
 * ## Why the event is enough on its own
 *
 * `auth-state` already exists and `App.tsx` handles it generically by re-reading
 * `GET /api/session/status`, which reports `auth_state: "failed"`. No frontend
 * change, no new event name, no new vocabulary — this is the missing signal, not a
 * missing feature.
 */
describe("createAuthOutcomeHandler", () => {
  const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

  let outcomeDb: Db;
  let outcomeSse: SseHub;
  let logged: { level: string; msg: string }[];

  /** A log that keeps its lines instead of printing them. */
  const log: BootLog = {
    info: (msg) => void logged.push({ level: "info", msg }),
    warn: (msg) => void logged.push({ level: "warn", msg }),
    error: (msg) => void logged.push({ level: "error", msg }),
  };

  /** The callback `boot` hands the adapter, built over the real db and hub. */
  function handler() {
    return createAuthOutcomeHandler({ db: outcomeDb, sse: outcomeSse, log });
  }

  /**
   * The rows a browser would receive, read off the wire.
   *
   * Bytes rather than hub internals, for the reason `sweep.test.ts`'s `watch` gives:
   * the question is "what does the browser get told", and it is answerable only by
   * the frame a browser could parse.
   */
  function watch(guid: string): () => { type: string; data: unknown }[] {
    const written: string[] = [];
    outcomeSse.attach(
      guid,
      {
        write: (chunk: string) => {
          written.push(String(chunk));
          return true;
        },
        end: () => undefined,
      } as never,
      null,
    );
    return () =>
      written
        .join("")
        .split("\n\n")
        .filter((frame) => frame.trim() !== "" && !frame.startsWith(":"))
        .map((frame) => {
          const out: { type: string; data: unknown } = { type: "", data: null };
          for (const line of frame.split("\n")) {
            if (line.startsWith("event: ")) out.type = line.slice("event: ".length);
            else if (line.startsWith("data: ")) out.data = line.slice("data: ".length);
          }
          return out;
        });
  }

  beforeEach(() => {
    logged = [];
    outcomeDb = new Db(":memory:");
    outcomeSse = new SseHub();
    outcomeDb.createSession({
      guid: GUID,
      secretHash: hashSecret("S".repeat(43)),
      csrfKey: generateCsrfKey(),
      now: Date.now(),
      expiresAt: Date.now() + 3_600_000,
    });
    // The one state a login is in when the runner reports how it went: a claim has
    // bound a slot and `auth_state` is awaiting an answer. Not a convenient shape —
    // it is the shape, and `markAuthFailed`'s `WHERE auth_state = 'authenticating'`
    // is what makes anything the handler does conditional on it.
    outcomeDb.run(
      `UPDATE sessions SET state = 'authenticating', auth_state = 'authenticating',
                          runner_id = 'slot-1'
        WHERE guid = ?`,
      GUID,
    );
  });

  afterEach(() => {
    outcomeDb.close();
  });

  it("emits auth-state failed when the runner refuses a login", () => {
    // **The whole of #49 on this side.** Before this, the refusal was written to the
    // database and sent to nobody, and the next thing the user was told was the
    // sweeper's `challenge-expired` fifteen minutes later.
    const frames = watch(GUID);

    handler()(GUID, "failed");

    // On the wire, because the wire is the only thing the browser has. Delete the
    // emit in `index.ts` and this goes red while every database assertion below
    // still passes — which is what makes it a test of the signal rather than of the
    // write.
    expect(frames().map((f) => f.type)).toContain("auth-state");
    expect(frames().find((f) => f.type === "auth-state")?.data).toBe(
      JSON.stringify({ state: "failed" }),
    );
  });

  it("still records the failure, so the row and the event agree", () => {
    // The event is a nudge, never the record: it says "re-read the status", and what
    // it re-reads has to say `failed`. An emit without the write would leave the
    // client refreshing to an authenticating session and showing a spinner.
    handler()(GUID, "failed");

    expect(outcomeDb.getSession(GUID)?.auth_state).toBe("failed");
  });

  it("emits nothing extra on a successful login", () => {
    // The mirror, and the reason the failure needed saying at all: success already
    // has a signal — the runner's own `login-success` frame is forwarded verbatim
    // and the client refreshes on it. A second `auth-state` here would be a frame
    // per successful sign-in that nobody asked for.
    const frames = watch(GUID);

    handler()(GUID, "authenticated");

    expect(outcomeDb.getSession(GUID)?.auth_state).toBe("valid");
    expect(frames().map((f) => f.type)).not.toContain("auth-state");
  });

  it("warns instead of emitting twice when the runner repeats a failure", () => {
    // A reconnecting pump replays its buffer, so a duplicate `login-failed` is a
    // real event rather than a hypothetical. The second one writes nothing
    // (`markAuthFailed`'s guard), so it must not announce a change that did not
    // happen — the warning is the record of it.
    handler()(GUID, "failed");
    logged = [];

    handler()(GUID, "failed");

    expect(outcomeDb.getSession(GUID)?.auth_state).toBe("failed");
    expect(logged.map((l) => l.level)).toEqual(["warn"]);
  });
});
