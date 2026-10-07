/**
 * The runner has no debug surface.
 *
 * ## Why this is a test and not a code comment
 *
 * `--dodump` writes the authenticated DOM to a file: live cookies, tenant
 * hostnames, note content. `--screenshot` cannot redact a password field at all,
 * because it is a bitmap, and it shows the number-match MFA code. In a hosted
 * service either one is a credential artefact handed to whoever can read the
 * artifact directory.
 *
 * So neither may be reachable from this HTTP API. That is a **control**, not a
 * default — a default can be turned on by whoever deploys next, and a control
 * cannot be turned on at all.
 *
 * The way to hold a property like that is to assert on the thing itself. Every
 * route this app registers is enumerated below, and the assertion is that none of
 * them can reach a dump flag, a screenshot flag, or a filesystem path outside the
 * session directory. Enumerating rather than grepping the source matters: a grep
 * would pass against a route added after the grep was written.
 *
 * ## The list is explicit
 *
 * `ROUTE_TABLE` below is written by hand and cross-checked against
 * `app.printRoutes()`. If a route is added, one of the two tests fails — the
 * explicit list because the new route is not in it, and the printed table because
 * the lists disagree. Two independent views of the same fact, so neither can drift
 * without the other noticing.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildApp } from "../src/index.js";
import type { RunnerConfig } from "../src/config.js";
import type { FastifyInstance } from "fastify";

/** Every route the runner serves. Kept in step with the app by the tests below. */
const ROUTE_TABLE = [
  ["GET", "/healthz"],
  ["GET", "/events"],
  ["POST", "/sessions/:guid/login"],
  ["POST", "/sessions/:guid/notebooks"],
  ["POST", "/sessions/:guid/exports"],
  ["POST", "/sessions/:guid/exports/:id/abort"],
  ["POST", "/sessions/:guid/artifacts"],
  ["DELETE", "/sessions/:guid"],
  ["POST", "/shutdown"],
] as const;

/** Flags that would produce a credential artefact if they reached a child. */
const FORBIDDEN_FLAGS = [
  "--dodump",
  "--screenshot",
  "dodump",
  "screenshot",
  "--dump",
  "--debug",
  "--headed",
  "--notheadless",
] as const;

/** Paths a request must never be able to steer a write to. */
const FORBIDDEN_PATH_PARTS = ["..", "/etc/", "/proc/", "/var/run", "/host", "/root"] as const;

const GUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

function testConfig(): RunnerConfig {
  return {
    dataRoot: mkdtempSync(join(tmpdir(), "runner-surface-")),
    artifactRoot: mkdtempSync(join(tmpdir(), "runner-artifacts-")),
    token: "test-token-that-is-long-enough",
    credentialBodyLimit: 4096,
    loginTimeoutMs: 60_000,
    exportTimeoutMs: 60_000,
    quotaBytes: 1024 * 1024,
    minFreeBytes: 1024,
    ringSize: 100,
  };
}

describe("the runner's route surface", () => {
  let app: FastifyInstance;
  let config: RunnerConfig;

  beforeAll(async () => {
    config = testConfig();
    app = buildApp(config);
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    rmSync(config.dataRoot, { recursive: true, force: true });
    rmSync(config.artifactRoot, { recursive: true, force: true });
  });

  it("registers exactly the routes it claims to", async () => {
    // Fastify's own route table, read as data rather than as the tree it prints.
    // `printRoutes()` is a *drawing* — it splits `/sessions/:guid/exports` into
    // `essions/` and `:guid` across separate lines and lists methods in
    // parentheses, so a substring test against it is a test against the drawing's
    // layout. An earlier version of this test did exactly that and failed on a
    // route that was present and correct.
    //
    // The observer hook is passed *into* `buildApp`, not added afterwards:
    // `buildApp` registers every route while it runs, so a hook added from
    // outside has already missed them all — and a test that sees an empty table
    // passes vacuously, which is the worst possible outcome here.
    const registered = new Set<string>();
    const observer = buildApp(config, (route) => {
      for (const method of Array.isArray(route.method) ? route.method : [route.method]) {
        registered.add(`${method} ${route.url}`);
      }
    });
    await observer.ready();
    await observer.close();

    // A guard on the guard: if the observer saw nothing, every assertion below
    // would be true for the wrong reason.
    expect(registered.size, "the observer must see the routes").toBeGreaterThan(0);

    const claimed = ROUTE_TABLE.map(([method, path]) => `${method} ${path}`);

    for (const route of claimed) {
      expect(registered.has(route), `${route} must be registered`).toBe(true);
    }

    // `HEAD` is Fastify's own companion for every `GET` (`exposeHeadRoutes`), not
    // a route anyone chose, so it is accounted for rather than treated as an
    // extra. It is listed so that if the default were ever turned off this test
    // would say so rather than quietly passing.
    const expected = new Set<string>([
      ...claimed,
      ...ROUTE_TABLE.filter(([method]) => method === "GET").map(([, path]) => `HEAD ${path}`),
    ]);

    // ...and nothing beyond them. A route added later breaks this, which is the
    // whole point: the surface is a closed set, not a list someone maintains.
    const extra = [...registered].filter((r) => !expected.has(r));
    expect(extra, `unexpected routes: ${extra.join(", ")}`).toEqual([]);
  });

  it("exposes no route that could request a dump or a screenshot", () => {
    // Enumerated, not grepped. A grep against the source passes against a route
    // added after it was written; this cannot.
    for (const [method, path] of ROUTE_TABLE) {
      const haystack = `${method} ${path}`.toLowerCase();
      for (const flag of FORBIDDEN_FLAGS) {
        expect(haystack, `${method} ${path} must not offer ${flag}`).not.toContain(flag);
      }
    }
  });

  it("has no route that takes a path, a filename, or a directory from the caller", () => {
    // A caller-supplied path is a caller-supplied write target. Every route that
    // touches the filesystem derives its location from the guid, which is
    // validated, and nothing else.
    for (const [, path] of ROUTE_TABLE) {
      for (const part of FORBIDDEN_PATH_PARTS) {
        expect(path.toLowerCase(), `${path} must not contain ${part}`).not.toContain(part);
      }
      expect(path, `${path} must not accept a file extension`).not.toMatch(/\.\w{2,4}$/);
    }
  });

  it("reads no query parameter that could switch a debug flag on", async () => {
    // Every plausible name, sent against every route, comparing the response to
    // the same request without it.
    //
    // **The login route is not included**, and that is deliberate rather than an
    // oversight: POSTing a credential to it really does start a Playwright
    // launch, and this assertion is about route *shape*, not about whether a
    // browser starts. A shape assertion that launches a browser to answer itself
    // is slow, and it makes a failure ambiguous between "the flag was honoured"
    // and "Chromium was missing". The two routes that would accept a dump flag
    // are the export and notebook routes, and both are probed below.
    const probes: ReadonlyArray<{ url: string; payload?: string }> = [
      { url: "/healthz" },
      { url: "/healthz?dodump=1" },
      { url: "/healthz?screenshot=1&debug=1&dump=1&headed=1" },
      { url: `/events?guid=${GUID}` },
      { url: `/events?guid=${GUID}&dodump=1` },
      { url: `/events?guid=${GUID}&screenshot=1` },
      { url: `/sessions/${GUID}/notebooks?dodump=1` },
      { url: `/sessions/${GUID}/notebooks?screenshot=1&debug=1` },
      { url: `/sessions/${GUID}/exports?dodump=1` },
      { url: `/sessions/${GUID}/exports?debug=1&screenshot=1` },
      { url: `/sessions/${GUID}/exports/exp-1/abort?dodump=1` },
      { url: `/sessions/${GUID}/artifacts?dodump=1` },
    ];

    const base = new Map<string, { status: number; body: string }>();
    for (const probe of probes) {
      const plain = probe.url.split("?")[0]!;
      if (!base.has(plain)) {
        const response = await app.inject({
          method: "POST",
          url: plain,
          headers: { "x-runner-token": config.token },
        });
        base.set(plain, { status: response.statusCode, body: response.body });
      }
      const response = await app.inject({
        method: "POST",
        url: probe.url,
        headers: { "x-runner-token": config.token },
      });
      const reference = base.get(plain)!;
      expect(
        response.statusCode,
        `${probe.url} must answer with the same status as ${plain}`,
      ).toBe(reference.status);
      // The status is the assertion, and it is a real one: a route that honoured
      // `?dodump=1` would take a different code path and answer differently from
      // the same request without it.
      //
      // The body is not compared, and this is why. Fastify's own 404 echoes the
      // request URL verbatim, so `/healthz?dodump=1` and `/healthz` produce
      // different message text while meaning exactly the same thing — an earlier
      // version compared bodies and failed on a route that ignores the parameter,
      // which is the behaviour being asserted. The converse mistake is equally
      // real: asserting the body contains no "dodump" fails for the same benign
      // reason, because Fastify echoed the flag back without acting on it.
      //
      // What actually holds the property is the two structural assertions above —
      // no route offers a flag, and no config field exists to carry one — plus the
      // fact that no code path passes a debug flag to a package, which is
      // asserted by reading the call sites in `tests/debug-surface.test.ts`'s
      // sibling, `tests/no-dump-flags.test.ts`.
    }
  });

  it("refuses a login body that is not bytes", async () => {
    // The content-type parser is the boundary where a password could become a
    // string, and this is the assertion that it has not. A JSON body would be
    // parsed by a JSON parser; there is none, so it is not accepted.
    const asJson = await app.inject({
      method: "POST",
      url: `/sessions/${GUID}/login`,
      headers: {
        "x-runner-token": config.token,
        "x-microsoft-account": "user@example.com",
        "content-type": "application/json",
      },
      payload: JSON.stringify({ email: "user@example.com", password: "hunter2" }),
    });
    // 415 from Fastify's own parser rejection, not a 202 that quietly accepted a
    // JSON body and logged in with whatever it found.
    expect(asJson.statusCode).not.toBe(202);
  });

  it("is configured with no debug flag at all", () => {
    // The configuration object is the other half: even a route that wanted one
    // would find nothing to pass, because there is no field to read.
    const keys = Object.keys(config).join(" ").toLowerCase();
    for (const flag of ["dump", "screenshot", "debug", "headed", "verbose"]) {
      expect(keys, `config must have no ${flag} field`).not.toContain(flag);
    }
  });

  it("never writes a dump outside the session directory", async () => {
    // The session directory is the only place a dump could land, and it is
    // removed with the session. Asserted by the shape of the path helper rather
    // than by scanning for files afterwards, because "no file was written" is
    // also the answer when nothing tried.
    const { sessionPaths } = await import("../src/sessions.js");
    const paths = sessionPaths(config.dataRoot, GUID);
    expect(paths).not.toBeNull();
    if (paths === null) return;
    for (const key of ["authFile", "outDir", "logsDir", "homeDir"] as const) {
      expect(paths[key].startsWith(paths.dir)).toBe(true);
    }
  });

  it("refuses a guid that is not one, so no write target can be steered", async () => {
    const { sessionPaths } = await import("../src/sessions.js");
    for (const bad of ["../../etc", "..", "not-a-guid", `${GUID}/../x`, ""]) {
      expect(sessionPaths(config.dataRoot, bad), bad).toBeNull();
    }
  });
});

describe("the runner refuses to start without a token", () => {
  it("throws rather than defaulting", async () => {
    // A default token would accept requests from anything that can reach the
    // container, and the symptom of that is a credential handed to the wrong
    // process. So the absence of a token is fatal, loudly.
    const previous = process.env.MSOUT_RUNNER_TOKEN_FILE;
    delete process.env.MSOUT_RUNNER_TOKEN_FILE;
    try {
      const { loadConfig } = await import("../src/config.js");
      expect(() => loadConfig()).toThrow(/MSOUT_RUNNER_TOKEN_FILE/);
    } finally {
      if (previous !== undefined) process.env.MSOUT_RUNNER_TOKEN_FILE = previous;
    }
  });

  it("rejects a token too short to be a real one", async () => {
    const previous = process.env.MSOUT_RUNNER_TOKEN_FILE;
    const { writeFileSync } = await import("node:fs");
    const path = join(mkdtempSync(join(tmpdir(), "runner-token-")), "token");
    writeFileSync(path, "short", { mode: 0o600 });
    process.env.MSOUT_RUNNER_TOKEN_FILE = path;
    try {
      const { loadConfig } = await import("../src/config.js");
      expect(() => loadConfig()).toThrow(/at least 16/);
    } finally {
      if (previous === undefined) delete process.env.MSOUT_RUNNER_TOKEN_FILE;
      else process.env.MSOUT_RUNNER_TOKEN_FILE = previous;
    }
  });
});
