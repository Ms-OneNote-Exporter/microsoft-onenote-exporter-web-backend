/**
 * The export terminal, and the counts it must carry.
 *
 * ## Why this file exists at all
 *
 * `runExport`'s return value was discarded and the package's `export-done` was
 * relayed verbatim, so a run that wrote **zero pages** because every section
 * failed crossed into the api as a success and the user downloaded a 130-byte
 * empty zip with `state: "done"`. Observed on the deployed host, 2026-10-09.
 *
 * The first attempt to fix that passed **115 runner tests** while containing
 * three defects, because nothing here existed:
 *
 *   - `terminalSeen` was set by the package's `export-done` *and* used to decide
 *     whether to publish the runner's own. The package always emits it, so the
 *     terminal was suppressed and never replaced — no terminal at all, and every
 *     successful export would have hung at `running`.
 *   - the stats were read as `stats.pages` / `stats.sections` / `stats.assets`.
 *     The package returns `totalPages` / `totalSections` / `totalAssets`. Every
 *     read was `undefined`, so every export reported zero pages.
 *   - a throwing `runExport` published all-zero counts, which the api's
 *     classification reads as **done**.
 *
 * `events.test.ts` cannot catch any of that: it feeds `formatSse` a hand-written
 * event object and never runs an export. So these tests drive the real route with
 * a mocked package that **returns the package's real field names** — a rename on
 * either side now fails here rather than in production.
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { runExport } from "@msout/microsoft-onenote-export-notebook";

vi.mock("@msout/microsoft-onenote-list-notebooks", () => ({
  listNotebooks: vi.fn(async () => []),
}));

vi.mock("@msout/microsoft-webauth", () => ({
  login: vi.fn(async () => true),
  LOGIN_REASONS: ["unknown"],
}));

vi.mock("@msout/microsoft-onenote-export-notebook", () => ({
  runExport: vi.fn(),
}));

import { buildApp } from "../src/index.js";
import { sessionPaths } from "../src/sessions.js";

const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const TOKEN = "t".repeat(43);
const ID = "artifact-id-1";

/**
 * Transcribed from `newStats()` in the installed package, so the mock cannot
 * drift into agreeing with a wrong reader.
 *
 * Note the `total*` prefix. It is the whole point of this file: reading
 * `stats.pages` here yields `undefined`, and that is exactly the bug.
 */
function packageStats(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    totalPages: 0,
    totalSections: 0,
    totalAssets: 0,
    failedPages: 0,
    failedSections: 0,
    failedGroups: 0,
    failedAssets: 0,
    notebookNotFound: false,
    ...over,
  };
}

let dataRoot: string;

beforeEach(() => {
  vi.mocked(runExport).mockReset();
  dataRoot = mkdtempSync(join(tmpdir(), "runner-export-terminal-"));
  const paths = sessionPaths(dataRoot, GUID);
  if (paths === null) throw new Error("the test guid was rejected by sessionPaths");
  mkdirSync(paths.dir, { recursive: true });
  // The route refuses without an auth file, so one has to exist.
  writeFileSync(paths.authFile, "{}");
});

afterEach(() => {
  rmSync(dataRoot, { recursive: true, force: true });
});

async function startExport(): Promise<string> {
  const app = buildApp({
    dataRoot,
    port: 0,
    host: "127.0.0.1",
    token: TOKEN,
    credentialBodyLimit: 4096,
    ringSize: 64,
  } as never);
  const address = await app.listen({ port: 0, host: "127.0.0.1" });

  const response = await fetch(`${address}/sessions/${GUID}/exports`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-runner-token": TOKEN,
    },
    body: JSON.stringify({ id: ID, notebook: "MS is great" }),
  });
  if (response.status !== 202) {
    throw new Error(`export route answered ${response.status}: ${await response.text()}`);
  }
  return address;
}

/**
 * Every terminal frame the hub holds for this session.
 *
 * The type is inside the `data:` JSON — the runner's wire format has no `event:`
 * line, which is why a parser looking for `event:` reports "nothing published".
 *
 * Polls, because the export runs detached: the route answers 202 and the work
 * continues after the response.
 */
async function terminalsFor(address: string): Promise<Array<Record<string, unknown>>> {
  const deadline = Date.now() + 3_000;
  for (;;) {
    const controller = new AbortController();
    let text = "";
    try {
      const response = await fetch(`${address}/events?guid=${GUID}&since=0`, {
        signal: controller.signal,
        headers: { "x-runner-token": TOKEN },
      });
      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      while (Date.now() < deadline) {
        const { value, done } = await reader.read();
        if (done) break;
        text += decoder.decode(value, { stream: true });
        if (text.includes("export-done") || text.includes("export-partial")) break;
      }
      controller.abort();
    } catch {
      // An abort is the normal way out of a stream that never ends.
    }

    const terminals: Array<Record<string, unknown>> = [];
    for (const frame of text.split("\n\n")) {
      if (frame.trim() === "" || frame.startsWith(":")) continue;
      let payload: Record<string, unknown> = {};
      for (const line of frame.split("\n")) {
        if (line.startsWith("data: ")) {
          try {
            payload = JSON.parse(line.slice("data: ".length)) as Record<string, unknown>;
          } catch {
            payload = {};
          }
        }
      }
      if (payload.type === "export-done" || payload.type === "export-partial") {
        terminals.push(payload);
      }
    }
    if (terminals.length > 0 || Date.now() >= deadline) return terminals;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

describe("the export terminal", () => {
  it("publishes exactly one terminal, carrying the counts from stats", async () => {
    // The package emits its own `export-done` and then returns. Both halves are
    // what the real 0.5.0 does, in that order.
    vi.mocked(runExport).mockImplementation(async (options: Record<string, unknown>) => {
      const onEvent = options.onEvent as (e: Record<string, unknown>) => void;
      onEvent({ type: "export-started", id: ID });
      onEvent({ type: "export-done", id: ID, notebook: "MS is great", pages: 0, sections: 0, assets: 0 });
      return packageStats({ totalPages: 7, totalSections: 3, totalAssets: 2 });
    });

    const address = await startExport();
    const terminals = await terminalsFor(address);

    // Exactly one. A suppressed-and-never-replaced terminal is the defect that
    // passed 115 tests; a duplicated one is the same mistake in the other
    // direction, and `#finishExport` would drop it silently.
    expect(terminals).toHaveLength(1);
    expect(terminals[0]!.type).toBe("export-done");

    // `total*`, not `pages`. These are `undefined` if the reader uses the wrong
    // prefix, which is why the mock returns the package's real field names.
    expect(terminals[0]!.pages).toBe(7);
    expect(terminals[0]!.sections).toBe(3);
    expect(terminals[0]!.assets).toBe(2);

    // The notebook name is only ever on the package's event — `stats` has no such
    // field — so it has to be captured while suppressing it.
    expect(terminals[0]!.notebook).toBe("MS is great");
  });

  it("carries the failure counts, so the api can tell a total loss from a total success", async () => {
    // The observed failure exactly: the section list rendered, every section
    // failed to export, and zero pages were written.
    vi.mocked(runExport).mockImplementation(async (options: Record<string, unknown>) => {
      const onEvent = options.onEvent as (e: Record<string, unknown>) => void;
      onEvent({ type: "export-done", id: ID, notebook: "MS is great", pages: 0, sections: 1, assets: 0 });
      return packageStats({ totalPages: 0, totalSections: 1, failedSections: 1 });
    });

    const address = await startExport();
    const terminals = await terminalsFor(address);

    expect(terminals).toHaveLength(1);
    expect(terminals[0]!.pages).toBe(0);
    expect(terminals[0]!.failedSections).toBe(1);
    expect(terminals[0]!.notebookNotFound).toBe(false);
  });

  it("carries notebookNotFound, which is set for an empty notebook as well as an unloaded one", async () => {
    vi.mocked(runExport).mockImplementation(async (options: Record<string, unknown>) => {
      const onEvent = options.onEvent as (e: Record<string, unknown>) => void;
      onEvent({ type: "export-done", id: ID, notebook: "Empty", pages: 0, sections: 0, assets: 0 });
      return packageStats({ notebookNotFound: true });
    });

    const address = await startExport();
    const terminals = await terminalsFor(address);

    expect(terminals).toHaveLength(1);
    expect(terminals[0]!.notebookNotFound).toBe(true);
  });

  it("adds no terminal of its own when the package already emitted one for an abort", async () => {
    // The abort path returns early (exporter.js:1641) after publishing
    // `export-aborted` + `export-partial`. The runner must not then publish a
    // second terminal: `#finishExport` dedupes by artifactId, so whichever
    // arrives first wins and the other is dropped without a word.
    vi.mocked(runExport).mockImplementation(async (options: Record<string, unknown>) => {
      const onEvent = options.onEvent as (e: Record<string, unknown>) => void;
      onEvent({ type: "export-aborted", id: ID });
      onEvent({ type: "export-partial", id: ID, reason: "aborted" });
      return packageStats({ totalPages: 4 });
    });

    const address = await startExport();
    const terminals = await terminalsFor(address);

    expect(terminals).toHaveLength(1);
    expect(terminals[0]!.type).toBe("export-partial");
  });

  it("publishes a terminal when runExport throws, marked as a failed walk", async () => {
    // Without this the session sits at `exporting` with a live runner and no
    // outcome until the absolute cap. And all-zero counts with
    // `notebookNotFound: false` classify as **done**, which is how a thrown
    // export was on track to being reported as a success.
    vi.mocked(runExport).mockImplementation(async () => {
      throw new Error("Chromium is not installed");
    });

    const address = await startExport();
    const terminals = await terminalsFor(address);

    expect(terminals).toHaveLength(1);
    expect(terminals[0]!.type).toBe("export-done");
    expect(terminals[0]!.walkFailed).toBe(true);
    // The name comes from the request; the package never emitted an event here.
    expect(terminals[0]!.notebook).toBe("MS is great");
    // And no internals on the wire — the cause belongs in the api's log.
    expect(JSON.stringify(terminals[0])).not.toContain("Chromium");
  });
});