/**
 * A fresh archive: `out/` is emptied before every export.
 *
 * ## The bug this file is about
 *
 * `out/` was never cleared. The export package merges into whatever is already
 * there and says so — `warnIfOutputExists`, `exporter.js:1492`:
 *
 * > Files from a previous run that are no longer in the notebook are left in
 * > place, so this is a merge, not a clean mirror. Remove the folder first for a
 * > clean export.
 *
 * It warns and then does nothing, because the CLI's user is expected to read the
 * warning. The runner has no user at a prompt, so every session accumulated, and
 * the third shape of the bug is the one that matters: **a second export of the
 * same notebook shipped the first one's pages, including pages deleted from
 * OneNote in between.** The archive looked current and was not, and nothing said
 * so anywhere — the counts come from this run and the file list does not.
 *
 * ## What is asserted here, and what is not
 *
 * The claim under test is the **archive**, not the directory. A test that reads
 * `out/` back proves only that the runner tidied up; what the user downloads is
 * `vault.zip`, built by archiver from that directory, and a bug between the two
 * is exactly the bug a user hits. So the entry list is read out of the zip.
 *
 * The zip is parsed by hand, from the End Of Central Directory. `runner/Dockerfile`
 * asserts the runtime dependency set is exactly the three `@msout` packages plus
 * `archiver` and `fastify`, by name; a zip reader would be one more name in that
 * list and a lockfile diff to argue about, for a format whose index is two fixed
 * records. `tests/contract.test.ts` is the file that reads the other side of a
 * contract, and it reads it because nobody else can.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rm } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { runExport } from "@msout/microsoft-onenote-export-notebook";

vi.mock("@msout/microsoft-onenote-list-notebooks", () => ({
  listNotebooks: vi.fn(async () => []),
}));

vi.mock("@msout/microsoft-webauth", () => ({
  login: vi.fn(async () => true),
  LOGIN_REASONS: ["unknown"],
  answerChallenge: vi.fn(() => true),
}));

vi.mock("@msout/microsoft-onenote-export-notebook", () => ({
  runExport: vi.fn(),
}));

// `rm` and nothing else. The wipe is the one call this file needs to be able to
// fail, and replacing the whole module would take the artifacts route's `mkdir`
// and `stat` down with it — the failure would then be indistinguishable from the
// route being broken.
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return { ...actual, rm: vi.fn(actual.rm) };
});

import { buildApp } from "../src/index.js";
import { sessionPaths } from "../src/sessions.js";

const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const TOKEN = "t".repeat(43);

/**
 * Two artifact ids, 43 base64url characters each, as the route requires.
 *
 * Different per export on purpose: the second archive must be a *new* zip, not the
 * first one left where it was. A test that reused an id would pass against a
 * runner that never wrote a second archive at all.
 */
const ARTIFACT_1 = "A".repeat(43);
const ARTIFACT_2 = "B".repeat(43);

/**
 * What each notebook writes, as `out/<notebook>/<page>`.
 *
 * Transcribed from the package's own layout rather than invented: `exporter.js:1539`
 * resolves `outputBase = path.resolve(baseDir, safeName(notebookName))`, and
 * `baseDir` is the `exportDir` the runner passes. A mock that wrote a different
 * shape would let a real regression through — the accumulation is precisely that
 * one notebook's directory sitting beside another's.
 */
const VAULT: Record<string, ReadonlyArray<readonly [string, string]>> = {
  "Notebook A": [
    ["Notebook A/page-1.md", "# page one"],
    ["Notebook A/page-2.md", "# page two"],
  ],
  "Notebook B": [["Notebook B/page-1.md", "# page one"]],
};

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
let artifactRoot: string;
let outDir: string;
let app: ReturnType<typeof buildApp> | null = null;
let address = "";

/** What `out/` held each time `runExport` was called. Empty means the wipe landed. */
let outDirSeenByExport: string[][] = [];

beforeEach(() => {
  vi.mocked(runExport).mockReset();
  // `mockClear` and not `mockReset`: the reset would also drop the pass-through
  // to the real `rm` installed by the mock factory, and every later test would be
  // asserting against a no-op.
  vi.mocked(rm).mockClear();

  dataRoot = mkdtempSync(join(tmpdir(), "runner-export-fresh-"));
  artifactRoot = mkdtempSync(join(tmpdir(), "runner-export-fresh-artifacts-"));
  const paths = sessionPaths(dataRoot, GUID);
  if (paths === null) throw new Error("the test guid was rejected by sessionPaths");
  outDir = paths.outDir;
  mkdirSync(paths.dir, { recursive: true });
  // The export route refuses without an auth file, so one has to exist.
  writeFileSync(paths.authFile, "{}");

  outDirSeenByExport = [];
  app = null;
  address = "";
});

afterEach(async () => {
  if (app !== null) await app.close();
  app = null;
  rmSync(dataRoot, { recursive: true, force: true });
  rmSync(artifactRoot, { recursive: true, force: true });
});

async function listen(): Promise<string> {
  app = buildApp({
    dataRoot,
    artifactRoot,
    port: 0,
    host: "127.0.0.1",
    token: TOKEN,
    credentialBodyLimit: 4096,
    ringSize: 256,
  } as never);
  return app.listen({ port: 0, host: "127.0.0.1" });
}

function post(url: string, body: unknown) {
  return fetch(`${address}${url}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-runner-token": TOKEN,
    },
    body: JSON.stringify(body),
  });
}

/**
 * Starts an export and waits for its terminal.
 *
 * Waiting on the terminal rather than on a sleep, because the export is detached:
 * the route answers 202 and the work continues afterwards. The terminal is also
 * what proves the slot was released — `claimed.release()` runs in the same
 * synchronous stretch as the publish, so once this has seen it the next export
 * cannot lose a race to the 409.
 */
async function exportNotebook(id: string, notebook: string): Promise<void> {
  const response = await post(`/sessions/${GUID}/exports`, { id, notebook });
  if (response.status !== 202) {
    throw new Error(`export route answered ${response.status}: ${await response.text()}`);
  }
  await waitForTerminal(id);
}

function parseFrames(text: string): Array<Record<string, unknown>> {
  const frames: Array<Record<string, unknown>> = [];
  for (const frame of text.split("\n\n")) {
    if (frame.trim() === "" || frame.startsWith(":")) continue;
    for (const line of frame.split("\n")) {
      // The type is inside the `data:` JSON: this wire format has no `event:` line.
      if (!line.startsWith("data: ")) continue;
      try {
        frames.push(JSON.parse(line.slice("data: ".length)) as Record<string, unknown>);
      } catch {
        // A frame cut in half by the reader. The next poll replays it from the
        // ring anyway, so dropping it here loses nothing.
      }
    }
  }
  return frames;
}

/**
 * The one terminal for `id`, or throws.
 *
 * Polls `/events` rather than holding a stream open, because `since=0` replays
 * the whole ring: a frame published while the previous poll was being torn down
 * cannot be missed, which a single long-lived connection would have to get right.
 */
async function waitForTerminal(id: string, timeoutMs = 5_000): Promise<Record<string, unknown>> {
  const isTerminalFor = (f: Record<string, unknown>): boolean =>
    (f.type === "export-done" || f.type === "export-partial") && f.id === id;

  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const controller = new AbortController();
    const seen: Array<Record<string, unknown>> = [];
    try {
      const response = await fetch(`${address}/events?guid=${GUID}&since=0`, {
        signal: controller.signal,
        headers: { "x-runner-token": TOKEN },
      });
      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      const pollUntil = Date.now() + 400;
      let text = "";
      while (Date.now() < pollUntil) {
        const { value, done } = await reader.read();
        if (done) break;
        text += decoder.decode(value, { stream: true });
        seen.push(...parseFrames(text));
        if (seen.some(isTerminalFor)) break;
      }
    } catch {
      // An abort is the normal way out of a stream that never ends.
    } finally {
      controller.abort();
    }

    const found = seen.find(isTerminalFor);
    if (found !== undefined) return found;
    if (Date.now() >= deadline) {
      throw new Error(`no terminal for ${id} within ${timeoutMs}ms; saw ${JSON.stringify(seen)}`);
    }
    await new Promise((r) => setTimeout(r, 25));
  }
}

/** Stages the archive, through the real route, and returns its entry list. */
async function stageArchive(artifactId: string): Promise<string[]> {
  const response = await post(`/sessions/${GUID}/artifacts`, { artifactId });
  if (response.status !== 201) {
    throw new Error(`artifacts route answered ${response.status}: ${await response.text()}`);
  }
  const zipPath = join(artifactRoot, ".staging", artifactId, "vault.zip");
  expect(existsSync(zipPath), "the route reported a staged archive that is not there").toBe(true);
  return zipEntryNames(zipPath);
}

/**
 * Every entry name in a zip, hand-read from the End Of Central Directory.
 *
 * ## The two records, and nothing else is needed
 *
 * EOCD (22 bytes, plus an optional comment of up to 65535) carries the total
 * entry count and the offset of the central directory. Each central directory
 * header carries its own name length, so the directory is a forward walk. That is
 * the entire index — no decompression, no local headers, no data descriptors.
 *
 * Read-only on purpose. A helper that can write into the archive under test is a
 * helper that can corrupt it and still pass.
 */
function zipEntryNames(zipPath: string): string[] {
  const EOCD_SIG = 0x06054b50;
  const CENTRAL_SIG = 0x02014b50;
  const EOCD_MIN = 22;
  const MAX_COMMENT = 0xffff;
  // name at 46; name/extra/comment lengths at 28/30/32.
  const CD_NAME_AT = 46;

  const buf = readFileSync(zipPath);
  if (buf.length < EOCD_MIN) throw new Error("too short to be a zip");

  // Walk back from the end. Scanned rather than assumed-at-the-end because a zip
  // may carry an archive comment, and the comment may itself contain the bytes of
  // the signature — so the *last* match wins, not the first one found.
  let eocd = -1;
  const scanFrom = Math.max(0, buf.length - EOCD_MIN - MAX_COMMENT);
  for (let i = buf.length - EOCD_MIN; i >= scanFrom; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("no end-of-central-directory record: not a zip");

  const total = buf.readUInt16LE(eocd + 10);
  const at = buf.readUInt32LE(eocd + 16);

  const names: string[] = [];
  let offset = at;
  for (let i = 0; i < total; i++) {
    if (offset + CD_NAME_AT > buf.length || buf.readUInt32LE(offset) !== CENTRAL_SIG) {
      throw new Error(`central directory entry ${i} of ${total} is not a header`);
    }
    const nameLen = buf.readUInt16LE(offset + 28);
    const extraLen = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    names.push(buf.subarray(offset + CD_NAME_AT, offset + CD_NAME_AT + nameLen).toString("utf8"));
    offset += CD_NAME_AT + nameLen + extraLen + commentLen;
  }
  return names;
}

/** Files (not folder entries), which is what the assertion is about. */
function filesIn(names: readonly string[]): string[] {
  return names.filter((n) => !n.endsWith("/"));
}

describe("out/ starts empty for every export", () => {
  it("the second export's archive holds only the second notebook's pages", async () => {
    // **The claim: the archive, read back out of vault.zip.** Not `out/`. What a
    // user downloads is the zip, and a bug between the directory and the archive
    // is a bug a user hits.
    vi.mocked(runExport).mockImplementation(async (options: Record<string, unknown>) => {
      const exportDir = options.exportDir as string;
      const notebook = String(options.notebook);
      const onEvent = options.onEvent as (e: Record<string, unknown>) => void;

      // What the wipe left behind at the moment the walk began. Recorded here so
      // the ordering claim is checked at the only place it can be.
      outDirSeenByExport.push(readdirSync(exportDir));

      for (const [relative, body] of VAULT[notebook] ?? []) {
        const target = join(exportDir, relative);
        mkdirSync(join(target, ".."), { recursive: true });
        writeFileSync(target, body);
      }
      onEvent({ type: "export-done", id: options.id, notebook, pages: 2, sections: 1, assets: 0 });
      return packageStats({ totalPages: 2, totalSections: 1 });
    });

    address = await listen();

    // Run 1 — and its archive is read, so that the assertion on run 2 cannot pass
    // by both archives being empty.
    await exportNotebook("run-1", "Notebook A");
    const first = filesIn(await stageArchive(ARTIFACT_1));
    expect(first).toEqual(["Notebook A/page-1.md", "Notebook A/page-2.md"]);

    // Run 2, same session, same `out/`.
    await exportNotebook("run-2", "Notebook B");
    const second = filesIn(await stageArchive(ARTIFACT_2));

    expect(second).toEqual(["Notebook B/page-1.md"]);
    // Stated separately as well: the claim is that A's pages are *absent*, and
    // `toEqual` above would already say so — but this is the sentence the bug is
    // made of, and it reads as itself.
    expect(second.join("\n")).not.toContain("Notebook A");
    // ...and the filesystem claim underneath it, which is where the defect lives.
    expect(readdirSync(outDir)).toEqual(["Notebook B"]);
  });

  it("clears out/ before the walk, not after — so a stale vault is never walkable", async () => {
    // The same notebook exported twice, which is the case that ships **deleted**
    // pages: the second archive looks current and carries pages that were removed
    // from OneNote in between, and the counts on the terminal come from this run
    // so nothing on screen contradicts them.
    vi.mocked(runExport).mockImplementation(async (options: Record<string, unknown>) => {
      const exportDir = options.exportDir as string;
      const onEvent = options.onEvent as (e: Record<string, unknown>) => void;

      // Everything the walk could have found still there, recorded at the moment
      // the walk began. This is the ordering claim, not a later observation of it.
      outDirSeenByExport.push(readdirSync(exportDir, { recursive: true }));

      const target = join(exportDir, "Notebook A", "page-1.md");
      mkdirSync(join(target, ".."), { recursive: true });
      writeFileSync(target, "# the only page left");
      onEvent({ type: "export-done", id: options.id, notebook: "Notebook A", pages: 1, sections: 1, assets: 0 });
      return packageStats({ totalPages: 1, totalSections: 1 });
    });

    address = await listen();

    // What an earlier run of the same notebook left behind: a page the user has
    // since deleted in OneNote, still sitting in `out/`.
    mkdirSync(join(outDir, "Notebook A", "deleted-page"), { recursive: true });
    writeFileSync(join(outDir, "Notebook A", "deleted-page", "gone.md"), "# removed in OneNote");

    await exportNotebook("run-1", "Notebook A");
    const first = filesIn(await stageArchive(ARTIFACT_1));
    expect(first.join("\n")).not.toContain("gone.md");

    await exportNotebook("run-2", "Notebook A");
    const second = filesIn(await stageArchive(ARTIFACT_2));

    // Recorded by the mock at the moment `runExport` was called, twice: the wipe
    // had already landed both times, including on the run that inherited the
    // deleted page.
    expect(outDirSeenByExport).toEqual([[], []]);
    expect(second).toEqual(["Notebook A/page-1.md"]);
    expect(second.join("\n")).not.toContain("gone.md");
  });

  it("a wipe that fails publishes its own terminal, not the walk-failed one", async () => {
    // A permission error or a busy mount. The export does not run, and the
    // previous vault is still on disk — a state the api's `WALK_FAILED` ("the
    // export stopped unexpectedly partway through") describes badly, because
    // nothing stopped partway and nothing was lost.
    vi.mocked(runExport).mockImplementation(async (options: Record<string, unknown>) => {
      const onEvent = options.onEvent as (e: Record<string, unknown>) => void;
      onEvent({ type: "export-done", id: options.id, notebook: "Notebook A", pages: 1, sections: 1, assets: 0 });
      return packageStats({ totalPages: 1, totalSections: 1 });
    });
    vi.mocked(rm).mockRejectedValueOnce(new Error("EACCES: permission denied, unlink 'out'"));

    address = await listen();

    const previous = join(outDir, "Notebook A", "page-1.md");
    mkdirSync(join(outDir, "Notebook A"), { recursive: true });
    writeFileSync(previous, "# the earlier export, still here");

    const response = await post(`/sessions/${GUID}/exports`, { id: "run-1", notebook: "Notebook A" });
    expect(response.status).toBe(202);

    const terminal = await waitForTerminal("run-1");

    // No walk ran. Asserted first because it is the fact that makes the rest of
    // the terminal true: a walk that ran would carry counts.
    expect(runExport).not.toHaveBeenCalled();
    expect(terminal.pages).toBe(0);

    // Its own classification, and its own words.
    expect(terminal.failure).toBe("export_dir_unprepared");
    expect(terminal.message).toBe(
      "the export directory could not be prepared, so nothing was exported.",
    );
    // The distinction the whole terminal exists to draw. `walkFailed` alone is
    // one bit meaning "no usable vault", and it covers both cases.
    expect(terminal.message).not.toContain("partway");
    expect(terminal.message).not.toContain("stopped");

    // Nothing was deleted by accident, which is the other half of what the user
    // has to be told: the wipe failed, so the old vault is intact and a retry is
    // safe.
    expect(readFileSync(previous, "utf8")).toContain("the earlier export");

    // `walkFailed` stays true deliberately, and this says why: it is the one bit
    // the api reads to skip staging. With it false and all counts zero, the api
    // classifies the export as **done** and publishes whatever survived the failed
    // wipe as this export's vault. The distinct part of this terminal is
    // `failure`, not the clearing of `walkFailed`.
    expect(terminal.walkFailed).toBe(true);
  });

  it("a wipe that fails still releases the job slot", async () => {
    // The failure path returns out of the IIFE's `try`, so the `finally` has to
    // run: a leaked slot with `RestartPolicy: "no"` means every later export on
    // this container answers 409 for the rest of the session.
    vi.mocked(runExport).mockImplementation(async (options: Record<string, unknown>) => {
      const onEvent = options.onEvent as (e: Record<string, unknown>) => void;
      onEvent({ type: "export-done", id: options.id, notebook: "Notebook A", pages: 1, sections: 1, assets: 0 });
      return packageStats({ totalPages: 1, totalSections: 1 });
    });

    address = await listen();
    vi.mocked(rm).mockRejectedValueOnce(new Error("EACCES: permission denied, unlink 'out'"));

    await exportNotebook("run-1", "Notebook A");

    // The second attempt gets the slot, so it is refused by the wipe rather than
    // by a 409 naming a job that finished.
    const second = await post(`/sessions/${GUID}/exports`, { id: "run-2", notebook: "Notebook A" });
    expect(second.status).toBe(202);
    await waitForTerminal("run-2");
  });

  it("clears out/ on the first export too, so a re-run of one session starts clean", async () => {
    // The `existsSync(outDir)` guard on the artifacts route is satisfied by
    // `makeSessionDirs`, so "the export already ran once" is not a thing this
    // process can observe from the directory alone — which is exactly why the
    // wipe is not conditional on anything the route can see.
    vi.mocked(runExport).mockImplementation(async (options: Record<string, unknown>) => {
      outDirSeenByExport.push(readdirSync(options.exportDir as string));
      const onEvent = options.onEvent as (e: Record<string, unknown>) => void;
      onEvent({ type: "export-done", id: options.id, notebook: "Notebook A", pages: 0, sections: 0, assets: 0 });
      return packageStats();
    });

    address = await listen();
    mkdirSync(join(outDir, "left-over-from-a-dead-container"), { recursive: true });

    await exportNotebook("run-1", "Notebook A");

    expect(outDirSeenByExport).toEqual([[]]);
  });
});