/**
 * The runner published an empty notebook list, every time.
 *
 * ## What happened
 *
 * A listing on the deployed host:
 *
 *     runner  [SUCCESS] Found 3 notebooks!
 *     runner  [DEBUG]   Matched notebook links from the MRU feed: 3 entries.
 *     runner  [DEBUG]   3 of 3 notebooks resolved to a link.
 *     api     notebooks column: []
 *
 * The api persisted an empty list after a listing that had demonstrably found three.
 * Reproducible, which is what made it diagnosable — every earlier attempt at this was
 * "it worked once and I cannot see why it did not".
 *
 * ## Cause
 *
 * `@msout/microsoft-onenote-list-notebooks`'s `listNotebooks()` resolves to a **bare
 * array**:
 *
 *     return uniqueNotebooks;
 *
 * The runner read it as an object with a `notebooks` property:
 *
 *     const result = (await listNotebooks(...)) as { notebooks?: ReadonlyArray<...> };
 *     notebooks: (result.notebooks ?? []).map(...)
 *
 * `result.notebooks` on an array is `undefined`, so `?? []` produced an empty list. **The
 * names died on that line**, while the package's own log — a different component, holding
 * the real data — cheerfully reported three notebooks.
 *
 * The `as` cast is why it compiled. An array is not `{notebooks?}`; saying so with a cast
 * is a way of telling the compiler to stop looking.
 *
 * ## Why it survived
 *
 * **There was no test of this route's happy path.** The only `notebooks` tests in the
 * runner were about debug query parameters — that `?dodump=1` is refused. The path that
 * publishes the result was never exercised, so nothing could notice it returning nothing.
 *
 * And it was invisible from the outside for a second reason: the api published
 * `{notebooks: [...]}` while the client parsed `{state, items}`, so an empty array and a
 * correctly shaped one both rendered as nothing. Backend #38 made this visible; it did
 * not cause it.
 *
 * ## What the mock must be
 *
 * A **bare array**, because that is what the package returns. A mock returning
 * `{notebooks: [...]}` would pass against the broken code — the fixture would encode the
 * bug as the contract, which is the failure mode this project has produced repeatedly.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const GUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const TOKEN = "t".repeat(43);

/** Transcribed from `return uniqueNotebooks;` in the package. A **bare array**. */
const PACKAGE_NOTEBOOKS = [
  { name: "Work", url: "https://onenote.cloud.microsoft/notebooks/1" },
  { name: "Personal", url: "https://onenote.cloud.microsoft/notebooks/2" },
];

vi.mock("@msout/microsoft-onenote-list-notebooks", () => ({
  listNotebooks: vi.fn(async () => PACKAGE_NOTEBOOKS),
}));

vi.mock("@msout/microsoft-webauth", () => ({
  login: vi.fn(async () => true),
  LOGIN_REASONS: ["unknown"],
}));

vi.mock("@msout/microsoft-onenote-export-notebook", () => ({
  runExport: vi.fn(async () => ({})),
}));

import { buildApp } from "../src/index.js";
import { sessionPaths } from "../src/sessions.js";

let dataRoot: string;

beforeEach(() => {
  dataRoot = mkdtempSync(join(tmpdir(), "runner-notebooks-"));
  const paths = sessionPaths(dataRoot, GUID);
  if (paths === null) throw new Error("the test guid was rejected by sessionPaths");
  mkdirSync(paths.dir, { recursive: true });
  // The route refuses without an auth file, so one has to exist.
  writeFileSync(paths.authFile, "{}");
});

afterEach(() => {
  rmSync(dataRoot, { recursive: true, force: true });
});

/**
 * A live app, listening on an ephemeral port.
 *
 * `token`, not `runnerToken`: the config field is `token`, and an `as never` cast let the
 * wrong key through — every request answered 401 and the test failed on a missing event
 * rather than on the thing it exists to check.
 */
async function listening() {
  const app = buildApp({
    dataRoot,
    port: 0,
    host: "127.0.0.1",
    token: TOKEN,
    credentialBodyLimit: 4096,
    // The replay depth. Left out at first, and `new EventHub(undefined)` retained
    // nothing, so `/events` replayed an empty ring and the test reported "nothing
    // published" — while the route had published perfectly well.
    ringSize: 64,
  } as never);
  const address = await app.listen({ port: 0, host: "127.0.0.1" });
  return { app, address };
}

/**
 * The frames the hub holds for this session, read off the replay.
 *
 * `/events` is a stream that never ends, so `app.inject` would hang until the test timed
 * out — which is what the first two attempts did. Over a real socket the replay arrives
 * immediately and the request is aborted once the frames have been read.
 *
 * No production seam: `app.decorate("hub", hub)` would be easier and is the wrong thing,
 * because a test-only handle on production code is a seam the test then trusts instead of
 * the behaviour.
 */
async function framesFor(
  address: string,
): Promise<Array<{ type: string; data: Record<string, unknown> }>> {
  const controller = new AbortController();
  try {
    const response = await fetch(`${address}/events?guid=${GUID}&since=0`, {
      signal: controller.signal,
      // The token, because `/events` is behind the same `onRequest` guard as everything
      // but `/healthz`. Without it the reader consumes a 401 body, which contains no
      // `event:` lines, and the test reports "no frames published" — a failure that
      // names the wrong thing entirely.
      headers: { "x-runner-token": TOKEN },
    });
    if (!response.ok) throw new Error(`/events answered ${response.status}`);
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let text = "";
    const deadline = Date.now() + 2_000;
    while (Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
      if (text.includes("notebooks-listed") || text.includes("notebooks-failed")) break;
    }

    // **The type is inside the data JSON.** `formatSse` writes `id: <seq>` and
    // `data: {"type": ..., …}` with no `event:` line — the runner's wire format, which
    // is why the api's own reader takes the type out of the payload. A parser looking
    // for `event:` finds no frames at all and reports that nothing was published, which
    // is what the first three attempts of this file did.
    const out: Array<{ type: string; data: Record<string, unknown> }> = [];
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
      const type = typeof payload.type === "string" ? payload.type : "";
      if (type === "") continue;
      // The payload the caller wants, without the `type` it was keyed on.
      const { type: _type, ...rest } = payload;
      out.push({ type, data: rest as Record<string, unknown> });
    }
    return out;
  } finally {
    controller.abort();
  }
}

/** POST the route, let the background work land, and read what it published. */
async function listAndRead(): Promise<Array<{ type: string; data: Record<string, unknown> }>> {
  const { app, address } = await listening();
  try {
    const posted = await fetch(`${address}/sessions/${GUID}/notebooks`, {
      method: "POST",
      headers: { "x-runner-token": TOKEN },
    });
    expect(posted.status).toBe(202);

    // The route publishes from a detached async block, so the 202 lands first. One turn
    // of the macrotask queue is enough for an already-resolved mock; a fixed sleep would
    // be a way for this test to be slow and still pass.
    await new Promise((resolve) => setTimeout(resolve, 50));
    return await framesFor(address);
  } finally {
    await app.close();
  }
}

describe("POST /sessions/:guid/notebooks", () => {
  it("publishes the notebooks the package returned", async () => {
    // The bug, in one assertion: it published an empty array against a package that
    // returned two, while the package's own log said otherwise.
    const events = await listAndRead();
    const listed = events.find((e) => e.type === "notebooks-listed");

    expect(listed).toBeDefined();
    expect(listed?.data.notebooks).toEqual([
      { name: "Work", url: "https://onenote.cloud.microsoft/notebooks/1" },
      { name: "Personal", url: "https://onenote.cloud.microsoft/notebooks/2" },
    ]);
  });

  it("publishes every name, not just the first", async () => {
    // A bug that dropped all but one would look identical to success on a
    // one-notebook account, which is the common case.
    const events = await listAndRead();
    const listed = events.find((e) => e.type === "notebooks-listed");
    const notebooks = listed?.data.notebooks as Array<{ name: string }>;

    expect(notebooks).toHaveLength(2);
    expect(notebooks.map((n) => n.name)).toEqual(["Work", "Personal"]);
  });

  it("publishes an empty list when the account genuinely has none", async () => {
    // So the empty case stays covered: a fix that always published one entry would
    // otherwise pass both tests above.
    const { listNotebooks } = await import("@msout/microsoft-onenote-list-notebooks");
    vi.mocked(listNotebooks).mockResolvedValueOnce([]);

    const events = await listAndRead();
    const listed = events.find((e) => e.type === "notebooks-listed");

    // Present and empty — which is different from absent, and different from a shape the
    // reader cannot parse.
    expect(listed).toBeDefined();
    expect(listed?.data.notebooks).toEqual([]);
  });

  it("publishes a failure, and no list, when the package throws", async () => {
    const { listNotebooks } = await import("@msout/microsoft-onenote-list-notebooks");
    vi.mocked(listNotebooks).mockRejectedValueOnce(new Error("no egress"));

    const events = await listAndRead();

    expect(events.find((e) => e.type === "notebooks-failed")).toBeDefined();
    // No empty list alongside it, which would read as "this account has no notebooks"
    // rather than "the listing did not work" — the exact confusion this whole file is
    // about, one level up.
    expect(events.find((e) => e.type === "notebooks-listed")).toBeUndefined();
  });
});