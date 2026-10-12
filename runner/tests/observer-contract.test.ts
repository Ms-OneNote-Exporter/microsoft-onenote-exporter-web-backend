/**
 * The listing's log lines are the *installed package's* vocabulary, not this
 * repository's.
 *
 * ## Why this file exists and is not in `notebooks-list.test.ts`
 *
 * `@msout/microsoft-onenote-list-notebooks` 0.0.8 taps its own logger and emits
 * `listing-log {line, level}` through an `onEvent` callback. Before that version
 * it emitted nothing at all: a listing that takes thirty seconds produces silence
 * on this side of the seam for the whole of those thirty seconds, and a user
 * cannot tell that apart from a hung listing.
 *
 * **The assertion that matters is against the package on disk**, because the
 * failure it exists to catch is a *version* failure. `runner/Dockerfile` asserts
 * the dependency **set** by name — `@msout/microsoft-onenote-list-notebooks` is
 * there, at whatever version the lockfile says — so an image built from a lockfile
 * that still said 0.0.7 passes that check, ships, and then emits nothing. The
 * `listing-log` name is the first thing in this repo that can tell 0.0.7 from
 * 0.0.8, so it is read from the installed package and nowhere else.
 *
 * That is also why the import here is `require` through `createRequire` rather
 * than `import`. It is the installed CommonJS, resolved through the package's own
 * `exports` map, with no transform in between. And this file contains **no**
 * `vi.mock` of the package, deliberately: `notebooks-list.test.ts` mocks it, and a
 * mock in this file would make the one assertion this repository has about the
 * real thing assert about the fake instead. Verified by mutation — with the
 * dependency back at 0.0.7 the first test below is red, and it is red because
 * `require` throws, not because a fixture was changed.
 *
 * ## What is and is not driven here
 *
 * What is driven: the installed package's own vocabulary, and this runner's own
 * pipeline from a `listing-log` event to the bytes on the wire.
 *
 * What is not: a real listing. `listNotebooks()` launches Chromium and would make
 * this file slow, flaky and dependent on a Microsoft origin, which is what
 * `notebooks-list.test.ts` and `export-terminal.test.ts` mock for. So the wiring
 * at the call site — that the listing's `onEvent` reaches `hub.publish` — is read
 * from the source rather than executed. That is the same trade `contract.test.ts`
 * makes and the reason for it is the same: a listing cannot be faked into being
 * evidence about a package, and a source read is honest about what it is.
 */
import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { EventHub, formatSse, type RunnerEvent } from "../src/events.js";

const require_ = createRequire(import.meta.url);

const PKG = "@msout/microsoft-onenote-list-notebooks";
const GUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const SRC = join(import.meta.dirname, "..", "src");

/** The version actually installed, quoted only in a failure message. */
const installedVersion = (): string => {
  try {
    return (require_(`${PKG}/package.json`) as { version: string }).version;
  } catch {
    return "unknown";
  }
};

/**
 * The installed package's observer module.
 *
 * A failure here is reported as a version failure on purpose. The bare
 * `ERR_PACKAGE_PATH_NOT_EXPORTED` that 0.0.7 raises names a path and not a
 * cause, and the cause is always the same: nothing was bumped.
 */
const observer = (): { LIST_EVENT_TYPES: readonly string[] } => {
  try {
    return require_(`${PKG}/observer`) as { LIST_EVENT_TYPES: readonly string[] };
  } catch (cause) {
    throw new Error(
      `the installed ${PKG}@${installedVersion()} has no ./observer subpath, so it cannot ` +
        `declare the listing vocabulary. The lockfile and node_modules have to be brought to ` +
        `0.0.8 or later: npm install ${PKG}@0.0.8` +
        `\n  (original failure: ${cause instanceof Error ? cause.message : String(cause)})`,
    );
  }
};

const read = (file: string): string => readFileSync(join(SRC, file), "utf8");

/**
 * The notebooks route as text.
 *
 * Sliced to the route so the assertion cannot be satisfied by the login or the
 * export, which already had `onEvent` before this change did.
 */
const listingRoute = (): string => {
  const index = read("index.ts");
  return index.slice(index.indexOf('app.post("/sessions/:guid/notebooks"'));
};

describe("the installed listing package declares the vocabulary the runner forwards", () => {
  it("lists listing-log among the events a listing can emit", () => {
    // The load-bearing assertion in this file, and the one the 0.0.7 mutation
    // turns red. If the package is old, `observer()` throws above and this never
    // runs.
    expect(observer().LIST_EVENT_TYPES).toContain("listing-log");
  });

  it("declares exactly one name, so a second vocabulary cannot appear unnoticed", () => {
    // One type, not a taxonomy: a listing has no counts and no determinable
    // totals, so there is nothing else honest for it to report. A package that
    // added a second name would be a change to the seam this repo types by hand,
    // and it should be a red build rather than a typecheck failure about a shape
    // nobody read.
    expect(observer().LIST_EVENT_TYPES).toEqual(["listing-log"]);
  });

  it("does not put the vocabulary on the main entry, which is why the import above is a subpath", () => {
    // Read rather than assumed. If a later version re-exported it from the main
    // entry, the subpath import would keep working and nothing would say so —
    // and the main entry is what `packages()` loads, so a name there would look
    // like the runner had picked it up.
    const main = require_(PKG) as Record<string, unknown>;
    expect(Object.keys(main).sort()).toEqual(["dismissMcasInterstitial", "listNotebooks"]);
  });
});

describe("the runner forwards that vocabulary", () => {
  it("has listing-log in its own event union, with the line and the level", () => {
    // `level` is the half a naive pass-through drops: without it a viewer cannot
    // tell "network idle timeout — continuing anyway" (WARN) from a routine INFO,
    // and it is not recoverable on the far side of the api.
    expect(read("events.ts")).toContain(
      '| { type: "listing-log"; line: string; level: string }',
    );
  });

  it("hands the listing's onEvent to the hub, at the listing route", () => {
    // Source, not execution, and the limitation is stated in the header: a real
    // listing cannot be driven here. What is checked is the thing a mock could
    // not prove anyway — that this route, and not the login route that already
    // had an `onEvent`, publishes what the package emitted under the same name.
    const route = listingRoute();
    expect(route).toContain("onEvent:");
    expect(route).toContain("hub.publish(guid, event)");
  });

  it("publishes the package's event without rebuilding it", () => {
    // `event` straight through, rather than a `{line, level}` re-listing. A
    // rebuild is a second place for the shape to be wrong, and the package's event
    // is already the runner's event — `ListEvent` and the `RunnerEvent` member are
    // the same three fields, which is what makes the direct publish typecheck.
    expect(listingRoute()).toMatch(/onEvent: \(event: ListEvent\) => hub\.publish\(guid, event\)/);
  });

  it("passes the listing no option it did not pass before", () => {
    // `no-dump-flags.test.ts` forbids `dodump` and `screenshot` in a package call;
    // this is the narrower, per-route half — a listing gained exactly one option,
    // and it is `onEvent`. `keepOpen` is the runner's own long-standing (inert)
    // argument and is left exactly as it was.
    const options = listingRoute().slice(
      listingRoute().indexOf("await listNotebooks({"),
      listingRoute().indexOf("});", listingRoute().indexOf("await listNotebooks({")),
    );
    const keys = [...options.matchAll(/^\s*([A-Za-z]\w*):/gm)].map((m) => m[1]);
    expect(keys).toEqual(["authFile", "keepOpen", "onEvent"]);
  });
});

describe("a listing-log line reaches the wire intact", () => {
  it("carries the type inside the payload, which is how the api reads it", () => {
    const hub = new EventHub(8);
    const seen: RunnerEvent[] = [];
    hub.subscribe(GUID, (entry) => seen.push(entry.event));

    hub.publish(GUID, { type: "listing-log", line: "Found 3 notebooks!", level: "info" });

    expect(seen).toEqual([
      { type: "listing-log", line: "Found 3 notebooks!", level: "info" },
    ]);

    // **Data only, no `event:` line.** The api's reader takes the type out of the
    // JSON — and a second vocabulary of SSE event names is precisely the thing
    // this project's first frontend invented and then silently dropped events
    // over. `listing-log` has to work the way `export-log` works or it does not
    // work at all.
    const frame = formatSse({ seq: 7, event: seen[0]! });
    expect(frame.startsWith("id: 7\ndata: ")).toBe(true);
    expect(frame).not.toContain("event: ");
    expect(JSON.parse(frame.slice("id: 7\ndata: ".length))).toEqual({
      type: "listing-log",
      line: "Found 3 notebooks!",
      level: "info",
    });
  });

  it("is not confused with the export's own log", () => {
    // Two names carrying the same idea, deliberately not merged. `export-log`
    // carries an artifact `id` and belongs to an export; a `listing-log` belongs
    // to the listing that is happening now and has no id at all. A client that
    // routed both to one log pane would show export lines under a listing that
    // never started one.
    const hub = new EventHub(8);
    const seen: RunnerEvent[] = [];
    hub.subscribe(GUID, (entry) => seen.push(entry.event));

    hub.publish(GUID, { type: "listing-log", line: "Connecting to OneNote...", level: "info" });
    hub.publish(GUID, { type: "export-log", id: "artifact-id", line: "exported page 1/29" });

    expect(seen.map((e) => e.type)).toEqual(["listing-log", "export-log"]);
  });
});