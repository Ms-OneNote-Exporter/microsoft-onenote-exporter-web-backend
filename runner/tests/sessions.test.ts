/**
 * The single job slot, and the paths a guid can reach.
 *
 * ## The two properties
 *
 * 1. **One job at a time.** The api's queue serialises already; this is the
 *    backstop. Two api instances pointed at one runner, or a retry that raced,
 *    must not end up with two browsers fighting over two sessions' worth of
 *    memory — and a refusal must say *what* is holding the slot, because "busy"
 *    with no explanation is indistinguishable from a hung service.
 *
 * 2. **A guid is the only thing that steers a write.** It reaches `path.join` to
 *    build a directory name, so anything that is not a guid could escape the data
 *    root. That is the one filesystem write an attacker reaching this HTTP API
 *    controls, so it is checked twice: by shape, and by containment.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import {
  sessionPaths,
  makeSessionDirs,
  removeSessionDirs,
  JobSlot,
  JobBusyError,
} from "../src/sessions.js";

const GUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const OTHER = "11111111-2222-3333-4444-555555555555";

describe("sessionPaths", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "runner-paths-"));
  });

  it("puts every path under the session directory", () => {
    const paths = sessionPaths(root, GUID);
    expect(paths).not.toBeNull();
    if (paths === null) return;
    for (const key of ["authFile", "outDir", "logsDir", "homeDir"] as const) {
      expect(paths[key].startsWith(paths.dir), key).toBe(true);
    }
  });

  it("resolves inside the data root", () => {
    const paths = sessionPaths(root, GUID);
    if (paths === null) throw new Error("expected paths");
    const resolvedRoot = resolve(root);
    for (const key of ["dir", "authFile", "outDir", "logsDir", "homeDir"] as const) {
      expect(paths[key].startsWith(resolvedRoot + sep), key).toBe(true);
    }
  });

  it("refuses a guid that is not one", () => {
    // Checked by shape *and* by containment, because they fail differently: the
    // regex rejects `..`, and the containment check is the second layer for
    // anything that slipped past it.
    for (const bad of [
      "../../etc/passwd",
      "..",
      ".",
      "not-a-guid",
      `${GUID}/../other`,
      `${GUID}/../../etc`,
      "",
      "  ",
      GUID.toUpperCase() + "/x",
      "00000000-0000-0000-0000-00000000000",
      GUID + "0",
    ]) {
      expect(sessionPaths(root, bad), bad).toBeNull();
    }
  });

  it("refuses a non-string", () => {
    for (const bad of [null, undefined, 42, {}, []]) {
      expect(sessionPaths(root, bad as never)).toBeNull();
    }
  });

  it("gives two sessions different directories", () => {
    const a = sessionPaths(root, GUID);
    const b = sessionPaths(root, OTHER);
    if (a === null || b === null) throw new Error("expected paths");
    expect(a.dir).not.toBe(b.dir);
    expect(a.authFile).not.toBe(b.authFile);
  });

  it("is stable: the same guid yields the same paths", () => {
    // The api reads the auth file path back after a restart; a path that changed
    // between calls would lose every session's saved state.
    expect(sessionPaths(root, GUID)).toEqual(sessionPaths(root, GUID));
  });
});

describe("makeSessionDirs", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "runner-dirs-"));
  });

  it("creates every directory it promises", () => {
    const paths = sessionPaths(root, GUID);
    if (paths === null) throw new Error("expected paths");
    makeSessionDirs(paths);
    for (const key of ["dir", "outDir", "logsDir", "homeDir"] as const) {
      expect(existsSync(paths[key]), key).toBe(true);
    }
  });

  it("is safe to call twice", () => {
    // A retry that raced would call it again, and `mkdirSync` throws on an
    // existing directory unless `recursive` is set — which it is, but the
    // property is worth holding rather than trusting.
    const paths = sessionPaths(root, GUID);
    if (paths === null) throw new Error("expected paths");
    expect(() => {
      makeSessionDirs(paths);
      makeSessionDirs(paths);
    }).not.toThrow();
  });

  it("removes everything it created", () => {
    const paths = sessionPaths(root, GUID);
    if (paths === null) throw new Error("expected paths");
    makeSessionDirs(paths);
    removeSessionDirs(paths);
    expect(existsSync(paths.dir)).toBe(false);
    // ...and only that. A sibling session's data must survive another session's
    // erase.
    const other = sessionPaths(root, OTHER);
    if (other === null) throw new Error("expected paths");
    makeSessionDirs(other);
    expect(existsSync(other.dir)).toBe(true);
    expect(existsSync(paths.dir)).toBe(false);
    rmSync(root, { recursive: true, force: true });
  });

  it("does not throw when the directory is already gone", () => {
    const paths = sessionPaths(root, GUID);
    if (paths === null) throw new Error("expected paths");
    // Erase is called on teardown, when the container may already have taken the
    // directory with it.
    expect(() => {
      removeSessionDirs(paths);
      removeSessionDirs(paths);
    }).not.toThrow();
  });

  it("creates directories owner-only", () => {
    // The session directory holds the auth file and any dump the packages wrote.
    // World-readable would put a live session in every process's reach.
    const paths = sessionPaths(root, GUID);
    if (paths === null) throw new Error("expected paths");
    mkdirSync(root, { recursive: true });
    makeSessionDirs(paths);
    const mode = require("node:fs").statSync(paths.dir).mode & 0o777;
    expect(mode & 0o077, `mode was ${mode.toString(8)}`).toBe(0);
    rmSync(root, { recursive: true, force: true });
  });
});

describe("JobSlot", () => {
  let slot: JobSlot;

  beforeEach(() => {
    slot = new JobSlot();
  });

  it("is free at first", () => {
    expect(slot.busy).toBe(false);
    expect(slot.describe()).toBeNull();
  });

  it("is busy once claimed, and free after release", () => {
    const claimed = slot.claim(GUID, "login");
    expect(slot.busy).toBe(true);
    claimed.release();
    expect(slot.busy).toBe(false);
  });

  it("names the job holding the slot when refusing a second", () => {
    // "busy" alone is indistinguishable from a hung service. The caller needs to
    // know which session and which kind is in the way.
    slot.claim(GUID, "export");
    try {
      slot.claim(OTHER, "login");
      throw new Error("expected a refusal");
    } catch (error) {
      expect(error).toBeInstanceOf(JobBusyError);
      const busy = error as JobBusyError;
      expect(busy.activeGuid).toBe(GUID);
      expect(busy.activeKind).toBe("export");
      expect(busy.message).toContain("export");
    }
  });

  it("refuses a second claim for the same session too", () => {
    // Two logins for one session is the retry-raced case, and running two
    // browsers for it would corrupt the auth file both are writing.
    slot.claim(GUID, "login");
    expect(() => slot.claim(GUID, "login")).toThrow(JobBusyError);
  });

  it("accepts a new claim once the first is released", () => {
    const first = slot.claim(GUID, "login");
    first.release();
    const second = slot.claim(OTHER, "list");
    expect(slot.describe()?.guid).toBe(OTHER);
    second.release();
  });

  it("ignores a double release, so a second caller cannot free someone else's slot", () => {
    // The token is what scopes a release to its own claim. Calling `release()`
    // twice must not free a claim that has since been made by someone else — which
    // is the bug a bare `this.current = null` would have.
    const first = slot.claim(GUID, "login");
    first.release();
    const second = slot.claim(OTHER, "list");
    first.release(); // stale
    expect(slot.busy, "the second job must still hold the slot").toBe(true);
    expect(slot.describe()?.guid).toBe(OTHER);
    second.release();
  });

  it("reports a job's start time as an ISO string", () => {
    slot.claim(GUID, "login");
    const since = slot.describe()!.since;
    expect(since).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(Number.isNaN(Date.parse(since))).toBe(false);
  });

  it("aborts only a job that carries a signal", () => {
    // Login and list are not abortable, and a caller's abort must not silently
    // do nothing to them.
    const login = slot.claim(GUID, "login");
    expect(slot.abortNow()).toBe(false);
    login.release();

    const controller = new AbortController();
    const exporting = slot.claim(GUID, "export", controller);
    expect(slot.abortNow()).toBe(true);
    expect(controller.signal.aborted).toBe(true);
    exporting.release();
  });

  it("survives a double abort", () => {
    // A caller may retry an abort whose response was lost. Throwing here would
    // turn a retry into an error the caller has to interpret.
    const controller = new AbortController();
    slot.claim(GUID, "export", controller);
    expect(slot.abortNow()).toBe(true);
    expect(() => slot.abortNow()).not.toThrow();
    expect(controller.signal.aborted).toBe(true);
  });

  it("reports nothing to abort when the slot is free", () => {
    expect(slot.abortNow()).toBe(false);
  });
});
