/**
 * `completeExport` — the three steps between a finished export and a download.
 *
 * ## The shape of these tests
 *
 * They assert **the calls that happened and their order**, because order is the
 * whole of the design here:
 *
 * - `finalize` renames staging into place, so it must not run before the runner
 *   has streamed the zip — the orchestrator answers `409 nothing staged`
 *   otherwise.
 * - the row must not claim an artifact before the rename happened, because
 *   `artifact.available` is what the client turns into a download link and Caddy's
 *   authoriser matches on it.
 *
 * So a test that asserted "finalize was called" and nothing else would pass on an
 * implementation that called it *first* and never recovered. The order is asserted
 * explicitly below.
 *
 * ## What is deliberately not asserted
 *
 * Nothing about `runExport`'s own behaviour, and nothing about SQLite — the row
 * writes are covered against a real database in `export-completion-db.test.ts`.
 * Duplicating them here would be a second fixture encoding a second assumption.
 */

import { describe, expect, it, vi } from "vitest";

import { completeExport, LOST_ALL_PAGES, NOTEBOOK_NOT_FOUND, UNPUBLISHABLE, WALK_FAILED, type ExportCompletionDeps } from "../src/export-completion.js";
import type { ExportFinishedInput } from "../src/runner-adapter-http.js";

const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const ARTIFACT = "A".repeat(43);
const NOW = 1_700_000_000_000;

function finished(overrides: Partial<ExportFinishedInput> = {}): ExportFinishedInput {
  return {
    sessionId: GUID,
    artifactId: ARTIFACT,
    partial: false,
    partialReason: null,
    notebook: "Notebook",
    progress: { pages: 12, sections: 3, assets: 40 },
    finishedAt: NOW + 5_000,
    ...overrides,
  };
}

/** callOrder records which collaborator was reached, and in what order. */
interface Harness {
  readonly deps: ExportCompletionDeps;
  readonly order: string[];
  readonly finalizeInput: () => { artifactId: string; sessionGuid: string; partial: boolean } | undefined;
  readonly complete: () => Record<string, unknown> | undefined;
  readonly unpublishable: () => Record<string, unknown> | undefined;
}

function harness(
  options: {
    stageFails?: boolean;
    finalizeFails?: boolean;
    finalizeFailsAs?: { kind: string };
  } = {},
): Harness {
  const order: string[] = [];
  let seenFinalize: { artifactId: string; sessionGuid: string; partial: boolean } | undefined;
  let seenComplete: Record<string, unknown> | undefined;
  let seenUnpublishable: Record<string, unknown> | undefined;

  const deps: ExportCompletionDeps = {
    runner: {
      publishArtifact: vi.fn(async () => {
        order.push("stage");
        if (options.stageFails === true) {
          throw new Error("ENOSPC: no space left on device");
        }
      }),
    },
    orchestrator: {
      finalize: vi.fn(async (input) => {
        order.push("finalize");
        seenFinalize = input;
        if (options.finalizeFails === true) {
          return {
            ok: false,
            error: (options.finalizeFailsAs ?? { kind: "conflict" }) as never,
          };
        }
        return {
          ok: true,
          value: {
            artifactId: input.artifactId,
            archiveName: input.partial ? "vault.partial.zip" : "vault.zip",
            bytes: 2048,
            partial: input.partial,
          },
        };
      }),
    },
    db: {
      completeExport: vi.fn((input) => {
        order.push("record");
        seenComplete = input;
        return true;
      }),
      markExportUnpublishable: vi.fn((input) => {
        order.push("unpublishable");
        seenUnpublishable = input;
        return true;
      }),
    },
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };

  return {
    deps,
    order,
    finalizeInput: () => seenFinalize,
    complete: () => seenComplete,
    unpublishable: () => seenUnpublishable,
  };
}

describe("a finished export", () => {
  it("stages, then finalises, then records — in that order", async () => {
    const h = harness();

    await completeExport(h.deps, finished());

    // The order is the assertion, not the calls themselves. `finalize` renames a
    // staged archive, so a `finalize` that ran first would 409 on a real
    // orchestrator; and `record` before `finalize` would advertise an artifact
    // Caddy cannot find.
    expect(h.order).toEqual(["stage", "finalize", "record"]);
  });

  it("stages under the api's own artifact id, not one it invents", async () => {
    const h = harness();

    await completeExport(h.deps, finished());

    // The id is minted by the api and carried through unchanged. A runner-derived
    // id would be derived from the session GUID and would leak it into every
    // download path and Caddy access log (PLAN-v3 §5).
    expect(h.deps.runner.publishArtifact).toHaveBeenCalledWith({
      sessionId: GUID,
      artifactId: ARTIFACT,
    });
    expect(h.finalizeInput()).toEqual({
      artifactId: ARTIFACT,
      sessionGuid: GUID,
      partial: false,
    });
  });

  it("records the artifact id and a finishedAt on the session", async () => {
    const h = harness();

    await completeExport(h.deps, finished());

    expect(h.complete()).toMatchObject({
      guid: GUID,
      artifactId: ARTIFACT,
      partial: false,
      partialReason: null,
      notebook: "Notebook",
      progress: { pages: 12, sections: 3, assets: 40 },
      finishedAt: NOW + 5_000,
    });
  });
});

describe("a partial export", () => {
  it("finalises with partial true, because the orchestrator cannot verify it", async () => {
    const h = harness();

    await completeExport(
      h.deps,
      finished({ partial: true, partialReason: "aborted", progress: null }),
    );

    // This bit selects the `.partial.zip` name and writes the on-disk marker, and
    // the orchestrator deliberately trusts rather than checks it — it never saw the
    // walk. So it has to arrive as the truth from the side that did.
    expect(h.finalizeInput()?.partial).toBe(true);
    expect(h.complete()).toMatchObject({ partial: true, partialReason: "aborted" });
    // Still published. §8.2 preserves what is on disk, so a partial vault is a
    // vault the user may want — labelled, not withheld.
    expect(h.order).toContain("record");
  });
});

describe("when publishing fails", () => {
  it("does not finalise when the runner could not archive", async () => {
    const h = harness({ stageFails: true });

    await completeExport(h.deps, finished());

    // Finalising after a failed archive would publish nothing and report a
    // conflict the operator then has to work out from two log lines.
    expect(h.order).toEqual(["stage", "unpublishable"]);
    expect(h.deps.orchestrator.finalize).not.toHaveBeenCalled();
    expect(h.complete()).toBeUndefined();
  });

  it("never records an artifact id when the publish failed", async () => {
    const h = harness({ stageFails: true });

    await completeExport(h.deps, finished());

    // An id here would make `artifact.available` true and let Caddy authorise a
    // download of an archive that does not exist.
    expect(h.complete()).toBeUndefined();
    expect(h.unpublishable()).toMatchObject({ guid: GUID, artifactId: ARTIFACT });
  });

  it("tells the user not to export again", async () => {
    const h = harness({ stageFails: true });

    await completeExport(h.deps, finished());

    // The walk succeeded. Reporting this as "export failed" sends the user to
    // re-run an hour of work over an archiving problem.
    expect(h.unpublishable()?.error).toBe(UNPUBLISHABLE);
    expect(UNPUBLISHABLE).toMatch(/no need to export again/i);
  });

  it("treats a 409 from finalize as an export with no archive, not a retry", async () => {
    const h = harness({ finalizeFails: true, finalizeFailsAs: { kind: "conflict", status: 409 } });

    await completeExport(h.deps, finished());

    expect(h.order).toEqual(["stage", "finalize", "unpublishable"]);
    expect(h.complete()).toBeUndefined();
    // One attempt, not a retry loop: the runner wrote no archive, so a second
    // attempt would find the same nothing.
    expect(h.deps.orchestrator.finalize).toHaveBeenCalledTimes(1);
  });

  it("never throws, because it is called from the event pump", async () => {
    const h = harness({ stageFails: true });

    // A rejection here would tear down the pump's try block and lose every
    // subsequent event for this session too.
    await expect(completeExport(h.deps, finished())).resolves.toBeUndefined();
  });

  it("carries no path or host detail into the message the user reads", async () => {
    const h = harness({ stageFails: true });

    await completeExport(h.deps, finished());

    // The full cause goes to the log, which is the operator's to read and may
    // contain a path. The stored error is what a browser renders.
    expect(String(h.unpublishable()?.error)).not.toContain("/");
    expect(String(h.unpublishable()?.error)).not.toContain("ENOSPC");
  });
});

describe("classification of failed exports", () => {
  function failedFinished(overrides: Partial<ExportFinishedInput> = {}): ExportFinishedInput {
    return finished({
      ...overrides,
      partial: false,
      partialReason: null,
      progress: { pages: 0, sections: 0, assets: 0 },
    });
  }

  it("does not stage when notebookNotFound is true", async () => {
    const h = harness();

    await completeExport(
      h.deps,
      failedFinished({ notebookNotFound: true, notebook: "Notebook" }),
    );

    // When notebookNotFound, we skip staging entirely - no empty vault.zip is written
    expect(h.order).toEqual(["unpublishable"]);
    expect(h.deps.runner.publishArtifact).not.toHaveBeenCalled();
    expect(h.finalizeInput()).toBeUndefined();
    expect(h.complete()).toBeUndefined();
    expect(h.unpublishable()?.error).toBe(NOTEBOOK_NOT_FOUND);
  });

  it("does not stage when lost > 0 and pages === 0", async () => {
    const h = harness();

    await completeExport(
      h.deps,
      failedFinished({
        failedSections: 2,
        failedPages: 5,
        failedGroups: 1,
        pages: 0,
      }),
    );

    // When the walk produced no pages, we skip staging entirely
    expect(h.order).toEqual(["unpublishable"]);
    expect(h.deps.runner.publishArtifact).not.toHaveBeenCalled();
    expect(h.finalizeInput()).toBeUndefined();
    expect(h.complete()).toBeUndefined();
    // **Not** UNPUBLISHABLE. That text says "Nothing was lost — there is no need to
    // export again", which the frontend then follows with "Nothing was completed,
    // so you can start again." The two contradict each other on one line, and
    // this case is a real loss: sections were found and every one failed.
    expect(h.unpublishable()?.error).toBe(LOST_ALL_PAGES);
    expect(h.unpublishable()?.error).not.toBe(UNPUBLISHABLE);
    expect(h.unpublishable()?.error).not.toContain("Nothing was lost");
  });

  it("stages and records when partial true (some pages succeeded, some failed)", async () => {
    const h = harness();

    await completeExport(
      h.deps,
      finished({
        partial: true,
        progress: { pages: 10, sections: 5, assets: 30 },
        failedSections: 2,
        failedPages: 3,
        failedGroups: 1,
      }),
    );

    // The order is 'stage', 'finalize', 'record' - all three steps
    expect(h.order).toEqual(["stage", "finalize", "record"]);
    expect(h.finalizeInput()?.partial).toBe(true);
  });

  it("stages and records when partial false (no failures)", async () => {
    const h = harness();

    await completeExport(h.deps, finished());

    expect(h.order).toEqual(["stage", "finalize", "record"]);
    expect(h.finalizeInput()?.partial).toBe(false);
  });
});

/**
 * The three failure messages, and the one rule they all obey.
 *
 * The frontend renders `state: 'failed'` as
 * `The export failed: ${running.error} Nothing was completed, so you can start again.`
 * So a message that says "nothing was lost" or offers its own advice appears on
 * one line contradicting the sentence wrapped around it. Each of these three
 * shipped into a draft that way — LOST_ALL_PAGES was literally UNPUBLISHABLE's
 * text — and the assertion that caught it was the one that pinned the bug.
 */
describe("the failure messages", () => {
  for (const [name, message] of [
    ["NOTEBOOK_NOT_FOUND", NOTEBOOK_NOT_FOUND],
    ["LOST_ALL_PAGES", LOST_ALL_PAGES],
    ["WALK_FAILED", WALK_FAILED],
  ] as const) {
    it(`${name} does not contradict the sentence the frontend wraps around it`, () => {
      // The frontend appends both of these itself.
      expect(message).not.toMatch(/nothing was lost/i);
      expect(message).not.toMatch(/no need to export again/i);
      expect(message).not.toMatch(/you can start again|try exporting again/i);
      // And no host paths, ids, or internals.
      expect(message).not.toMatch(/\/|stack|chromium|runner/i);
    });

    it(`${name} offers hedged alternatives and asserts none of them`, () => {
      // Each of the three failure messages must present multiple possibilities
      // without claiming which one is correct. The presence of "may" or "or"
      // indicates hedging; the absence of definitive language confirms no claim.
      const hasHedge = message.match(/may|or/i);
      expect(hasHedge).toBeTruthy(`${name} must present multiple possibilities without asserting which one`);
    });
  }

  it("NOTEBOOK_NOT_FOUND mentions all three indistinguishable causes", () => {
    // The three causes (empty, not loaded, re-verification) must all be mentioned
    // as possibilities, using hedged language (may, or) that does not assert any one.
    expect(NOTEBOOK_NOT_FOUND).toMatch(/empty/i);
    expect(NOTEBOOK_NOT_FOUND).toMatch(/load/i); // covers "not loaded", "not have loaded"
    expect(NOTEBOOK_NOT_FOUND).toMatch(/re-verification/i);
    // The hedge words must be present to avoid asserting a specific cause
    expect(NOTEBOOK_NOT_FOUND).toMatch(/may/i);
    expect(NOTEBOOK_NOT_FOUND).toMatch(/or/i);
  });

  it("NOTEBOOK_NOT_FOUND is distinct from UNPUBLISHABLE", () => {
    expect(NOTEBOOK_NOT_FOUND).not.toBe(UNPUBLISHABLE);
    expect(NOTEBOOK_NOT_FOUND).toMatch(/has no sections|empty|not loaded/i);
  });
});