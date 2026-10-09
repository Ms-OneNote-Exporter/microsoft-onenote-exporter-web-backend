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

import { completeExport, UNPUBLISHABLE, type ExportCompletionDeps } from "../src/export-completion.js";
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