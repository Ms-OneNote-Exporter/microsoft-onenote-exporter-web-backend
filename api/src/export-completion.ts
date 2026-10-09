/**
 * What happens between "the runner exported a notebook" and "the user can download
 * it".
 *
 * ## The gap this module fills
 *
 * Every half of publishing already existed, in a different process, and nothing
 * connected them:
 *
 * | Step | Owner | Status before this |
 * |---|---|---|
 * | export the vault | `runner`, via `runExport` | worked |
 * | stream it to `<ArtifactRoot>/.staging/<id>/` | `runner`, `POST /sessions/:guid/artifacts` | **route existed, no caller** |
 * | rename it into place | `orchestrator`, `POST /finalize` | **route existed and was tested, no caller** |
 * | record the id so a download can be authorised | `api`, SQLite | **no writer at all** |
 *
 * So a runner could finish an export, stream a vault and announce `export-done`,
 * and the api would keep reporting `state: "running"`, `finishedAt: null` and
 * `artifact.available: false` — for ever, because those are read from a row
 * nothing wrote.
 *
 * This is the project's own pattern (§1 of the plan this repository sits beside)
 * with the seam moved one level out: the event arrived, the handler ran, the SSE
 * frame reached the browser, and the assertion that mattered was never made. The
 * test that shipped alongside it asserted **the event** and not **the row** — the
 * same gap as the two credential bugs this suite was rewritten to catch.
 *
 * ## Why the api drives this, and not the runner
 *
 * The runner cannot reach the orchestrator — it has no URL for it, no route to
 * `msout-control`, and by design holds only the egress and credential networks.
 * The orchestrator cannot ask the runner to zip anything. **The api is the only
 * component that can reach both**, and it is the only one that knows what the
 * export's outcome actually was, which is what `/finalize` trusts for labelling
 * and explicitly cannot verify.
 *
 * ## Why the order is stage → finalise → record
 *
 * `finalize` renames staging into place, so it must not run before the zip is
 * there (`409 nothing staged`), and the row must not claim an artifact before the
 * rename has happened — `artifact.available` is what the client turns into a
 * download link, and Caddy's authoriser matches on that id. Recording last means
 * a crash at any point leaves the session recoverable rather than advertising an
 * artifact that does not exist.
 */

import type { Db } from "./db.js";
import type { OrchestratorApi } from "./orchestrator-client.js";
import type { ExportFinishedInput } from "./runner-adapter-http.js";
import type { PublishArtifactInput, RunnerAdapter } from "./runner-adapter.js";

/**
 * The slice of the api's logger this module uses.
 *
 * Structural, and with the project's own argument order — `(msg, fields)` rather
 * than pino's `(obj, msg)` — so the real `BootLog` satisfies it and a test double
 * is three lines. Naming it here rather than importing the server's logger type
 * keeps this module independent of how the server is built.
 */
export interface CompletionLog {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

/** What the three steps need. Injected so each can be faked independently. */
export interface ExportCompletionDeps {
  readonly runner: Pick<RunnerAdapter, "publishArtifact">;
  readonly orchestrator: Pick<OrchestratorApi, "finalize">;
  readonly db: Pick<Db, "completeExport" | "markExportUnpublishable">;
  readonly log: CompletionLog;
  /** Clock, injected so `finishedAt` is deterministic in tests. */
  readonly now?: () => number;
}

/**
 * UNPUBLISHABLE is the message a user sees when the export worked and the
 * download did not.
 *
 * It names the distinction rather than reporting "export failed", because the two
 * call for opposite responses: a failed export means run it again, and an
 * unpublishable one means **do not** — the notes are already on the runner's disk
 * and re-running the walk costs the user the time they already spent.
 */
export const UNPUBLISHABLE =
  "The export finished, but the file could not be prepared for download. " +
  "Nothing was lost — there is no need to export again.";

/**
 * completeExport publishes a finished export's vault and records the result.
 *
 * Never throws. It is called from the event pump, where a rejection would tear
 * down the stream and lose every later event for the session, and a failure here
 * has already been reduced to something the user can act on.
 */
export async function completeExport(
  deps: ExportCompletionDeps,
  input: ExportFinishedInput,
): Promise<void> {
  const now = deps.now ?? Date.now;

  // ---- 1. stage: the runner zips the vault into the artifact staging directory.
  try {
    await deps.runner.publishArtifact({
      sessionId: input.sessionId,
      artifactId: input.artifactId,
    } satisfies PublishArtifactInput);
  } catch (cause) {
    return unpublishable(deps, input, "archiving", cause);
  }

  // ---- 2. finalise: the orchestrator renames staging into place.
  //
  // `partial` is forwarded from what the runner reported and never re-derived.
  // The orchestrator selects the `.partial.zip` name and writes the marker from
  // this bit, and its own comment says it cannot verify it — it never saw the walk.
  const finalised = await deps.orchestrator.finalize({
    artifactId: input.artifactId,
    sessionGuid: input.sessionId,
    partial: input.partial,
  });
  if (!finalised.ok) {
    // A 409 means nothing was staged: the runner wrote no archive, so this export
    // genuinely has nothing to download. Retrying would not change that, which is
    // why it is recorded rather than re-attempted.
    return unpublishable(deps, input, "publishing", finalised.error);
  }

  // ---- 3. record: the id, the terminal state, and the return to `authenticated`.
  const recorded = deps.db.completeExport({
    guid: input.sessionId,
    artifactId: input.artifactId,
    partial: input.partial,
    partialReason: input.partialReason,
    notebook: input.notebook,
    progress: input.progress,
    startedAt: input.finishedAt,
    finishedAt: input.finishedAt,
  });

  if (recorded) {
    deps.log.info("export published", {
      session: input.sessionId,
      artifactId: input.artifactId,
      partial: input.partial,
      bytes: finalised.value.bytes,
      archiveName: finalised.value.archiveName,
    });
  } else {
    // The row is gone — erased, or expired between the event and here. Expected for
    // a late event, and not an error, but logged at `warn` because it is also what
    // a genuine bug looks like and the two are indistinguishable from here. The same
    // reasoning as `onAuthOutcome`.
    deps.log.warn("export finished for a session with no row", {
      session: input.sessionId,
      artifactId: input.artifactId,
    });
  }
}

/**
 * unpublishable records the "walked fine, cannot download" outcome.
 *
 * `stage` is named in the log rather than swallowed: "archiving" and "publishing"
 * are different failures with different causes — a full disk inside the runner
 * versus a refused rename in the orchestrator — and an operator reading only
 * "could not publish" has been told nothing actionable.
 */
function unpublishable(
  deps: ExportCompletionDeps,
  input: ExportFinishedInput,
  stage: "archiving" | "publishing",
  cause: unknown,
): void {
  const detail = cause instanceof Error ? cause.message : JSON.stringify(cause);
  deps.log.error("export finished but could not be published", {
    session: input.sessionId,
    artifactId: input.artifactId,
    stage,
    err: cause,
  });
  deps.db.markExportUnpublishable({
    guid: input.sessionId,
    error: UNPUBLISHABLE,
    artifactId: input.artifactId,
    notebook: input.notebook,
    partialReason: input.partialReason,
    finishedAt: input.finishedAt,
  });
  // `detail` is for the log only. The user gets `UNPUBLISHABLE`, which contains no
  // path and no host detail — the same rule as every other error crossing to a
  // browser in this api.
  void detail;
}