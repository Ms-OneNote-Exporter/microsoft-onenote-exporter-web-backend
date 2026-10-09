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
 * NOTEBOOK_NOT_FOUND is the message a user sees when the notebook had no
 * sections at all — so nothing could be walked.
 *
 * `exporter.js` sets `notebookNotFound` for a *genuinely empty* notebook and for
 * one that never loaded, because both produce the same empty list and the
 * package's judgement is that *"neither is a success"*. So this message must not
 * claim the notebook is missing: for a user with an empty notebook that would be
 * a lie, and it would be a lie about work that was never attempted.
 *
 * It is also **not** UNPUBLISHABLE's text. That one says *"Nothing was lost —
 * there is no need to export again"*, which the frontend then follows with
 * *"Nothing was completed, so you can start again."* The two contradict each
 * other on the same line, which is why the classification has its own message.
 *
 * Written to read as the middle of a sentence: the frontend wraps it as
 * `The export failed: ${error} Nothing was completed, so you can start again.`
 * So it states no outcome of its own and offers no advice of its own.
 */
export const NOTEBOOK_NOT_FOUND =
  "this notebook has no sections, so there was nothing to walk — " +
  "it may be empty, or OneNote may not have loaded it.";

/**
 * LOST_ALL_PAGES is the message when the walk ran but wrote no pages at all.
 *
 * Distinct from NOTEBOOK_NOT_FOUND because work *was* attempted and failed —
 * sections were found and could not be exported — which is a different problem
 * with a different remedy from a notebook that was never there.
 */
export const LOST_ALL_PAGES =
  "every section failed to export, so no pages were written.";

/**
 * WALK_FAILED is the message when the runner's export threw before any outcome.
 *
 * Says nothing about *why*. The cause is in the log (`err`), never here: a stack,
 * a module path, or "Chromium missing" is our internals and tells the user
 * nothing they can act on. It also does not claim nothing was lost, because we
 * cannot know that — the walk threw partway, and the vault may hold pages it had
 * already written.
 */
export const WALK_FAILED = "the export stopped unexpectedly partway through.";

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

  // ---- Classification: decide whether to stage, finalise, and record
  //
  // The order matters. Walk failure is checked first because it's a third,
  // distinct failure mode (not notebookNotFound and not loss counts).
  //
  // - walkFailed → failed, no artifact staged (throw in runExport)
  // - notebookNotFound → failed, no artifact staged (empty notebook)
  // - lost > 0 && pages === 0 → failed, no artifact staged (all pages failed)
  // - lost > 0 && pages > 0 → partial, artifact staged and labelled
  // - otherwise → done, artifact staged
  //
  // On `failed`, we skip staging entirely — no empty vault.zip is written.
  const lost = input.failedSections + input.failedPages + input.failedGroups;

  // walkFailed means runExport threw; the notebook was not the problem.
  if (input.walkFailed === true) {
    return unpublishableWalkFailed(deps, input, "the runner threw while exporting");
  }

  if (input.notebookNotFound === true) {
    return unpublishableNotebookNotFound(deps, input, "notebook not found");
  }

  if (lost > 0 && input.progress?.pages === 0) {
    return unpublishableLostAllPages(deps, input, "the walk wrote nothing; every page and section failed");
  }

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

/**
 * unpublishableNotebookNotFound records a failure where the notebook had no
 * sections — either genuinely empty or never loaded.
 *
 * This is a *failed* export with no artifact written at all. Unlike unpublishable
 * (which is for "walked but could not publish"), this is "nothing to publish
 * because the target didn't exist or had no content".
 *
 * The key distinction: UNPUBLISHABLE says "nothing was lost, don't re-export".
 * This says "the notebook was empty or missing, re-export won't help".
 */
function unpublishableNotebookNotFound(
  deps: ExportCompletionDeps,
  input: ExportFinishedInput,
  cause: string,
): void {
  deps.log.error("export failed because notebook was not found", {
    session: input.sessionId,
    artifactId: input.artifactId,
    err: cause,
  });
  deps.db.markExportUnpublishable({
    guid: input.sessionId,
    error: NOTEBOOK_NOT_FOUND,
    artifactId: input.artifactId,
    notebook: input.notebook,
    partialReason: input.partialReason,
    finishedAt: input.finishedAt,
  });
  // `cause` is for the log only. The user gets `NOTEBOOK_NOT_FOUND`, which contains
  // no path and no host detail.
  void cause;
}

/**
 * unpublishableWalkFailed records a failure where runExport threw an error.
 *
 * This is a *failed* export with no artifact written at all. The walk did not
 * even get to run due to a runtime error (Chromium missing, module import failed,
 * etc).
 *
 * The key distinction: this is NOT notebookNotFound (the notebook was fine),
 * and NOT "walk produced no pages" (no pages were attempted). This is "the
 * exporter itself threw".
 */
function unpublishableWalkFailed(
  deps: ExportCompletionDeps,
  input: ExportFinishedInput,
  cause: string,
): void {
  deps.log.error("export failed because the runner threw", {
    session: input.sessionId,
    artifactId: input.artifactId,
    err: cause,
  });
  deps.db.markExportUnpublishable({
    guid: input.sessionId,
    error: WALK_FAILED,
    artifactId: input.artifactId,
    notebook: input.notebook,
    partialReason: input.partialReason,
    finishedAt: input.finishedAt,
  });
  // `cause` is for the log only. The user gets a message that names the problem
  // but contains no path, no stack, and no host detail.
  void cause;
}

/**
 * unpublishableLostAllPages records a failure where the walk wrote no pages.
 *
 * This is a *failed* export with no artifact written at all. The walk ran, but
 * every page and section failed, so there is nothing to archive.
 *
 * The key distinction: UNPUBLISHABLE says "nothing was lost, don't re-export".
 * This says "the walk produced nothing; every page and section failed".
 */
function unpublishableLostAllPages(
  deps: ExportCompletionDeps,
  input: ExportFinishedInput,
  cause: string,
): void {
  deps.log.error("export failed because the walk produced no pages", {
    session: input.sessionId,
    artifactId: input.artifactId,
    err: cause,
  });
  deps.db.markExportUnpublishable({
    guid: input.sessionId,
    error: LOST_ALL_PAGES,
    artifactId: input.artifactId,
    notebook: input.notebook,
    partialReason: input.partialReason,
    finishedAt: input.finishedAt,
  });
  // `cause` is for the log only. See NOTEBOOK_NOT_FOUND for why this cannot be
  // UNPUBLISHABLE's text.
  void cause;
}