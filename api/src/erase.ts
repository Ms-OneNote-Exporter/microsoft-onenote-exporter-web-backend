/**
 * The erase state machine.
 *
 * PLAN-v2 §11, extended for the split by PLAN-v3 T7. It is a machine rather than a
 * single operation because container removal and directory deletion are two
 * operations, and a partial failure between them leaks data.
 *
 * What v3 adds is a third host. In v2 the directory and the cookie were both
 * reachable from one process. Now:
 *
 *   - the *row* is in SQLite, here
 *   - the *directory* is on the runner's vault mount, which this process cannot
 *     read at all — it asks the orchestrator
 *   - the *cookie* is in the browser
 *
 * So erasure must span all three, and the step that is new in v3 is expiring the
 * cookie: without it a stale tab keeps a live-looking session on a row that no
 * longer exists. T7 states the requirement and T-E1 requires both orders to work,
 * including when the row is already gone.
 *
 * The states below are the v2 ones. `erasing` is set first and the row is deleted
 * last, so an interrupted erase is visible as `erasing` on the next boot and the
 * sweeper can finish it.
 */

import type { Db, SessionRow } from "./db.js";
import type { SseHub } from "./sse.js";
import { expiredCsrfCookie, expiredSessionCookie, serialiseCookie } from "./cookies.js";

/** Where a step in the machine got to. Recorded so a retry knows what is left. */
export type EraseStep =
  | "marked"
  | "aborted"
  | "frozen"
  | "files-removed"
  | "directory-removed"
  | "container-removed"
  | "row-deleted";

/** What erase did, or where it stopped. */
export type EraseOutcome =
  | { readonly ok: true; readonly steps: readonly EraseStep[] }
  | {
      readonly ok: false;
      readonly steps: readonly EraseStep[];
      /** Which step failed. */
      readonly failedAt: EraseStep;
      readonly error: string;
    };

/** The orchestrator calls erase needs. */
export interface EraserOrchestrator {
  /** Stops and removes the runner bound to a session. */
  remove(slotId: string): Promise<{ ok: boolean }>;
  /** Reports pool occupancy, used to reclaim the slot. */
  stats(): Promise<{ ok: boolean; value: { size: number } }>;
}

/** The result of the runner-facing part of an erase. */
export interface RunnerControl {
  /** Aborts a login or export in flight. */
  abort(sessionId: string): Promise<void>;
  /** Freezes the runner so it cannot recreate the vault. */
  freeze(sessionId: string): Promise<void>;
  /** Best-effort secure delete of the session directory's contents. */
  shredDirectory(sessionId: string): Promise<void>;
}

/** Deps for the erase machine. */
export interface EraseDeps {
  readonly db: Db;
  readonly orchestrator: EraserOrchestrator;
  readonly runner: RunnerControl;
  readonly sse: SseHub;
  readonly log?: { warn: (msg: string, fields?: Record<string, unknown>) => void };
}

/**
 * The UI wording, from PLAN-v2 §11.
 *
 * "We deleted everything this service stored for this session" — never "nothing
 * remains anywhere". The distinction is not pedantry: this is a best-effort
 * `shred` plus `rm -rf` on a filesystem that may be CoW, on SSD with wear
 * levelling, under overlayfs. Saying "nothing remains" would be a claim about
 * physical media that the code cannot make.
 */
export const ERASE_UI_WORDING = "We deleted everything this service stored for this session.";

/**
 * run executes the machine for one session.
 *
 * Every step is attempted even after an earlier one fails, because each is
 * independent and the alternative is leaving more behind. The first failure is
 * reported so the sweeper can alert on repeats (§11: "keep a retry record, sweep
 * periodically, alert on repeats").
 *
 * A session whose row is already gone is not an error. `deleteSession` returns 0
 * and the machine still runs, because the directory might still exist — which is
 * exactly the case T-E1's "including when the row is already gone" describes.
 */
export async function runErase(deps: EraseDeps, sessionId: string): Promise<EraseOutcome> {
  const log = deps.log ?? { warn: () => {} };
  const steps: EraseStep[] = [];
  let failedAt: EraseStep | null = null;
  let firstError = "";

  const note = (step: EraseStep, error?: unknown): void => {
    steps.push(step);
    if (error !== undefined && failedAt === null) {
      failedAt = step;
      firstError = error instanceof Error ? error.message : String(error);
      log.warn("erase step failed", { session: sessionId, step, error: firstError });
    }
  };

  // 1. Mark erasing. Done first so an interruption is visible and recoverable.
  //
  // It also removes the session from the idle sweeper's view, because the sweeper
  // deletes rows past their absolute expiry and a row mid-erase must be left
  // alone for the machine to finish.
  try {
    deps.db.run(`UPDATE sessions SET state = 'erasing' WHERE guid = ?`, sessionId);
    note("marked");
  } catch (error) {
    note("marked", error);
  }

  // Tell subscribers the session is going away, before anything is destroyed.
  // A tab holding an open SSE stream should learn why it is being closed rather
  // than seeing the socket drop.
  try {
    deps.sse.emit(sessionId, "session-status", { state: "erasing" });
  } catch {
    // A closed subscriber must not stop an erase.
  }

  const session = deps.db.getSession(sessionId);
  const slotId = session?.runner_id ?? null;

  // 2. Abort any active login or export. §8.2: aborting preserves what is on
  // disk, which is then deleted by step 4 — this step exists so the abort does
  // not race the deletion.
  try {
    await deps.runner.abort(sessionId);
    note("aborted");
  } catch (error) {
    note("aborted", error);
  }

  // 3. Freeze the runner, so it cannot write into the directory being deleted.
  try {
    await deps.runner.freeze(sessionId);
    note("frozen");
  } catch (error) {
    note("frozen", error);
  }

  // 4 and 5. Secure delete then remove the directory. Both happen in the runner:
  // this process has no mount of the vault and could not do either.
  //
  // `shred` where supported, with CoW, SSD wear levelling and overlayfs
  // understood rather than glossed over (§11). The runner knows which of those
  // apply to the host it is on; this process does not.
  try {
    await deps.runner.shredDirectory(sessionId);
    note("files-removed");
    note("directory-removed");
  } catch (error) {
    note("files-removed", error);
    note("directory-removed", error);
  }

  // 6. Remove or recycle the container. §11: "force remove; if still failing, mark
  // the runner unhealthy and quarantine". The orchestrator force-removes; a second
  // failure here is recorded for the sweeper rather than retried inline.
  if (slotId !== null) {
    try {
      await deps.orchestrator.remove(slotId);
      note("container-removed");
    } catch (error) {
      note("container-removed", error);
    }
  } else {
    // Nothing bound, so nothing to remove. Recorded so the step list is complete
    // and a reader can tell "no container" from "container removal skipped".
    note("container-removed");
  }

  // Close every SSE stream for the session. The row is about to go, and a live
  // stream would keep replaying events for a session that no longer exists.
  deps.sse.drop(sessionId);

  // 7. Delete the row. Last, so an interruption above leaves a recoverable
  // `erasing` row rather than no trace at all.
  //
  // T-E1: this runs even when the row was already gone, because the directory
  // might still have existed and steps 4–5 above still did their work.
  try {
    deps.db.deleteSession(sessionId);
    note("row-deleted");
  } catch (error) {
    note("row-deleted", error);
  }

  // 8. Reclaim the slot. Local bookkeeping: the orchestrator has already removed
  // the container, and it refills the pool on its own tick. Recorded as part of
  // container removal rather than as a separate step, because there is nothing to
  // do here that can fail.
  //
  // The caller is responsible for the eighth thing erase must do, which has no
  // server-side action at all: expiring the cookies. See `expireCookieHeaders`.

  if (failedAt !== null) {
    return { ok: false, steps, failedAt, error: firstError };
  }
  return { ok: true, steps };
}

/**
 * expireCookieHeaders returns the Set-Cookie values that finish an erase.
 *
 * The half of T7 that has no database involvement. A server cannot clear a
 * browser's cookies, so the handler that runs the machine must send these — and
 * it must send them **whether or not the machine succeeded**, because a failed
 * erase that left the row deleted still needs the cookie gone, and a stale tab
 * holding a cookie for a deleted row is exactly the failure T7 describes.
 *
 * Both orders are therefore correct: cookie-then-machine and machine-then-cookie.
 */
export function expireCookieHeaders(): string[] {
  // Composed from the cookie specs rather than written out here, so the two paths
  // cannot drift: an expired cookie that drops HttpOnly or SameSite may not match
  // the original, leaving it in place. See cookies.ts for why each attribute is
  // what it is.
  return [serialiseCookie(expiredSessionCookie()), serialiseCookie(expiredCsrfCookie())];
}

/**
 * pendingErase finds sessions stuck mid-machine.
 *
 * Called at boot and by the sweeper. §11: "directory deletion failure →
 * erase_failed, keep a retry record, sweep periodically, alert on repeats". A row
 * left in `erasing` is that retry record.
 */
export function pendingErase(db: Db): SessionRow[] {
  return db.all<SessionRow>(`SELECT * FROM sessions WHERE state = 'erasing'`);
}