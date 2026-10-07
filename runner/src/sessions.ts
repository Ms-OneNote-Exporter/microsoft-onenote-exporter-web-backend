/**
 * Session directories, and the one job that may run at a time.
 *
 * ## One session per container
 *
 * The orchestrator starts a container per export session and destroys it after,
 * so the runner holds exactly one session's data at a time. That is the
 * containment property: two sessions' credentials and two browsers' memory never
 * coexist, and a leak is bounded by one notebook.
 *
 * ## Concurrency is 1
 *
 * The api's queue already serialises. This is the backstop: two api instances
 * pointed at one runner, or a retry that raced, must not end up with two
 * browsers fighting over two sessions' worth of memory. A second request while a
 * job runs gets a 409 that names the job holding the slot, because "busy" with
 * no explanation is indistinguishable from a hung service.
 */

import { mkdirSync, rmSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { isValidGuid } from "./credential.js";

export interface SessionPaths {
  /** The session's own directory. Everything else hangs off this. */
  readonly dir: string;
  /** The Playwright storage state the packages hand each other. */
  readonly authFile: string;
  /** Where the exporter writes the vault. */
  readonly outDir: string;
  /** Logs and HTML dumps, so erase is one directory removal. */
  readonly logsDir: string;
  /** `$HOME` for child processes, so nothing lands in a shared home. */
  readonly homeDir: string;
}

/**
 * The paths for one session, or null if the guid is not a guid.
 *
 * The guid is checked with {@link isValidGuid} *and* the result is confirmed to
 * be inside the data root. Both, because they fail differently: the regex rejects
 * `../`, and the containment check rejects anything that slipped past it — a
 * second layer for the one filesystem write an attacker reaching this HTTP API
 * controls.
 */
export function sessionPaths(dataRoot: string, guid: string): SessionPaths | null {
  if (!isValidGuid(guid)) return null;

  const root = resolve(dataRoot);
  const dir = resolve(join(root, guid));
  // `dir` must be exactly one level below the root, and the separator check
  // catches `/data/<guid>/../../x` reaching here through some other route.
  if (!dir.startsWith(root + sep)) return null;

  return {
    dir,
    authFile: join(dir, "auth.json"),
    outDir: join(dir, "out"),
    logsDir: join(dir, "logs"),
    homeDir: join(dir, "tmp"),
  };
}

/** Creates the session tree, owner-only. */
export function makeSessionDirs(paths: SessionPaths): void {
  for (const dir of [paths.dir, paths.logsDir, paths.outDir, paths.homeDir]) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

/** Removes a session tree. Best-effort: a failure must not throw into a request. */
export function removeSessionDirs(paths: SessionPaths): void {
  try {
    rmSync(paths.dir, { recursive: true, force: true });
  } catch {
    // Nothing useful to do here. The container is about to be destroyed, which
    // takes the directory with it — this is the in-container cleanup that makes
    // the disk space available sooner.
  }
}

/** What kind of job is occupying the runner. */
export type JobKind = "login" | "list" | "export";

/** A job in flight, or null. */
export interface ActiveJob {
  readonly guid: string;
  readonly kind: JobKind;
  readonly startedAt: number;
  /** Abort, for the export case. `login` and `list` are not abortable. */
  abort?: AbortController;
}

/** Raised when a job is requested while one is running. */
export class JobBusyError extends Error {
  constructor(
    readonly activeGuid: string,
    readonly activeKind: JobKind,
  ) {
    super(`a ${activeKind} job is already running for another session`);
    this.name = "JobBusyError";
  }
}

/**
 * Holds the single job slot.
 *
 * Deliberately a plain slot rather than a queue: the api serialises already, and a
 * queue here would mean a request that sat for an hour waiting its turn with the
 * caller believing it had been accepted.
 */
export class JobSlot {
  private current: ActiveJob | null = null;

  get busy(): boolean {
    return this.current !== null;
  }

  describe(): { guid: string; kind: JobKind; since: string } | null {
    if (this.current === null) return null;
    return {
      guid: this.current.guid,
      kind: this.current.kind,
      since: new Date(this.current.startedAt).toISOString(),
    };
  }

  /**
   * Signals the running job to stop.
   *
   * The signal rather than a kill, and deliberately: the export package's abort
   * is a normal outcome that stops between sections, keeps what it wrote, and
   * still resolves its internal links. `kill -9` would lose the partial artefact
   * §8.2 requires be preserved.
   *
   * Idempotent, because a caller may retry an abort whose first response was lost.
   */
  abortNow(): boolean {
    if (this.current?.abort === undefined) return false;
    this.current.abort.abort();
    return true;
  }

  /**
   * Claims the slot, or throws {@link JobBusyError}.
   *
   * `release` is returned rather than exposed as a method so the caller cannot
   * release someone else's slot: only the closure holding this token can.
   */
  claim(guid: string, kind: JobKind, abort?: AbortController): { release: () => void } {
    if (this.current !== null) {
      throw new JobBusyError(this.current.guid, this.current.kind);
    }
    this.current = { guid, kind, startedAt: Date.now(), ...(abort ? { abort } : {}) };
    let released = false;
    return {
      release: () => {
        if (released) return;
        released = true;
        this.current = null;
      },
    };
  }
}
