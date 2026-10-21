/**
 * The registry that orders an erase's cookie expiry against a create that
 * presents the erasing session's cookie.
 *
 * ## The race
 *
 * The erase's response carries a `Set-Cookie` that expires `__Host-msout`
 * **by name** (`expireCookieHeaders` in `erase.ts`). The api also announces the
 * erase with `session-status {state:"erasing"}` at the **start** of the machine,
 * and the frontend reads that snapshot as "no session" and offers to start a
 * replacement. So a new session can be created **while the erase is still
 * running**: its response sets a fresh cookie, and then the erase's response
 * lands and expires it.
 *
 * Two responses write the same cookie by name, and nothing ordered them. The
 * result is a session that exists in SQLite and is unreachable — every later
 * request carries no cookie and is answered 401.
 *
 * Measured on the deployed host, with one erase and one create, from the
 * browser's own requests (the cookie's guid only — the secret never left the
 * browser):
 *
 * ```
 * 37781 201 POST /api/session       cookie=4061d8a9   <- the create, with the OLD cookie
 * 37813 200 GET  /api/session/status cookie=e4e40fcb  <- the new session's cookie, in force
 * 37931 200 POST /api/session/erase cookie=4061d8a9   <- the erase's response, 150ms later
 * 37958 401 GET  /api/session/status cookie=(none)    <- the new session's cookie: GONE
 * ```
 *
 * ## The fix
 *
 * A create that presents the cookie of a session that is being erased must not
 * answer until that erase's response has been **flushed to the socket** — the
 * moment the browser applies its `Set-Cookie`. Two signals are needed, because
 * neither alone is exact:
 *
 *   - **the registry** (below) knows when *this* api process flushed the erase's
 *     response. It is exact, and it is lost if the api restarts.
 *   - **the row's state** survives a restart: a row still in `erasing` means an
 *     erase is in flight, whoever started it.
 *
 * ## Why it is a module and not part of the erase machine
 *
 * The machine is a pure function of its dependencies today, and giving it
 * process state would make it untestable in isolation. This module is a
 * separate seam, constructed once and threaded through `ServerDeps` like `sse`
 * and `limiter` — so an app that does not pass one cannot be built at all,
 * rather than silently losing the guarantee.
 */

/**
 * How long a create may wait for an erase.
 *
 * The erase machine's slowest path is a session **with** a runner: it aborts,
 * freezes and shreds through the container (the adapter's per-request timeout
 * is 15s each) and asks the orchestrator to remove the container (the
 * orchestrator's container verbs use `CONTAINER_VERB_TIMEOUT_MS`, 75s).
 *
 * 60s is generous against the runner-facing calls and short enough that a stuck
 * erase cannot hold a create for a visible length of time. **Reaching the bound
 * releases the create anyway** — the worst case is the old race, and a stuck
 * erase is a different problem from a lost one.
 */
export const MAX_ERASE_ORDERING_WAIT_MS = 60_000;

/** How often the restart-safe backstop re-reads the row while it waits. */
const ROW_POLL_INTERVAL_MS = 50;

/** The ordering seam the api's routes depend on. */
export interface EraseOrdering {
  /**
   * Records that an erase of `guid` is in flight.
   *
   * Called **before** the erase machine runs, so a create that arrives during
   * the machine finds the entry. The returned function releases it, and it must
   * be called when the erase's response has been **flushed to the socket** —
   * not merely built — because that is when the browser applies the expiry.
   *
   * Releasing twice is harmless ✓ (the second call does nothing).
   */
  register(guid: string): () => void;

  /**
   * Resolves when it is safe for a create to answer.
   *
   * "Safe" means the erase's response has been flushed, so the browser cannot
   * apply its expiry after the create's cookie is set.
   */
  settle(guid: string): Promise<void>;
}

/** An in-flight erase. */
interface Entry {
  /** Resolves when the erase's response has been flushed. */
  readonly done: Promise<void>;
  /** Releases the entry. Idempotent ✓. */
  release(): void;
}

export interface EraseOrderingOptions {
  /**
   * Whether the session named by a guid is still being erased.
   *
   * The **restart-safe** backstop: a row left in `erasing` means an erase is in
   * flight even if this process did not start it (the api restarted mid-erase).
   * It is a callback rather than a database handle so this module stays free of
   * the storage layer and testable in isolation ✓.
   */
  isErasing?: (guid: string) => boolean;
  /** Called when the wait hits its bound, so an operator can see a stuck erase. */
  log?: (message: string) => void;
}

/**
 * createEraseOrdering builds the registry.
 *
 * The state is per-process, and it is the **only** per-process state in this
 * path ✓ — the api's other authorities (sessions, runners) are in SQLite ✓
 * (ARCHITECTURE.md §4.9). Losing it on a restart is covered by the row's state
 * ✓, which is why the two are used together.
 */
export function createEraseOrdering(options: EraseOrderingOptions = {}): EraseOrdering {
  const entries = new Map<string, Entry>();

  const register = (guid: string): (() => void) => {
    let resolveDone: (() => void) | null = null;
    const done = new Promise<void>((resolve) => {
      resolveDone = resolve;
    });

    let released = false;
    const entry: Entry = {
      done,
      release: () => {
        if (released) return;
        released = true;
        // Only delete **this** entry: a second erase of the same guid may have
        // registered over it while this one was in flight.
        if (entries.get(guid) === entry) entries.delete(guid);
        resolveDone?.();
      },
    };

    entries.set(guid, entry);
    return entry.release;
  };

  const settle = async (guid: string): Promise<void> => {
    const entry = entries.get(guid);

    if (entry !== undefined) {
      // The exact signal: this process flushed the erase's response. Waiting for
      // it also implies the row is gone, because the machine deletes the row
      // before the response is sent ✓.
      await raceWithBound(entry.done, guid);
      return;
    }

    // No entry: either nothing is being erased ✓, or an erase started before
    // this process did (a restart). The row's state tells the two apart ✓.
    if (options.isErasing === undefined) return;
    if (!options.isErasing(guid)) return;

    await raceWithBound(waitUntilNotErasing(guid), guid);
  };

  /** Waits until the row named by the guid is no longer being erased. */
  const waitUntilNotErasing = async (guid: string): Promise<void> => {
    for (;;) {
      if (!options.isErasing!(guid)) return;
      await new Promise((resolve) => setTimeout(resolve, ROW_POLL_INTERVAL_MS));
    }
  };

  /** Races a promise against the bound, and says so when the bound is reached. */
  const raceWithBound = async (promise: Promise<void>, guid: string): Promise<void> => {
    let timer: NodeJS.Timeout | undefined;
    const bound = new Promise<void>((resolve) => {
      timer = setTimeout(() => {
        options.log?.(
          `create waited ${MAX_ERASE_ORDERING_WAIT_MS}ms for the erase of ${guid} to be flushed; the erase may be stuck`,
        );
        resolve();
      }, MAX_ERASE_ORDERING_WAIT_MS);
    });
    try {
      await Promise.race([promise, bound]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };

  return { register, settle };
}
