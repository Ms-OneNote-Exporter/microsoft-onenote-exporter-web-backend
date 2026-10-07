/**
 * Per-session events, and the SSE stream that carries them.
 *
 * ## Why the runner has its own event vocabulary
 *
 * The `@msout` packages report **what they saw on screen**:
 * `challenge`, `login-result {ok, reason}`, `export-progress {pages, sections,
 * assets}`. None of those is a statement about a session, and the packages
 * deliberately do not emit the ones that are — `login-started`, `login-success`,
 * `login-failed`, `auth-state` are the api's to say.
 *
 * The runner is the seam. It receives the package's vocabulary, and emits the
 * api's over SSE. Neither side can see the other's, which is exactly why every
 * serious bug in this project has been at a boundary like this one.
 *
 * ## The mapping, in one place
 *
 *   package                        runner -> api
 *   ------------------------------ ----------------------------------------
 *   (credential accepted)          login-started
 *   challenge {kind, number, ...}  challenge
 *   challenge-seen                 (nothing: no session claim)
 *   challenge-expired              (folded into the login-result reason)
 *   login-result {ok, reason}      login-success | login-failed {reason}
 *   export-started                 export-started {id}
 *   export-progress {progress}     export-progress {id, progress}
 *   export-log {line}              export-log {id, line}
 *   export-done                    export-done {id, pages, sections, assets}
 *   export-partial {reason}        export-partial {id, reason}
 *   export-aborted                 export-aborted {id}
 *
 * Three deliberate asymmetries:
 *
 * - **`challenge-seen` produces no event.** A challenge being answered is the
 *   opposite of a session claim: the login then continues to the redirect wait.
 *   Emitting `login-success` there would tell the browser a user is signed in
 *   mid-MFA and contradict it seconds later. The runner clears its own pending
 *   challenge and says nothing.
 *
 * - **The package's `challenge-expired` is not forwarded as the api's
 *   `challenge-expired`.** The api already emits that name on its own 15-minute
 *   login TTL, so one name would carry two unrelated deadlines. The runner folds
 *   it into the login-result reason instead.
 *
 * - **`id` is the api's**, passed in per request and echoed on every export
 *   event. The runner does not invent one: it does not know what a session is.
 */

export type RunnerEvent =
  | { type: "login-started" }
  | { type: "challenge"; kind: string; label: string; number: string | null; expiresAt: string | null }
  | { type: "login-success" }
  | { type: "login-failed"; reason: string }
  | { type: "notebooks-listed"; notebooks: ReadonlyArray<{ name: string; url: string }> }
  | { type: "notebooks-failed"; reason: string }
  | { type: "export-started"; id: string }
  | { type: "export-progress"; id: string; progress: ExportProgress }
  | { type: "export-log"; id: string; line: string }
  | { type: "export-done"; id: string; notebook: string; pages: number; sections: number; assets: number }
  | { type: "export-partial"; id: string; reason: string }
  | { type: "export-aborted"; id: string }
  | { type: "error"; message: string };

/**
 * Counts-so-far. Never a fraction.
 *
 * Mid-run the totals are not known, so a percentage would be a number the runner
 * cannot compute. The api types this as `{pages, sections, assets}` in its
 * `SessionSnapshot` and the frontend renders it as "N pages, M sections so far".
 */
export interface ExportProgress {
  readonly pages: number;
  readonly sections: number;
  readonly assets: number;
}

/** One event as stored in the ring and sent on the wire. */
export interface SequencedEvent {
  readonly seq: number;
  readonly event: RunnerEvent;
}

/**
 * A ring buffer per session, with a live subscriber list.
 *
 * Bounded on purpose: an export emits a log line per page and a container can
 * run for an hour, and an unbounded buffer in the one process holding a
 * credential is a memory leak with a security dimension.
 *
 * The gap is reported rather than papered over. A reconnecting client that asks
 * for events which have aged out is told so, because a replay that looks
 * continuous but is missing the middle is worse than one that admits a hole.
 */
export class EventHub {
  private readonly rings = new Map<string, SequencedEvent[]>();
  private readonly subscribers = new Map<string, Set<(e: SequencedEvent) => void>>();
  private seq = 0;

  constructor(private readonly ringSize: number) {}

  /**
   * Publishes an event for one session, and hands it to live subscribers.
   *
   * A subscriber that throws is logged and skipped, and the remaining
   * subscribers are still served. The throw is contained here rather than in the
   * subscriber because the alternative propagates: `publish` is called from
   * inside a login's `onEvent` callback, so an exception would unwind through
   * `login()` and turn one client's bug into a failed sign-in for another.
   */
  publish(guid: string, event: RunnerEvent): SequencedEvent {
    const entry: SequencedEvent = { seq: ++this.seq, event };
    const ring = this.rings.get(guid);
    if (ring === undefined) {
      this.rings.set(guid, [entry]);
    } else {
      ring.push(entry);
      // Trim from the front. A ring, not a queue: the newest events are the ones
      // a reconnecting client still needs.
      while (ring.length > this.ringSize) ring.shift();
    }
    for (const subscriber of this.subscribers.get(guid) ?? []) {
      try {
        subscriber(entry);
      } catch (cause) {
        // The subscriber is not detached: a transient failure on one write must
        // not cost that client the rest of the stream, and the next event is an
        // opportunity to succeed.
        process.stderr.write(
          `runner: an SSE subscriber threw while handling ${event.type}: ${
            cause instanceof Error ? cause.message : String(cause)
          }\n`,
        );
      }
    }
    return entry;
  }

  /** The newest sequence number for a session, for a client about to subscribe. */
  lastSeq(guid: string): number {
    const ring = this.rings.get(guid);
    return ring === undefined || ring.length === 0 ? 0 : ring[ring.length - 1]!.seq;
  }

  /**
   * Events after `since`, and whether the ring had already discarded some.
   *
   * `gap` is true when `since` is older than the oldest retained event, which
   * means the caller asked for something that is gone. Reported rather than
   * answered with a partial list that looks complete.
   */
  history(guid: string, since: number): { events: SequencedEvent[]; gap: boolean } {
    const ring = this.rings.get(guid);
    if (ring === undefined || ring.length === 0) return { events: [], gap: false };
    const oldest = ring[0]!.seq;
    return {
      events: ring.filter((e) => e.seq > since),
      // A gap means an event the caller asked for is gone. `oldest - 1` is the
      // last sequence still retained, so a `since` below that is a real hole —
      // asking for `oldest - 1` itself is complete, because everything after it
      // survives. Asking from `0` is never a gap: that is "everything", and the
      // ring's oldest entry is the answer.
      gap: since > 0 && since < oldest - 1,
    };
  }

  subscribe(guid: string, fn: (e: SequencedEvent) => void): () => void {
    let set = this.subscribers.get(guid);
    if (set === undefined) {
      set = new Set();
      this.subscribers.set(guid, set);
    }
    set.add(fn);
    return () => {
      set?.delete(fn);
      if (set?.size === 0) this.subscribers.delete(guid);
    };
  }

  /** Drops a session's events. Called when the container is destroyed. */
  forget(guid: string): void {
    this.rings.delete(guid);
    this.subscribers.delete(guid);
  }

  /** Drops every ring, for a test that has finished. */
  reset(): void {
    this.rings.clear();
    this.subscribers.clear();
    this.seq = 0;
  }
}

/**
 * Formats one event as an SSE frame.
 *
 * `data:` only, with no `event:` line. The api is the only consumer and it
 * dispatches on the `type` inside the JSON, so the SSE event name would be a
 * second vocabulary to keep in step — and the first version of this project's
 * frontend invented event names that did not exist and silently dropped events
 * because of it.
 */
export function formatSse(entry: SequencedEvent): string {
  return `id: ${entry.seq}\ndata: ${JSON.stringify(entry.event)}\n\n`;
}

/** The keepalive comment, sent on an idle stream so proxies do not close it. */
export const SSE_KEEPALIVE = ": keepalive\n\n";
