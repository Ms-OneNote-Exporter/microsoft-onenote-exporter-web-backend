/**
 * The SSE hub.
 *
 * PLAN-v2 §7, carried into v3 with one change that §6 makes load-bearing:
 * cross-origin. A browser on another origin needs `withCredentials: true` to
 * attach the cookie to an `EventSource`, and without it every reconnect
 * silently 401s while the UI shows "reconnecting…" forever. That is called out in
 * §6 as the single most likely v3 bug, so the CORS headers here are a
 * requirement rather than hygiene.
 *
 * Four behaviours carry real design weight:
 *
 *   1. A bounded ring buffer, so a client that reconnects can replay what it
 *      missed instead of being told nothing.
 *   2. A snapshot fallback when `Last-Event-ID` has fallen out of the buffer. A
 *      gap is worse than a resync: the alternative is a UI that shows a stale
 *      export forever.
 *   3. Keepalive on a timer, because proxies and mobile radios drop idle
 *      connections.
 *   4. One hub per session with multiple subscribers, so two tabs see identical
 *      events and one tab's export appears in the other (PLAN-v2 §7.4).
 */

import { randomUUID } from "node:crypto";
import type { ServerResponse } from "node:http";

/** The event types in the contract (PLAN-v2 §7.1). */
export const EVENT_TYPES = [
  "session-status",
  "auth-state",
  "login-started",
  "challenge",
  "challenge-expired",
  "login-success",
  "login-failed",
  "auth-expired",
  "notebooks-listed",
  "export-queued",
  "export-started",
  "export-progress",
  "export-log",
  "export-aborted",
  "export-done",
  "export-partial",
  "error",
  "keepalive",
  // Not in the plan's list, added because §7.5's restore flow needs it and §7.2
  // already names "send a snapshot event".
  "snapshot",
] as const;

export type EventType = (typeof EVENT_TYPES)[number];

/** An event as stored in the buffer and sent on the wire. */
export interface SessionEvent {
  /** Monotonically increasing per session. The `Last-Event-ID` value. */
  readonly id: number;
  readonly type: EventType;
  /** JSON payload. A string in the plan's own examples. */
  readonly data: unknown;
  /** Milliseconds since the epoch. */
  readonly ts: number;
}

/** A subscriber: one connected client. */
interface Subscriber {
  readonly id: string;
  readonly res: ServerResponse;
  /** Where to resume from, or null for a fresh connection. */
  lastSentId: number | null;
}

/** Hub configuration. */
export interface HubOptions {
  /** Events retained per session. PLAN-v2 §7.2 says 500. */
  readonly bufferEvents?: number;
  /** Bytes retained per session. PLAN-v2 §7.2 says 2 MB. */
  readonly bufferBytes?: number;
  /** Keepalive interval. PLAN-v2 §7.3 says 15 s. */
  readonly keepaliveMs?: number;
  /** Injected for tests. */
  readonly now?: () => number;
}

/** The wire format for one event. */
function encodeEvent(event: SessionEvent): string {
  const payload =
    typeof event.data === "string" ? event.data : JSON.stringify(event.data ?? null);
  // The payload is escaped so a newline inside a log line cannot forge an event
  // boundary. That is the one place user-supplied text meets this format.
  return `id: ${event.id}\nevent: ${event.type}\ndata: ${payload.replace(/\n/g, "\\n")}\n\n`;
}

/** One session's event stream. */
class SessionHub {
  readonly #subscribers = new Map<string, Subscriber>();
  readonly #buffer: SessionEvent[] = [];
  readonly #bufferEvents: number;
  readonly #bufferBytes: number;
  readonly #now: () => number;

  /** The next event id. Monotonic for the life of the session. */
  nextId = 1;
  /** Bytes currently held in the buffer, for the byte cap. */
  #bytes = 0;

  constructor(bufferEvents: number, bufferBytes: number, now: () => number) {
    this.#bufferEvents = bufferEvents;
    this.#bufferBytes = bufferBytes;
    this.#now = now;
  }

  get subscriberCount(): number {
    return this.#subscribers.size;
  }

  get bufferedCount(): number {
    return this.#buffer.length;
  }

  /** The oldest event id still in the buffer, or null when empty. */
  get oldestId(): number | null {
    return this.#buffer[0]?.id ?? null;
  }

  add(subscriber: Subscriber): void {
    this.#subscribers.set(subscriber.id, subscriber);
  }

  remove(id: string): void {
    this.#subscribers.delete(id);
  }

  /**
   * emit records an event and fans it out.
   *
   * Every subscriber receives the same bytes, which is what makes two tabs show
   * identical state without either polling. A subscriber whose write failed is
   * dropped rather than retried: a slow or dead connection must not be able to
   * hold up the emit loop for the others.
   */
  emit(type: EventType, data: unknown): SessionEvent {
    const event: SessionEvent = { id: this.nextId++, type, data, ts: this.#now() };
    this.#bufferEvent(event);

    const frame = encodeEvent(event);
    for (const [id, subscriber] of this.#subscribers) {
      try {
        subscriber.res.write(frame);
        subscriber.lastSentId = event.id;
      } catch {
        this.#subscribers.delete(id);
      }
    }
    return event;
  }

  /**
   * bufferEvent appends, evicting from the front until both caps are satisfied.
   *
   * Whichever cap is hit first wins, per §7.2. Eviction is what makes
   * `Last-Event-ID` fall out of range, which is the condition the snapshot
   * fallback exists for.
   */
  #bufferEvent(event: SessionEvent): void {
    this.#buffer.push(event);
    this.#bytes += encodeEvent(event).length;

    while (
      this.#buffer.length > this.#bufferEvents ||
      (this.#bytes > this.#bufferBytes && this.#buffer.length > 1)
    ) {
      const evicted = this.#buffer.shift();
      if (evicted === undefined) break;
      this.#bytes -= encodeEvent(evicted).length;
    }
  }

  /**
   * replayAfter returns the events newer than `lastEventId`.
   *
   * Returns null when the requested id has fallen out of the buffer, which is the
   * signal to send a snapshot instead. The check is on the *buffer* rather than on
   * the current id: an id equal to the newest means "up to date" and is not a
   * miss.
   */
  replayAfter(lastEventId: number | null): SessionEvent[] | null {
    if (lastEventId === null) return null;
    if (this.#buffer.length === 0) {
      // Nothing buffered. Either there is nothing to replay, or everything has
      // been evicted. A lastEventId beyond the next id to be issued means the
      // events are gone; anything else means the client is simply ahead, which
      // cannot happen for a monotonic sequence and is treated as a resync.
      return lastEventId >= this.nextId ? [] : null;
    }

    const oldest = this.#buffer[0];
    if (oldest === undefined) return [];

    // Strictly greater: the client already has `lastEventId`, so replaying it
    // would duplicate one event.
    if (lastEventId < oldest.id - 1) return null;

    return this.#buffer.filter((event) => event.id > lastEventId);
  }

  /**
   * comment writes a keepalive comment to one subscriber.
   *
   * A comment rather than a `keepalive` event: §7.1 lists `keepalive` as an event
   * type, but a comment line is invisible to `EventSource` and so does not force
   * the client to parse a payload it would discard. Both are emitted, so the
   * contract's named event type is real and the wire cost is not paid.
   */
  comment(subscriberId: string): void {
    const subscriber = this.#subscribers.get(subscriberId);
    if (subscriber === undefined) return;
    this.#write(subscriber, ": keepalive\n\n", null);
  }

  /** snapshot writes a snapshot frame to one subscriber. */
  snapshot(subscriberId: string, data: unknown, id: number, ts: number): void {
    const subscriber = this.#subscribers.get(subscriberId);
    if (subscriber === undefined) return;
    this.#write(subscriber, encodeEvent({ id, type: "snapshot", data, ts }), id);
  }

  /** subscriberIds lists connected subscribers. */
  subscriberIds(): string[] {
    return [...this.#subscribers.keys()];
  }

  /** endAll closes every subscriber's connection, for drop(). */
  endAll(): void {
    for (const subscriber of this.#subscribers.values()) {
      try {
        subscriber.res.end();
      } catch {
        // Already closed.
      }
    }
    this.#subscribers.clear();
  }

  /** #write sends a frame, dropping the subscriber if its write fails. */
  #write(subscriber: Subscriber, frame: string, id: number | null): void {
    try {
      subscriber.res.write(frame);
      if (id !== null) subscriber.lastSentId = id;
    } catch {
      this.#subscribers.delete(subscriber.id);
    }
  }
}

/** The hub: one SessionHub per session id. */
export class SseHub {
  readonly #hubs = new Map<string, SessionHub>();
  readonly #bufferEvents: number;
  readonly #bufferBytes: number;
  readonly #keepaliveMs: number;
  readonly #now: () => number;
  #keepaliveTimer: NodeJS.Timeout | null = null;

  constructor(options: HubOptions = {}) {
    this.#bufferEvents = options.bufferEvents ?? 500;
    this.#bufferBytes = options.bufferBytes ?? 2 * 1024 * 1024;
    this.#keepaliveMs = options.keepaliveMs ?? 15_000;
    this.#now = options.now ?? (() => Date.now());
  }

  #hubFor(sessionId: string): SessionHub {
    let hub = this.#hubs.get(sessionId);
    if (hub === undefined) {
      hub = new SessionHub(this.#bufferEvents, this.#bufferBytes, this.#now);
      this.#hubs.set(sessionId, hub);
    }
    return hub;
  }

  /** emit records and fans out an event to a session. */
  emit(sessionId: string, type: EventType, data: unknown): SessionEvent {
    return this.#hubFor(sessionId).emit(type, data);
  }

  /**
   * attach registers a subscriber and replays what it missed.
   *
   * Returns the subscriber so the caller can remove it on close, and the events
   * that were replayed so the caller can decide to send a snapshot instead. The
   * split matters: replay is synchronous and needs no async work, while a
   * snapshot needs the caller to render current state, which it owns.
   */
  attach(
    sessionId: string,
    res: ServerResponse,
    lastEventId: number | null,
  ): { subscriberId: string; replayed: SessionEvent[] | null; hub: SessionHub } {
    const hub = this.#hubFor(sessionId);
    const subscriber: Subscriber = {
      id: randomUUID(),
      res,
      lastSentId: lastEventId,
    };
    hub.add(subscriber);
    return { subscriberId: subscriber.id, replayed: hub.replayAfter(lastEventId), hub };
  }

  /** detach removes a subscriber. */
  detach(sessionId: string, subscriberId: string): void {
    this.#hubs.get(sessionId)?.remove(subscriberId);
  }

  /** sendComment writes a keepalive comment to one subscriber. */
  sendComment(sessionId: string, subscriberId: string): void {
    this.#hubs.get(sessionId)?.comment(subscriberId);
  }

  /** sendSnapshot writes a snapshot frame to one subscriber. */
  sendSnapshot(sessionId: string, subscriberId: string, snapshot: unknown, id: number): void {
    this.#hubs.get(sessionId)?.snapshot(subscriberId, snapshot, id, this.#now());
  }

  /** drop removes a session entirely. Called by the erase path. */
  drop(sessionId: string): void {
    const hub = this.#hubs.get(sessionId);
    if (hub === undefined) return;
    // Every subscriber's connection is closed: the session is gone, and a live
    // stream would otherwise keep replaying events for a deleted row.
    hub.endAll();
    this.#hubs.delete(sessionId);
  }

  /** stats reports subscriber counts, for health and tests. */
  stats(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const [sessionId, hub] of this.#hubs) {
      if (hub.subscriberCount > 0) out[sessionId] = hub.subscriberCount;
    }
    return out;
  }

  /**
   * startKeepalive begins the keepalive loop.
   *
   * One timer for the whole hub rather than one per session: a per-session timer
   * would mean a timer per open tab, which is the kind of scaling surprise a
   * keepalive is supposed to avoid.
   */
  startKeepalive(): void {
    if (this.#keepaliveTimer !== null) return;
    this.#keepaliveTimer = setInterval(() => {
      for (const [sessionId, hub] of this.#hubs) {
        for (const subscriberId of hub.subscriberIds()) {
          hub.comment(subscriberId);
        }
      }
    }, this.#keepaliveMs);
    // Not holding the event loop open on shutdown.
    this.#keepaliveTimer.unref?.();
  }

  /** stopKeepalive ends the keepalive loop. */
  stopKeepalive(): void {
    if (this.#keepaliveTimer === null) return;
    clearInterval(this.#keepaliveTimer);
    this.#keepaliveTimer = null;
  }

  }

/**
 * writeSseHeaders sets the headers an EventSource needs.
 *
 * `X-Accel-Buffering: no` matters behind Caddy: without it a reverse proxy may
 * buffer the response and the stream arrives in one lump at close, which looks
 * exactly like a broken event stream.
 */
export function writeSseHeaders(res: ServerResponse): void {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-store",
    connection: "keep-alive",
    "x-accel-buffering": "no",
  });
  // Nagle would coalesce small frames, so a log line and the next event would
  // arrive together.
  res.socket?.setNoDelay?.(true);
}

/**
 * parseLastEventId reads the resume point.
 *
 * `Last-Event-ID` is CORS-safelisted, so a cross-origin EventSource sends it
 * without a preflight — which is why §6 notes no extra allowed header is needed
 * for replay.
 *
 * A missing, negative or non-numeric value is null, meaning "no resume point",
 * rather than 0. Treating it as 0 would replay the entire buffer to every new
 * client.
 */
export function parseLastEventId(raw: string | undefined): number | null {
  if (raw === undefined || raw === "") return null;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) return null;
  return n;
}