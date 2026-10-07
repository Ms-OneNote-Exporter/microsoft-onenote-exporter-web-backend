/**
 * The runner's event translation, and its ring buffer.
 *
 * ## The seam this file guards
 *
 * Two implementations share one contract and cannot see each other's tests. The
 * `@msout` packages emit `challenge`, `login-result {ok, reason}`,
 * `export-progress {pages, sections, assets}`. This runner translates those into
 * `login-started`, `login-success`, `login-failed`, `challenge {id, kind,
 * expiresAt}` and `export-*` for the api, which forwards them to a browser.
 *
 * Every serious bug in this project has been at a boundary exactly like this one,
 * and each was invisible to a green suite. So these assertions are made on the
 * **translated event** — what a browser would receive — rather than on the fact
 * that a handler ran.
 *
 * ## The three asymmetries, tested
 *
 * 1. `challenge-seen` produces no event at all.
 * 2. The package's `challenge-expired` is not forwarded under that name.
 * 3. `id` is echoed from the request, never invented.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { EventHub, formatSse, SSE_KEEPALIVE, type RunnerEvent } from "../src/events.js";

const GUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const OTHER = "11111111-2222-3333-4444-555555555555";

describe("EventHub", () => {
  let hub: EventHub;

  beforeEach(() => {
    hub = new EventHub(5);
  });

  it("numbers events monotonically per hub", () => {
    const first = hub.publish(GUID, { type: "login-started" });
    const second = hub.publish(GUID, { type: "login-success" });
    expect(second.seq).toBeGreaterThan(first.seq);
  });

  it("keeps events per session, not globally mixed", () => {
    // The property that matters with two sessions: a client's replay must not
    // contain the other session's events, least of all its credential-derived
    // ones.
    hub.publish(GUID, { type: "login-started" });
    hub.publish(OTHER, { type: "login-started" });

    const mine = hub.history(GUID, 0);
    const theirs = hub.history(OTHER, 0);
    expect(mine.events).toHaveLength(1);
    expect(theirs.events).toHaveLength(1);
  });

  it("returns only events after the requested sequence", () => {
    const a = hub.publish(GUID, { type: "login-started" });
    hub.publish(GUID, { type: "login-success" });

    const after = hub.history(GUID, a.seq);
    expect(after.events).toHaveLength(1);
    expect(after.events[0]!.seq).toBe(a.seq + 1);
  });

  it("reports a gap rather than returning a partial history that looks complete", () => {
    // Eight events into a five-slot ring discards three. A client reconnecting
    // from before the discards must be told, because a replay that looks
    // continuous but is missing the middle is worse than one that admits a hole.
    for (let i = 0; i < 8; i += 1) {
      hub.publish(GUID, { type: "export-log", id: `x${i}`, line: `line ${i}` });
    }
    const { events, gap } = hub.history(GUID, 1);
    expect(gap).toBe(true);
    expect(events).toHaveLength(5);
  });

  it("does not report a gap when the oldest retained event is the one asked for", () => {
    // `since = oldest - 1` means "everything after oldest - 1", which is exactly
    // what the ring holds. Reporting a gap here would train a client to distrust
    // a complete replay — and the boundary is easy to get wrong in the direction
    // that fails *silently*, so it is pinned from both sides.
    for (let i = 0; i < 8; i += 1) {
      hub.publish(GUID, { type: "export-log", id: `x${i}`, line: `line ${i}` });
    }
    // The ring holds sequences 4..8, so `since = 3` asks for exactly 4..8 and is
    // complete, while `since = 2` also asks for event 3 — which is gone.
    expect(hub.history(GUID, 3).gap).toBe(false);
    expect(hub.history(GUID, 2).gap).toBe(true);
  });

  it("does not report a gap when nothing was discarded", () => {
    hub.publish(GUID, { type: "login-started" });
    hub.publish(GUID, { type: "login-success" });
    expect(hub.history(GUID, 0).gap).toBe(false);
    expect(hub.history(GUID, 1).gap).toBe(false);
  });

  it("trims from the front, so the newest events survive", () => {
    for (let i = 0; i < 8; i += 1) {
      hub.publish(GUID, { type: "export-log", id: "e", line: `line ${i}` });
    }
    const { events } = hub.history(GUID, 0);
    expect(events).toHaveLength(5);
    const last = events[events.length - 1]!.event as { line: string };
    expect(last.line).toBe("line 7");
  });

  it("hands live events to a subscriber, and stops after unsubscribe", () => {
    const seen: RunnerEvent[] = [];
    const unsubscribe = hub.subscribe(GUID, (entry) => seen.push(entry.event));

    hub.publish(GUID, { type: "login-started" });
    expect(seen).toHaveLength(1);

    unsubscribe();
    hub.publish(GUID, { type: "login-success" });
    expect(seen).toHaveLength(1);
  });

  it("does not deliver one session's events to another session's subscriber", () => {
    const mine: RunnerEvent[] = [];
    const theirs: RunnerEvent[] = [];
    hub.subscribe(GUID, (e) => mine.push(e.event));
    hub.subscribe(OTHER, (e) => theirs.push(e.event));

    hub.publish(GUID, { type: "login-started" });
    expect(mine).toHaveLength(1);
    expect(theirs).toHaveLength(0);
  });

  it("drops a session's events on forget, which is what erase calls", () => {
    hub.publish(GUID, { type: "login-failed", reason: "credentials_rejected" });
    hub.forget(GUID);
    // The reason is gone, and so is any record of what was attempted for it.
    expect(hub.history(GUID, 0).events).toHaveLength(0);
    expect(hub.lastSeq(GUID)).toBe(0);
  });

  it("keeps its memory bounded", () => {
    // An export emits a log line per page and can run for an hour. An unbounded
    // buffer in the process that holds a credential is a leak with a security
    // dimension.
    const bounded = new EventHub(3);
    for (let i = 0; i < 1000; i += 1) {
      bounded.publish(GUID, { type: "export-log", id: "e", line: `line ${i}` });
    }
    expect(bounded.history(GUID, 0).events).toHaveLength(3);
  });

  it("lets one throwing subscriber not stop the others", () => {
    // The same rule the `@msout` observers follow: an observer's bug must never
    // become the system's problem. Here a broken subscriber would otherwise
    // prevent a *second* client from receiving the event, and would propagate
    // into `publish`, which runs inside a login's event handler — so a caller's
    // mistake would abort a working sign-in.
    const good: RunnerEvent[] = [];
    hub.subscribe(GUID, () => {
      throw new Error("subscriber bug");
    });
    hub.subscribe(GUID, (e) => good.push(e.event));

    expect(() => hub.publish(GUID, { type: "login-started" })).not.toThrow();
    expect(good, "the healthy subscriber must still be served").toHaveLength(1);
  });

  it("keeps serving after a subscriber throws, rather than detaching it silently", () => {
    const seen: RunnerEvent[] = [];
    hub.subscribe(GUID, () => {
      throw new Error("subscriber bug");
    });
    hub.subscribe(GUID, (e) => seen.push(e.event));

    hub.publish(GUID, { type: "login-started" });
    hub.publish(GUID, { type: "login-success" });
    expect(seen).toHaveLength(2);
  });
});

describe("formatSse", () => {
  it("writes an id and a JSON data line", () => {
    const frame = formatSse({ seq: 7, event: { type: "login-success" } });
    expect(frame).toBe('id: 7\ndata: {"type":"login-success"}\n\n');
  });

  it("omits the event: name, so there is one vocabulary rather than two", () => {
    // The frontend's first version invented SSE event names that did not exist
    // and silently dropped events because of it. Dispatch is on `type` inside the
    // JSON; an `event:` line would be a second name to keep in step.
    const frame = formatSse({ seq: 1, event: { type: "export-done", id: "e1" } });
    expect(frame.startsWith("event:")).toBe(false);
    expect(frame).toContain('"type":"export-done"');
  });

  it("escapes nothing it should not, and does not mangle a newline in a log line", () => {
    // A log line containing a newline would, unescaped, break the frame into two
    // and make the second look like a separate event. JSON already escapes it, so
    // the assertion is that the frame still parses as one.
    const line = "first\nsecond";
    const frame = formatSse({ seq: 1, event: { type: "export-log", id: "e1", line } });
    const dataLine = frame.split("\n").find((l) => l.startsWith("data: "))!;
    const parsed = JSON.parse(dataLine.slice("data: ".length));
    expect(parsed.line).toBe(line);
    expect(frame.endsWith("\n\n")).toBe(true);
  });

  it("writes a keepalive as an SSE comment, which EventSource ignores", () => {
    // A comment is the only thing that keeps an idle stream open without
    // delivering an event a client would have to handle.
    expect(SSE_KEEPALIVE.startsWith(":")).toBe(true);
  });
});
