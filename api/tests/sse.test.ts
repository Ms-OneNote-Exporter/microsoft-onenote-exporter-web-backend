import { describe, expect, it, vi } from "vitest";
import { EventEmitter } from "node:events";
import type { ServerResponse } from "node:http";

import {
  EVENT_TYPES,
  SseHub,
  parseLastEventId,
} from "../src/sse.js";

/**
 * PLAN-v2 §7, §7.2, §7.3, §7.4, §7.5; PLAN-v3 §6. The behaviours with real design
 * weight are replay, the snapshot fallback, and multi-tab fan-out.
 */

/** A response stand-in that records what was written. */
function fakeResponse(): ServerResponse & { written: string[]; headers?: Record<string, unknown> } {
  const written: string[] = [];
  const res = new EventEmitter() as unknown as ServerResponse & {
    written: string[];
    headers?: Record<string, unknown>;
  };
  res.written = written;
  res.write = ((chunk: string) => {
    written.push(String(chunk));
    return true;
  }) as ServerResponse["write"];
  res.end = (() => {
    res.emit("close");
    return res;
  }) as ServerResponse["end"];
  res.writeHead = ((status: number, headers: Record<string, unknown>) => {
    res.headers = headers;
    return res;
  }) as ServerResponse["writeHead"];
  return res;
}

/** Parse the frames a response received. */
function frames(written: string[]): Array<{ id?: string; event?: string; data: string }> {
  return written
    .join("")
    .split("\n\n")
    .filter((f) => f.trim() !== "" && !f.startsWith(":"))
    .map((frame) => {
      const out: { id?: string; event?: string; data: string } = { data: "" };
      for (const line of frame.split("\n")) {
        if (line.startsWith("id: ")) out.id = line.slice(4);
        else if (line.startsWith("event: ")) out.event = line.slice(7);
        else if (line.startsWith("data: ")) out.data = line.slice(6);
      }
      return out;
    });
}

const SESSION = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const NOW = 1_700_000_000_000;

function newHub(options = {}) {
  return new SseHub({ now: () => NOW, ...options });
}

describe("emit and fan-out", () => {
  it("sends an event with an id, a type and a payload", () => {
    const hub = newHub();
    const res = fakeResponse();
    hub.attach(SESSION, res, null);

    hub.emit(SESSION, "login-started", { method: "password" });

    const [frame] = frames(res.written);
    expect(frame.id).toBe("1");
    expect(frame.event).toBe("login-started");
    expect(JSON.parse(frame.data)).toEqual({ method: "password" });
  });

  it("numbers events monotonically", () => {
    const hub = newHub();
    hub.emit(SESSION, "session-status", {});
    hub.emit(SESSION, "auth-state", {});
    const third = hub.emit(SESSION, "login-success", {});
    expect(third.id).toBe(3);
  });

  // §7.4: two tabs share one fan-out, so one tab's export appears in the other.
  it("delivers identical bytes to every subscriber", () => {
    const hub = newHub();
    const a = fakeResponse();
    const b = fakeResponse();
    const c = fakeResponse();
    hub.attach(SESSION, a, null);
    hub.attach(SESSION, b, null);
    hub.attach(SESSION, c, null);

    hub.emit(SESSION, "export-started", { notebook: "Work" });

    expect(a.written).toEqual(b.written);
    expect(b.written).toEqual(c.written);
  });

  it("does not deliver one session's events to another session", () => {
    const hub = newHub();
    const mine = fakeResponse();
    const theirs = fakeResponse();
    hub.attach(SESSION, mine, null);
    hub.attach("00000000-0000-0000-0000-000000000000", theirs, null);

    hub.emit(SESSION, "export-started", {});

    expect(frames(mine.written)).toHaveLength(1);
    expect(frames(theirs.written)).toHaveLength(0);
  });

  it("keeps subscribers isolated after one detaches", () => {
    const hub = newHub();
    const a = fakeResponse();
    const b = fakeResponse();
    const first = hub.attach(SESSION, a, null);
    hub.attach(SESSION, b, null);

    hub.detach(SESSION, first.subscriberId);
    hub.emit(SESSION, "export-done", {});

    expect(frames(a.written)).toHaveLength(0);
    expect(frames(b.written)).toHaveLength(1);
  });

  it("drops a subscriber whose write throws rather than failing the emit", () => {
    // A slow or dead connection must not hold up delivery for the others.
    const hub = newHub();
    const broken = fakeResponse();
    broken.write = (() => {
      throw new Error("EPIPE");
    }) as ServerResponse["write"];
    const healthy = fakeResponse();
    hub.attach(SESSION, broken, null);
    hub.attach(SESSION, healthy, null);

    expect(() => hub.emit(SESSION, "export-progress", {})).not.toThrow();
    expect(frames(healthy.written)).toHaveLength(1);
    expect(hub.stats()[SESSION]).toBe(1);
  });

  it("escapes a newline in a log line so it cannot forge an event boundary", () => {
    // The one place user-supplied text meets the wire format.
    const hub = newHub();
    const res = fakeResponse();
    hub.attach(SESSION, res, null);

    hub.emit(SESSION, "export-log", "line one\n\nevent: auth-state\ndata: forged");

    const parsed = frames(res.written);
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.event).toBe("export-log");
    expect(parsed[0]?.data).toContain("\\n");
  });

  it("carries a string payload through without JSON quoting it", () => {
    // The plan's own examples use strings; double-quoting would make the client
    // parse twice.
    const hub = newHub();
    const res = fakeResponse();
    hub.attach(SESSION, res, null);

    hub.emit(SESSION, "export-log", "plain text");
    expect(frames(res.written)[0]?.data).toBe("plain text");
  });
});

describe("replay", () => {
  it("replays only what the client missed", () => {
    const hub = newHub();
    hub.emit(SESSION, "export-started", {});
    hub.emit(SESSION, "export-progress", { pages: 10 });
    hub.emit(SESSION, "export-progress", { pages: 20 });

    const res = fakeResponse();
    const attached = hub.attach(SESSION, res, 1);

    expect(attached.replayed).not.toBeNull();
    expect(attached.replayed?.map((e) => e.id)).toEqual([2, 3]);
  });

  it("does not replay the event the client already has", () => {
    // Strictly greater. Replaying lastEventId would duplicate one event.
    const hub = newHub();
    hub.emit(SESSION, "export-started", {});
    hub.emit(SESSION, "export-progress", {});

    const attached = hub.attach(SESSION, fakeResponse(), 2);
    expect(attached.replayed).toEqual([]);
  });

  it("replays everything after a first-event id", () => {
    const hub = newHub();
    hub.emit(SESSION, "export-started", {});
    hub.emit(SESSION, "export-progress", {});

    const attached = hub.attach(SESSION, fakeResponse(), 0);
    expect(attached.replayed?.map((e) => e.id)).toEqual([1, 2]);
  });

  // T-S5 / §7.2: a Last-Event-ID that has fallen out of the buffer yields a
  // snapshot rather than a gap.
  it("returns null when the resume point has been evicted", () => {
    const hub = newHub({ bufferEvents: 3 });
    for (let i = 0; i < 10; i++) {
      hub.emit(SESSION, "export-progress", { i });
    }

    const attached = hub.attach(SESSION, fakeResponse(), 1);
    expect(attached.replayed).toBeNull();
  });

  it("replays normally when the resume point is still in the buffer", () => {
    const hub = newHub({ bufferEvents: 5 });
    for (let i = 0; i < 4; i++) {
      hub.emit(SESSION, "export-progress", { i });
    }

    const attached = hub.attach(SESSION, fakeResponse(), 2);
    expect(attached.replayed?.map((e) => e.id)).toEqual([3, 4]);
  });

  it("returns null rather than replaying the buffer to a fresh client", () => {
    // A client with no Last-Event-ID gets a snapshot, not the whole history.
    const hub = newHub();
    hub.emit(SESSION, "export-started", {});
    const attached = hub.attach(SESSION, fakeResponse(), null);
    expect(attached.replayed).toBeNull();
  });

  it("evicts by event count", () => {
    const hub = newHub({ bufferEvents: 2 });
    hub.emit(SESSION, "export-progress", { i: 1 });
    hub.emit(SESSION, "export-progress", { i: 2 });
    hub.emit(SESSION, "export-progress", { i: 3 });

    // Event 1 has been evicted, so the buffer holds [2, 3]. A client holding 2
    // needs only 3, which is present.
    expect(hub.attach(SESSION, fakeResponse(), 2).replayed?.map((e) => e.id)).toEqual([3]);
  });

  // The distinction that matters: a client holding 1 needs 2 and 3 and gets
  // both, so replaying is complete even though the buffer no longer holds 1.
  // Replaying the whole buffer to that client would duplicate an event.
  it("does not treat a partially-evicted buffer as a gap", () => {
    const hub = newHub({ bufferEvents: 2 });
    hub.emit(SESSION, "export-progress", { i: 1 });
    hub.emit(SESSION, "export-progress", { i: 2 });
    hub.emit(SESSION, "export-progress", { i: 3 });

    const attached = hub.attach(SESSION, fakeResponse(), 1);
    expect(attached.replayed?.map((e) => e.id)).toEqual([2, 3]);
  });

  it("reports a gap when the client is missing an event the buffer also lost", () => {
    const hub = newHub({ bufferEvents: 2 });
    for (let i = 1; i <= 4; i++) {
      hub.emit(SESSION, "export-progress", { i });
    }
    // Buffer holds [3, 4]. A client holding 0 needs 1 and 2, both evicted.
    expect(hub.attach(SESSION, fakeResponse(), 0).replayed).toBeNull();
    // A client holding 2 needs 3 and 4, both present.
    expect(hub.attach(SESSION, fakeResponse(), 2).replayed?.map((e) => e.id)).toEqual([3, 4]);
  });

  it("evicts by byte count", () => {
    // §7.2: whichever cap is hit first. A single huge event must not be allowed
    // to exhaust memory.
    const hub = newHub({ bufferEvents: 1000, bufferBytes: 500 });
    hub.emit(SESSION, "export-log", "x".repeat(300));
    hub.emit(SESSION, "export-log", "x".repeat(300));
    hub.emit(SESSION, "export-log", "x".repeat(300));

    expect(hub.attach(SESSION, fakeResponse(), 1).replayed).toBeNull();
  });

  it("treats a resume point beyond the next id as nothing to replay", () => {
    const hub = newHub();
    hub.emit(SESSION, "export-started", {});
    // Cannot normally happen for a monotonic sequence, but treating it as a
    // full replay would be worse than treating it as up to date.
    expect(hub.attach(SESSION, fakeResponse(), 99).replayed).toEqual([]);
  });
});

describe("parseLastEventId", () => {
  it("reads a valid id", () => {
    expect(parseLastEventId("42")).toBe(42);
  });

  it("treats a missing value as no resume point, not as 0", () => {
    // Treating it as 0 would replay the entire buffer to every new client.
    expect(parseLastEventId(undefined)).toBeNull();
    expect(parseLastEventId("")).toBeNull();
  });

  it("rejects a negative or non-numeric value", () => {
    for (const bad of ["-1", "abc", "1.5", "NaN"]) {
      expect(parseLastEventId(bad)).toBeNull();
    }
  });
});

describe("keepalive", () => {
  it("writes a comment line rather than an event frame", () => {
    // A comment is invisible to EventSource, so the client discards nothing.
    const hub = newHub();
    const res = fakeResponse();
    const attached = hub.attach(SESSION, res, null);

    hub.sendComment(SESSION, attached.subscriberId);

    expect(res.written.join("")).toBe(": keepalive\n\n");
    expect(frames(res.written)).toHaveLength(0);
  });

  it("writes a comment to every subscriber on the timer", () => {
    vi.useFakeTimers();
    try {
      const hub = newHub({ keepaliveMs: 1000 });
      const a = fakeResponse();
      const b = fakeResponse();
      hub.attach(SESSION, a, null);
      hub.attach(SESSION, b, null);
      hub.startKeepalive();

      vi.advanceTimersByTime(3000);

      expect(a.written.filter((w) => w.includes("keepalive"))).toHaveLength(3);
      expect(b.written.filter((w) => w.includes("keepalive"))).toHaveLength(3);
      hub.stopKeepalive();
    } finally {
      vi.useRealTimers();
    }
  });

  it("starts only one timer however many times it is started", () => {
    vi.useFakeTimers();
    try {
      const hub = newHub({ keepaliveMs: 1000 });
      const res = fakeResponse();
      hub.attach(SESSION, res, null);
      hub.startKeepalive();
      hub.startKeepalive();
      vi.advanceTimersByTime(1000);
      expect(res.written.filter((w) => w.includes("keepalive"))).toHaveLength(1);
      hub.stopKeepalive();
    } finally {
      vi.useRealTimers();
    }
  });

  it("stops cleanly", () => {
    vi.useFakeTimers();
    try {
      const hub = newHub({ keepaliveMs: 1000 });
      const res = fakeResponse();
      hub.attach(SESSION, res, null);
      hub.startKeepalive();
      hub.stopKeepalive();
      vi.advanceTimersByTime(5000);
      expect(res.written).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("snapshots", () => {
  it("writes a snapshot frame with an id", () => {
    const hub = newHub();
    const res = fakeResponse();
    const attached = hub.attach(SESSION, res, null);

    hub.sendSnapshot(SESSION, attached.subscriberId, { session: { state: "active" } }, 7);

    const [frame] = frames(res.written);
    expect(frame.event).toBe("snapshot");
    expect(frame.id).toBe("7");
    expect(JSON.parse(frame.data).session.state).toBe("active");
  });

  it("ignores a snapshot for an unknown subscriber", () => {
    const hub = newHub();
    expect(() => hub.sendSnapshot(SESSION, "nope", {}, 1)).not.toThrow();
  });
});

describe("drop", () => {
  it("closes every subscriber and forgets the session", () => {
    // Called by erase. A live stream for a deleted row would keep replaying
    // events for a session that no longer exists.
    const hub = newHub();
    const a = fakeResponse();
    const b = fakeResponse();
    let endedA = false;
    a.on("close", () => {
      endedA = true;
    });
    hub.attach(SESSION, a, null);
    hub.attach(SESSION, b, null);

    hub.drop(SESSION);

    expect(endedA).toBe(true);
    expect(hub.stats()).toEqual({});
  });

  it("ignores an unknown session", () => {
    expect(() => newHub().drop("nope")).not.toThrow();
  });
});

/*
 * The header assertions moved.
 *
 * They used to live here, testing a `writeSseHeaders(res)` helper that nothing in
 * production called. That helper wrote headers with `res.writeHead(200, {...})`,
 * which replaces the header set rather than merging — so it was correct in this
 * test and would have discarded the CORS headers the moment a route used it. The
 * live version is asserted against real HTTP in tests/sse-cors.test.ts, where a
 * browser's view is what is being checked.
 */

describe("event types", () => {
  it("covers the contract from PLAN-v2 §7.1", () => {
    for (const type of [
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
      "snapshot",
    ]) {
      expect(EVENT_TYPES).toContain(type);
    }
  });
});

describe("stats", () => {
  it("reports only sessions with subscribers", () => {
    const hub = newHub();
    const a = fakeResponse();
    hub.attach(SESSION, a, null);
    expect(hub.stats()).toEqual({ [SESSION]: 1 });
  });
});