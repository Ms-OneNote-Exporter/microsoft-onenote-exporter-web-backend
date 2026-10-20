/**
 * The id on the snapshot frame the SSE route writes.
 *
 * ## Why the id matters
 *
 * The api's frame ids are per session: `SessionHub.nextId` starts at 1 and a
 * hub is created per session guid (`api/src/sse.ts`). The `id:` on a frame is
 * the client's resume point — the browser sends it back as `Last-Event-ID` and
 * the api resumes from there.
 *
 * The snapshot frame used to carry `hub.nextId`, which is the id the **next**
 * event will take, not one that has been issued. So the snapshot and the first
 * real event shared an id on the wire, and a client that disconnected between
 * them resumed *past* the first real event and never saw it.
 *
 * The snapshot's id is now the last id actually issued (`nextId - 1`), which is
 * the only value a client can legitimately resume from. For a hub that has
 * issued nothing, that is `0`.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { buildServer, type ServerDeps } from "../src/server.js";
import { ApiConfig, validateOrigins } from "../src/config.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { FakeOrchestrator } from "../mock/fake-orchestrator.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";

const ORIGIN = "https://microsoft-onenote-exporter.phttp.com";
const SECRET = "A".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

const config: ApiConfig = {
  allowedOrigins: validateOrigins(ORIGIN),
  csrfKey: "C".repeat(43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  publicOrigin: "https://one-backend.phttp.com",
  orchestratorUrl: "http://mock:9100",
  orchestratorSecret: "B".repeat(43),
  orchestratorReplayWindowSeconds: 60,
  logLevel: "silent",
  listen: "127.0.0.1:0",
  databasePath: ":memory:",
  sseBufferEvents: 500,
  sseKeepaliveMs: 15_000,
};

let db: Db;
let app: FastifyInstance;
let sse: SseHub;

beforeEach(async () => {
  db = new Db(":memory:");
  db.createSession({
    guid: GUID,
    secretHash: hashSecret(SECRET),
    csrfKey: generateCsrfKey(),
    now: Date.now(),
    expiresAt: Date.now() + 43_200_000,
  });
  sse = new SseHub({ now: () => Date.now() });
  const deps: ServerDeps = {
    db,
    sse,
    limiter: new RateLimiter({ logSalt: "t" }),
    orchestrator: new FakeOrchestrator({ size: 1 }),
  };
  app = buildServer(config, deps);
  await app.ready();
});

afterEach(async () => {
  await app.close();
  db.close();
});

function cookie(): string {
  return `${SESSION_COOKIE}=${GUID}:${SECRET}`;
}

/**
 * Opens the stream over a real socket and returns the first frame.
 *
 * `app.inject` waits for the response to *complete*, and an SSE stream does not
 * complete until it is closed — so inject hangs for the full timeout. A real
 * `fetch` with an AbortController reads the first frame as it arrives, which is
 * also what a browser does.
 */
async function firstFrame(headers: Record<string, string>): Promise<string> {
  const address = await app.listen({ host: "127.0.0.1", port: 0 });
  const controller = new AbortController();
  try {
    const response = await fetch(`${address}/api/session/events`, {
      headers,
      signal: controller.signal,
    });
    expect(response.status).toBe(200);
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let raw = "";
    // The snapshot is the first thing the route writes, so the first chunk that
    // carries a frame boundary is the frame.
    while (!raw.includes("\n\n")) {
      const { done, value } = await reader.read();
      if (done) break;
      raw += decoder.decode(value, { stream: true });
    }
    return raw;
  } finally {
    controller.abort();
    await app.close();
  }
}

/** The `id:` field of the first frame, or null when it has none. */
function frameId(frame: string): string | null {
  const match = /^id: (.*)$/m.exec(frame);
  return match === null ? null : match[1]!.trim();
}

describe("GET /api/session/events — the snapshot frame's id", () => {
  it("carries the last id issued, not the id the next event will take", async () => {
    // One event already issued, so the hub's next id is 2 and the last issued
    // one is 1. The snapshot must say 1.
    sse.emit(GUID, "auth-state", { state: "none" });

    const frame = await firstFrame({ origin: ORIGIN, cookie: cookie() });

    expect(frame).toContain("event: snapshot");
    expect(frameId(frame)).toBe("1");
  });

  it("carries 0 for a session that has issued nothing yet", async () => {
    // Nothing emitted: the next id is 1 and the last issued one is 0.
    const frame = await firstFrame({ origin: ORIGIN, cookie: cookie() });

    expect(frame).toContain("event: snapshot");
    expect(frameId(frame)).toBe("0");
  });

  it("does not share its id with the next event the hub issues", async () => {
    // The property the fix exists for: a client that disconnects after the
    // snapshot and before the first real event resumes from the snapshot's id
    // and must still receive that event.
    sse.emit(GUID, "auth-state", { state: "none" });

    const frame = await firstFrame({ origin: ORIGIN, cookie: cookie() });
    const snapshotId = frameId(frame);

    // The next event the hub issues takes the id the snapshot did not take.
    const next = sse.emit(GUID, "auth-state", { state: "valid" });

    expect(String(next.id)).not.toBe(snapshotId);
  });
});
