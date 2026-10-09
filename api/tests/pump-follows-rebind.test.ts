/**
 * A pump must follow the session to the runner it was rebound onto, and abandon
 * the one it left behind.
 *
 * ## The bug this reproduces, found on a live host
 *
 * 2026-10-09, session `cc915fdf`, on the deployed stack at `2deae28`:
 *
 * ```
 * 08:56:13  api     export published   session=cc915fdf  artifactId=pjJQR…  partial=false
 * 08:56:27  api     runner claimed   runner=slot-1  mode=rebind
 * 08:56:27  runner  POST /sessions/cc915fdf-…/exports  → 202
 * 08:57:58  runner  [SUCCESS] Export complete!  Total Pages: 1
 * ```
 *
 * The runner finished the export, in 91 seconds, and wrote the vault. The api's
 * row still read `export_state: running` an hour later, and `state` was still
 * `exporting` — so §0.9.9's "a sweeper check that an exporting session still has
 * a live runner" would have had nothing to heal: the runner *was* live, the export
 * *had* completed, and the api simply never heard about either.
 *
 * ## Why it is the pump and not the rebind
 *
 * `#pump` read the address **once**, before its retry loop:
 *
 * ```ts
 * const address = this.#addressFor(sessionId);   // runner-adapter-http.ts
 * while (!signal.aborted) { … fetch(`${address}/events?…`) … }
 * ```
 *
 * and `#ensurePump` returned early whenever a pump already existed. So the stream
 * stayed bound to whatever `runner_url` was when it opened, for the life of the
 * pump. `releaseForIdle` nulls `runner_id` without stopping the pump — it is a DB
 * statement, and the pump lives in the adapter — and #50's rebind then points the
 * session at a *different* slot. The next export's `export-done` is published by
 * the new runner, onto a stream nobody is reading.
 *
 * This is §1's ninth instance wearing a different hat: the pump ran, the rebind
 * ran, `/healthz` was 200 the whole time, and the export finished. Nothing
 * asserted that the component reading the events was pointed at the component
 * producing them.
 *
 * ## The three things this file asserts, and why each is here
 *
 * 1. **The runner that ran the export is the runner that was read.** The original
 *    symptom.
 * 2. **The old runner's connection is closed.** The half that is easy to leave
 *    out: re-pointing without aborting the previous pump fixes symptom 1 while
 *    leaking a stream against a container the session no longer owns — and one
 *    that may since have been handed to somebody else.
 * 3. **Only one stream exists per session.** Two live pumps deliver every event
 *    twice, which is what `#pumps` exists to prevent. This is the assertion that
 *    caught the first attempt at this fix.
 *
 * All three are read off **real sockets**. The fixture counts connections and
 * watches them close, because "did the callback fire" and "is the old stream gone"
 * are different questions and only one of them was being asked.
 */

import { createServer, type Server, type Socket } from "node:http";
import { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { HttpRunnerAdapter, type ExportFinishedInput } from "../src/runner-adapter-http.js";
import { SseHub } from "../src/sse.js";

const TOKEN = "runner-token-for-tests";
const SESSION = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

/**
 * A runner that answers `/events`, and tracks its own sockets.
 *
 * The socket tracking is the load-bearing part of this fixture. Asserting that the
 * completion callback ran proves a stream was read *somewhere*; it cannot tell
 * you whether the previous one was also still open. `openStreams` answers the
 * second question, and it is the only reason the leak is observable at all.
 */
class CountingRunner {
  readonly sse = new SseHub();
  /** How many times `/events` was opened on this runner. */
  eventStreamRequests = 0;
  #frames: string[] = [];
  /**
   * Sockets currently carrying an **event stream**.
   *
   * Deliberately not "all connections": `listNotebooks` also makes a short
   * `POST /sessions/…/notebooks` over the same keep-alive agent, and counting
   * that would report two connections for one stream. The question this fixture
   * exists to answer is whether the *pump* was torn down, so only `/events`
   * sockets are counted.
   */
  #eventSockets = new Set<Socket>();
  #server: Server | undefined;

  /** The frames this runner will send, once a stream opens. */
  set frames(value: string[]) {
    this.#frames = value;
  }

  /** Event streams this runner is currently holding open. */
  get openStreams(): number {
    return this.#eventSockets.size;
  }

  async listen(): Promise<void> {
    this.#server = createServer((request, response) => {
      if ((request.url ?? "").startsWith("/events")) {
        this.eventStreamRequests += 1;
        const socket = request.socket;
        this.#eventSockets.add(socket);
        socket.on("close", () => {
          this.#eventSockets.delete(socket);
        });
        response.writeHead(200, {
          "content-type": "text/event-stream",
          "cache-control": "no-cache",
        });
        for (const frame of this.#frames) response.write(frame);
        return; // left open, like a real stream
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{}");
    });
    await new Promise<void>((resolve) => {
      this.#server!.listen(0, "127.0.0.1", resolve);
    });
  }

  get aliasUrl(): string {
    const { port } = this.#server!.address() as AddressInfo;
    // The alias shape the adapter validates, with the real port behind it. The
    // hostname is rewritten to loopback by `fetchImpl` below, exactly as in
    // `runner-adapter-http.test.ts`, so the request still crosses a real socket.
    return `http://msout-runner-slot-${port}:${port}`;
  }

  async close(): Promise<void> {
    if (this.#server === undefined) return;
    // `close()` alone waits for every connection to end, and the event stream is
    // deliberately left open — so without this the server never finishes closing
    // and the test hangs in teardown rather than failing on an assertion.
    this.#server.closeAllConnections();
    await new Promise<void>((resolve) => {
      this.#server!.close(() => resolve());
    });
  }
}

const running: CountingRunner[] = [];

afterEach(async () => {
  for (const runner of running.splice(0)) await runner.close();
});

async function countingRunner(): Promise<CountingRunner> {
  const runner = new CountingRunner();
  await runner.listen();
  running.push(runner);
  return runner;
}

/** The frame a runner publishes when an export finishes. */
function exportDoneFrame(): string {
  return `id: 1\ndata: ${JSON.stringify({
    type: "export-done",
    id: "export-1",
    notebook: "MS is great",
    pages: 1,
    sections: 1,
    assets: 0,
  })}\n\n`;
}

/**
 * Waits for a condition, or gives up.
 *
 * A socket close is delivered by the event loop rather than synchronously with
 * the `abort()` that caused it, so the assertion has to give the loop a turn.
 * Failing the assertion after the wait is what makes this a check rather than a
 * sleep that happens to be long enough today.
 */
async function until(predicate: () => boolean, timeoutMs = 2_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return predicate();
}

describe("the event pump follows a session onto the runner it was rebound onto", () => {
  it("reads the new runner, closes the old stream, and keeps exactly one", async () => {
    const first = await countingRunner();
    const second = await countingRunner();
    const finished: ExportFinishedInput[] = [];

    // The address the api would report: slot-1 until the rebind, slot-2 after.
    // This is a variable on purpose — the bug is that the pump does not re-read it.
    let address = first.aliasUrl;

    const adapter = new HttpRunnerAdapter({
      addressFor: () => address,
      token: TOKEN,
      sse: second.sse,
      onExportFinished: (input) => {
        finished.push(input);
      },
      timeoutMs: 2_000,
      fetchImpl: (input: string | URL | Request, init?: RequestInit) => {
        const url = new URL(typeof input === "string" ? input : input.toString());
        if (url.hostname.startsWith("msout-runner-")) {
          // Both runners answer on loopback; the port is preserved, so the request
          // reaches whichever fixture is really listening there.
          url.hostname = "127.0.0.1";
        }
        return fetch(url, init);
      },
    });

    // The session signs in on slot-1: the pump opens there and stays there.
    first.frames = [];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();
    expect(first.eventStreamRequests).toBeGreaterThan(0);
    expect(first.openStreams).toBe(1);

    // The idle release nulls `runner_id`, and #50's rebind hands the session a
    // different runner. This is the state the deployed host was in.
    address = second.aliasUrl;

    // The second export runs on slot-2 and publishes `export-done` there.
    second.frames = [exportDoneFrame()];
    await adapter.startExport({
      sessionId: SESSION,
      exportId: "export-1",
      notebook: "MS is great",
      signal: new AbortController().signal,
    });
    await adapter.drain();

    // (1) The runner that *ran* the export is the runner that was *read*. Before
    // the fix the pump stayed on slot-1, answered nothing, and `finished` stayed
    // empty — which is precisely what the deployed host did for an hour.
    expect(second.eventStreamRequests).toBeGreaterThan(0);
    expect(finished).toHaveLength(1);
    expect(finished[0]).toMatchObject({ sessionId: SESSION, partial: false });

    // (2) The abandoned stream is **closed**, not merely forgotten. Re-pointing
    // without aborting satisfies (1) perfectly while leaking a connection against
    // a runner the session no longer owns.
    expect(await until(() => first.openStreams === 0)).toBe(true);

    // (3) Exactly one stream exists for this session. A further runner-facing call
    // must re-use the pump rather than open a second one; two live pumps deliver
    // every event twice, and this is the assertion that caught the first version
    // of the fix, which aborted nothing and so leaked rather than re-pointed.
    const streamsBefore = second.eventStreamRequests;
    await adapter.listNotebooks(SESSION);
    await adapter.drain();
    expect(second.eventStreamRequests).toBe(streamsBefore);

    // And the stream that survived is still the live one, not a zombie.
    expect(second.openStreams).toBe(1);

    adapter.stopAll();
    expect(await until(() => second.openStreams === 0)).toBe(true);
  });

  it("leaves a live pump alone when the session has no runner yet", async () => {
    // The sweeper's release nulls `runner_id` and does **not** stop the pump, so
    // `#addressFor` can answer null while a working stream is still delivering.
    // Treating that as licence to tear the stream down would destroy a stream
    // that may be one frame from `export-done` — a fresh instance of the bug this
    // file exists to prevent. The route's `#call` answers `no-address` instead.
    const runner = await countingRunner();
    const finished: ExportFinishedInput[] = [];
    let address: string | null = runner.aliasUrl;

    const adapter = new HttpRunnerAdapter({
      addressFor: () => address,
      token: TOKEN,
      sse: runner.sse,
      onExportFinished: (input) => {
        finished.push(input);
      },
      timeoutMs: 2_000,
      fetchImpl: (input: string | URL | Request, init?: RequestInit) => {
        const url = new URL(typeof input === "string" ? input : input.toString());
        if (url.hostname.startsWith("msout-runner-")) url.hostname = "127.0.0.1";
        return fetch(url, init);
      },
    });

    runner.frames = [];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();
    expect(runner.eventStreamRequests).toBe(1);

    // Released: the session has no runner, but its stream is still live. The call
    // itself is refused — that is `#call`'s `no-address`, unchanged by this fix.
    address = null;
    await expect(adapter.listNotebooks(SESSION)).rejects.toThrow(/address/i);

    // The null did not open a replacement stream, and did not tear the live one
    // down. Asserted on the *request count* rather than on socket liveness,
    // because a close is delivered by the event loop and a liveness assertion here
    // would pass for the wrong reason — an aborted socket has not closed yet at
    // the instant the assertion runs, so the check would hold either way.
    expect(runner.eventStreamRequests).toBe(1);

    // The decisive one: re-bind the same address and touch the runner again. A
    // pump that survived is re-used and the count stays 1; one that was torn down
    // on the null has to open a second stream, and the count becomes 2.
    address = runner.aliasUrl;
    await adapter.listNotebooks(SESSION);
    await adapter.drain();
    expect(runner.eventStreamRequests).toBe(1);

    adapter.stopAll();
    expect(await until(() => runner.openStreams === 0)).toBe(true);
  });
});