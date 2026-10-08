/**
 * The api → runner adapter, driven over a real socket.
 *
 * ## The shape of these tests
 *
 * Every one of them starts a real HTTP server standing in for a runner, and every
 * one asserts on **the bytes that arrived at it**. Not on the adapter's return
 * value, and not on the event the api published.
 *
 * That is not a stylistic preference. The bug this project shipped twice — a
 * frontend that JSON-encoded the password, and a `capStream` that ended a body
 * before it began — both presented identically to every test written against the
 * handler: the route answered 202, `login-started` fired, and the credential was
 * wrong. Only the far side could tell. See §1 of the plan this repository sits
 * beside.
 *
 * So: `readBody` here returns the raw request body, and the interesting assertion
 * is `expect(received.equals(expected)).toBe(true)`.
 *
 * ## What is a genuine control rather than a default
 *
 * - The token is required. A missing or wrong one is a 401 and no bytes are read,
 *   and there is no way to configure the adapter without one.
 * - The address must match the alias shape. A `runnerUrl` that does not is refused
 *   before a connection is attempted, so a misconfigured or tampered value cannot
 *   receive a password.
 * - The account travels as a header. The body is the credential and only the
 *   credential.

 */

import { EventEmitter } from "node:events";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { AddressInfo } from "node:net";
import { Readable } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HttpRunnerAdapter, RunnerCallError, unsupportedChallenge } from "../src/runner-adapter-http.js";
import { SseHub } from "../src/sse.js";

const TOKEN = "runner-token-for-tests";
const SESSION = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const ACCOUNT = "someone@example.com";

/** One request as the fake runner saw it. */
interface Seen {
  readonly method: string;
  readonly url: string;
  readonly token: string | undefined;
  readonly account: string | undefined;
  readonly contentType: string | undefined;
  readonly body: Buffer;
}

/** A stand-in runner that records what arrived. */
class FakeRunner {
  /** Data requests — the four verbs. */
  readonly seen: Seen[] = [];
  /** Event-stream connections, recorded apart from the verbs. */
  readonly eventStreams: Seen[] = [];
  readonly server: Server;
  #port = 0;
  #status = 202;
  #responseBody: Record<string, unknown> = { accepted: true };
  /** Frames pushed on the event stream, in order. */
  sseFrames: string[] = [];
  /** Events the api published, read back out of the hub. */
  readonly sse = new SseHub();

  constructor() {
    this.server = createServer((request, response) => {
      void this.#handle(request, response);
    });
  }

  async listen(): Promise<number> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    this.#port = (this.server.address() as AddressInfo).port;
    return this.#port;
  }

  async close(): Promise<void> {
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  /** The address the adapter is given — the alias, with this runner's port. */
  get aliasUrl(): string {
    return `http://msout-runner-slot-1:${this.#port}`;
  }

  /** status sets what the next request answers. */
  answerWith(status: number, body: Record<string, unknown> = { accepted: true }): void {
    this.#status = status;
    this.#responseBody = body;
  }

  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk as Buffer));

    const seen: Seen = {
      method: request.method ?? "",
      url: request.url ?? "",
      token: request.headers["x-runner-token"] as string | undefined,
      account: request.headers["x-microsoft-account"] as string | undefined,
      contentType: request.headers["content-type"] as string | undefined,
      body: Buffer.concat(chunks),
    };

    if ((request.url ?? "").startsWith("/events")) {
      // Recorded apart from the data requests. The event stream is a real request
      // the adapter makes, but folding it into `seen` would make "the credential
      // route was called exactly once" untestable — and it would hide whether the
      // pump opened at all, which is its own thing worth asserting.
      this.eventStreams.push(seen);
      response.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
      });
      for (const frame of this.sseFrames) response.write(frame);
      // Left open, like a real stream. The test ends it by closing the adapter.
      return;
    }

    this.seen.push(seen);

    const payload = JSON.stringify(this.#responseBody);
    response.writeHead(this.#status, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(payload),
    });
    response.end(payload);
  }
}

const running: FakeRunner[] = [];

afterEach(async () => {
  for (const runner of running.splice(0)) await runner.close();
});

async function fakeRunner(): Promise<FakeRunner> {
  const runner = new FakeRunner();
  await runner.listen();
  running.push(runner);
  return runner;
}

/**
 * An adapter pointed at the fake runner.
 *
 * ## Why `fetchImpl` is wrapped rather than the runner's address rewritten
 *
 * The address the adapter is given is a Docker network alias,
 * `msout-runner-slot-1`, which only resolves inside the runner network — Docker's
 * embedded DNS, not this machine's. So the fetch is wrapped to send the alias's
 * host to `127.0.0.1` and leave **everything else alone**: the path, the method,
 * the headers, and above all the body.
 *
 * That is the narrowest possible substitution, and it is narrow on purpose. The
 * assertions in this file are about bytes and paths, so a mock `fetch` would make
 * every one of them vacuous — a test that checks the adapter would only be checking
 * that it called itself. Rewriting one hostname keeps the request real: it goes
 * over a socket, Node serialises the body, and the fake runner reads the bytes
 * that would have arrived in production.
 */
function adapterFor(
  runner: FakeRunner,
  overrides: { addressFor?: (id: string) => string | null } = {},
): HttpRunnerAdapter {
  return new HttpRunnerAdapter({
    addressFor: overrides.addressFor ?? (() => runner.aliasUrl),
    token: TOKEN,
    sse: runner.sse,
    timeoutMs: 2_000,
    fetchImpl: (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      if (url.hostname.startsWith("msout-runner-")) {
        url.hostname = "127.0.0.1";
      }
      return fetch(url, init);
    },
  });
}

/** A stream carrying exactly these bytes. */
function byteStream(text: string): Readable {
  return Readable.from([Buffer.from(text, "utf8")]);
}

/**
 * A response stand-in that records what the hub wrote.
 *
 * Reading the hub through its **public** surface rather than its `#hubs` map:
 * attaching a subscriber and parsing the frames is what a browser does, so the
 * assertion is about bytes on the wire rather than about an internal collection.
 */
function fakeResponse(): ServerResponse & { written: string[] } {
  const written: string[] = [];
  const res = new EventEmitter() as unknown as ServerResponse & { written: string[] };
  res.written = written;
  res.write = ((chunk: string) => {
    written.push(String(chunk));
    return true;
  }) as ServerResponse["write"];
  res.end = (() => {
    res.emit("close");
    return res;
  }) as ServerResponse["end"];
  res.writeHead = (() => res) as ServerResponse["writeHead"];
  return res;
}

/** The frames a subscriber received, parsed. */
function framesFrom(res: { written: string[] }): readonly {
  type: string;
  data: unknown;
}[] {
  return res.written
    .join("")
    .split("\n\n")
    .filter((frame) => frame.trim() !== "" && !frame.startsWith(":"))
    .map((frame) => {
      const out: { type: string; data: unknown } = { type: "", data: null };
      for (const line of frame.split("\n")) {
        if (line.startsWith("event: ")) out.type = line.slice("event: ".length);
        else if (line.startsWith("data: ")) {
          try {
            out.data = JSON.parse(line.slice("data: ".length)) as unknown;
          } catch {
            out.data = line.slice("data: ".length);
          }
        }
      }
      return out;
    });
}

/**
 * Subscribes to a session and waits until at least `count` frames have arrived.
 *
 * The subscription is made *before* the adapter is called, which is why this
 * returns a handle rather than an array: the caller needs the same response object
 * afterwards.
 */
function subscribe(sse: SseHub): {
  res: ReturnType<typeof fakeResponse>;
  received: (count?: number) => Promise<readonly { type: string; data: unknown }[]>;
} {
  const res = fakeResponse();
  sse.attach(SESSION, res, null);
  return {
    res,
    received: async (count = 1) => {
      for (let attempt = 0; attempt < 200; attempt++) {
        const frames = framesFrom(res);
        if (frames.length >= count) return frames;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      return framesFrom(res);
    },
  };
}

// ---------------------------------------------------------------------------

describe("the credential arrives at the runner byte-for-byte", () => {
  /** The cases, borrowed from the verbatim test so the two cannot drift. */
  const cases: ReadonlyArray<readonly [string, string]> = [
    ["a plain password", "hunter2"],
    ["double quotes", 'pass"word'],
    ["single quotes", "pass'word"],
    ["a backslash", "pass\\word"],
    ["a JSON-looking string", '{"password":"hunter2"}'],
    ["a backslash-escaped quote", 'pa\\"ss'],
    ["a leading space", " hunter2"],
    ["a trailing space", "hunter2 "],
    ["both", " hunter2 "],
    ["a trailing tab", "hunter2\t"],
    ["a trailing newline", "hunter2\n"],
    ["a trailing CRLF", "hunter2\r\n"],
    ["only whitespace", "   "],
    ["non-ASCII", "pässwörd-Ω-日本"],
    ["an emoji", "pw🔑🔒"],
    ["an embedded NUL", "hunter2\u0000evil"],
    ["an embedded newline", "hunter2\nevil"],
    ["a single character", "x"],
    ["the maximum length", "A".repeat(4096)],
  ];

  for (const [name, password] of cases) {
    it(`sends ${name} unmodified`, async () => {
      const runner = await fakeRunner();
      const adapter = adapterFor(runner);

      await adapter.submitCredential({
        sessionId: SESSION,
        account: ACCOUNT,
        stream: byteStream(password),
        correlationId: "corr",
      });

      expect(runner.seen).toHaveLength(1);
      const got = runner.seen[0]!;
      // The whole assertion: equal buffers.
      expect(got.body.equals(Buffer.from(password, "utf8"))).toBe(true);
      expect(got.body.length).toBe(Buffer.byteLength(password, "utf8"));
      // And the account is not in it, because it travels as a header.
      expect(got.account).toBe(ACCOUNT);
      expect(got.body.toString("utf8")).not.toContain(ACCOUNT);
    });
  }

  it("does not JSON-encode a password that looks like JSON", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);
    const password = '{"password":"hunter2"}';

    await adapter.submitCredential({
      sessionId: SESSION,
      account: ACCOUNT,
      stream: byteStream(password),
      correlationId: "corr",
    });

    // The specific regression: these bytes come back, not `password=hunter2`.
    expect(runner.seen[0]!.body.toString("utf8")).toBe(password);
    expect(runner.seen[0]!.body.includes("password=hunter2")).toBe(false);
  });

  it("keeps the byte count exact, so length is not silently adjusted", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);
    // 4096 bytes is allowed by the api's cap. A padding byte must not appear.
    const password = "A".repeat(4096);

    await adapter.submitCredential({
      sessionId: SESSION,
      account: ACCOUNT,
      stream: byteStream(password),
      correlationId: "corr",
    });

    expect(runner.seen[0]!.body.length).toBe(4096);
  });
});

describe("the address", () => {
  it("is the one the orchestrator reported, and never constructed here", async () => {
    const runner = await fakeRunner();
    // A lookup that returns a deliberately different alias than the runner's own
    // port would prove the adapter dialed what it was told. Two servers, one
    // called: if the adapter built its own address it would have hit the wrong
    // port.
    const adapter = adapterFor(runner, { addressFor: () => runner.aliasUrl });

    await adapter.submitCredential({
      sessionId: SESSION,
      account: ACCOUNT,
      stream: byteStream("hunter2"),
      correlationId: "corr",
    });

    expect(runner.seen).toHaveLength(1);
  });

  it("refuses an address that is not this stack's own runner", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    for (const bad of [
      "http://evil.example.com:3100",
      "http://msout-runner-slot-1:3100@evil.example.com",
      // A path in the URL would let a caller aim a *different* route.
      "http://msout-runner-slot-1:3100/../../admin",
      // https is not what the runner serves, and accepting it would mean a
      // downgrade decision made silently.
      "https://msout-runner-slot-1:3100",
      // No port: would resolve to 80.
      "http://msout-runner-slot-1",
      "not a url at all",
      "",
    ]) {
      const failing = adapterFor(runner, { addressFor: () => bad });
      await expect(
        failing.submitCredential({
          sessionId: SESSION,
          account: ACCOUNT,
          stream: byteStream("hunter2"),
          correlationId: "corr",
        }),
      ).rejects.toThrow(/address/i);
    }

    // No request reached the runner from any of those.
    expect(runner.seen).toHaveLength(0);
  });

  it("reports no address as its own failure, not a connection error", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner, { addressFor: () => null });

    const error = await adapter
      .submitCredential({
        sessionId: SESSION,
        account: ACCOUNT,
        stream: byteStream("hunter2"),
        correlationId: "corr",
      })
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(RunnerCallError);
    expect((error as RunnerCallError).failure).toBe("no-address");
  });
});

describe("the token is required, and it is a control", () => {
  it("is presented on every route but none without it is honoured", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    await adapter.submitCredential({
      sessionId: SESSION,
      account: ACCOUNT,
      stream: byteStream("hunter2"),
      correlationId: "corr",
    });

    expect(runner.seen[0]!.token).toBe(TOKEN);
  });

  it("surfaces a 401 as unauthorised rather than a login failure", async () => {
    const runner = await fakeRunner();
    runner.answerWith(401, { error: "unauthorised" });
    const adapter = adapterFor(runner);

    const error = await adapter
      .listNotebooks(SESSION)
      .catch((e: unknown) => e);

    expect((error as RunnerCallError).failure).toBe("unauthorised");
  });
});

describe("runner events reach the api's own vocabulary", () => {
  it("republishes a number-match challenge with its number", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "challenge",
        kind: "phone-approval",
        label: "Tap approve in your phone",
        number: "42 918 337",
        expiresAt: "2026-10-07T12:05:00.000Z",
      })}\n\n`,
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    const events = await sub.received();

    const challenge = events.find((e) => e.type === "challenge");
    // The number is the point: a headless login has no Microsoft window to read it
    // from, so if it does not arrive the user cannot complete MFA at all.
    expect((challenge?.data as { number?: string }).number).toBe("42 918 337");
    expect((challenge?.data as { kind?: string }).kind).toBe("phone-approval");
  });

  it("names a code challenge as unsupported instead of letting it expire", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "challenge",
        kind: "code",
        label: "Enter the code we sent you",
        number: null,
        expiresAt: null,
      })}\n\n`,
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    const events = await sub.received();

    const failed = events.find((e) => e.type === "login-failed");
    expect((failed?.data as { reason?: string }).reason).toBe("challenge-not-supported");
    // The message names the gap rather than saying "sign-in failed", which for an
    // account that works everywhere else is the most confusing thing to say.
    expect((failed?.data as { message?: string }).message).toBe(unsupportedChallenge);
    expect(unsupportedChallenge).toMatch(/code/i);
    expect(unsupportedChallenge).toMatch(/approve/i);
  });

  it("carries an export's progress through with its counts", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "export-progress",
        id: "artifact-id",
        progress: { pages: 12, sections: 3, assets: 40 },
      })}\n\n`,
      `id: 2\ndata: ${JSON.stringify({
        type: "export-done",
        id: "artifact-id",
        notebook: "Notebook",
        pages: 20,
        sections: 7,
        assets: 55,
      })}\n\n`,
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    const events = await sub.received(2);

    const progress = events.find((e) => e.type === "export-progress");
    expect(progress?.data).toMatchObject({
      id: "artifact-id",
      progress: { pages: 12, sections: 3, assets: 40 },
    });
    const done = events.find((e) => e.type === "export-done");
    expect(done?.data).toMatchObject({ id: "artifact-id", pages: 20, sections: 7 });
  });

  it("forwards a replay gap rather than hiding it", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "error",
        message: "gap: some events were discarded",
      })}\n\n`,
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    const events = await sub.received();

    const error = events.find((e) => e.type === "error");
    expect((error?.data as { message?: string }).message).toMatch(/gap/);
  });

  it("drops an event whose shape does not match, rather than passing it on", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({ type: "not-a-real-event", anything: 1 })}\n\n`,
      // A frame that is not JSON at all.
      `id: 2\ndata: {not json\n\n`,
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    const events = await sub.received();

    // The malformed frame is reported. The unknown type is dropped: forwarding it
    // would put a name on the wire that no frontend has a renderer for.
    expect(events.some((e) => e.type === "not-a-real-event")).toBe(false);
    expect(events.some((e) => (e.data as { message?: string }).message === "unreadable runner event")).toBe(
      true,
    );
  });

  it("emits login-started exactly once, from the route and not the runner", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.sseFrames = [`id: 1\ndata: ${JSON.stringify({ type: "login-started" })}\n\n`];

    const sub = subscribe(runner.sse);
    await adapter.submitCredential({
      sessionId: SESSION,
      account: ACCOUNT,
      stream: byteStream("hunter2"),
      correlationId: "corr",
    });
    const events = await sub.received();

    // Two of them would tell a browser a login began twice.
    expect(events.filter((e) => e.type === "login-started")).toHaveLength(0);
  });

  it("reads a frame split across two reads as one frame", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    // Deliberately split mid-JSON, which is what a TCP boundary does to a frame.
    const whole = `id: 1\ndata: ${JSON.stringify({ type: "login-success" })}\n\n`;
    runner.sseFrames = [whole.slice(0, 20), whole.slice(20)];

    const sub = subscribe(runner.sse);
    await adapter.submitCredential({
      sessionId: SESSION,
      account: ACCOUNT,
      stream: byteStream("hunter2"),
      correlationId: "corr",
    });
    const events = await sub.received();

    // A partial frame treated as complete would fail to parse and report
    // "unreadable runner event" instead.
    expect(events.some((e) => e.type === "login-success")).toBe(true);
    expect(events.some((e) => (e.data as { message?: string }).message?.includes("unreadable"))).toBe(
      false,
    );
  });
});

describe("the other three verbs", () => {
  it("lists notebooks on the session's own route", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    await adapter.listNotebooks(SESSION);

    expect(runner.seen[0]!.method).toBe("POST");
    expect(runner.seen[0]!.url).toBe(`/sessions/${SESSION}/notebooks`);
  });

  it("sends one export target, never both", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    await adapter.startExport({
      sessionId: SESSION,
      exportId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      notebook: "Notebook",
      signal: new AbortController().signal,
    });

    const body = JSON.parse(runner.seen[0]!.body.toString("utf8")) as Record<string, unknown>;
    expect(body.id).toBe("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(body.notebook).toBe("Notebook");
    // Both present would leave the runner to pick, and it would be a caller
    // relying on which one it picked.
    expect(body.notebookUrl).toBeUndefined();
  });

  it("prefers the notebook URL over the name when both are known", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    await adapter.startExport({
      sessionId: SESSION,
      exportId: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      notebook: "Renamed Since Listing",
      notebookUrl: "https://onenote.example/1-A/stable",
      signal: new AbortController().signal,
    });

    const body = JSON.parse(runner.seen[0]!.body.toString("utf8")) as Record<string, unknown>;
    expect(body.notebookUrl).toBe("https://onenote.example/1-A/stable");
    expect(body.notebook).toBeUndefined();
  });

  it("aborts a named export", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    await adapter.abortExport({ sessionId: SESSION, exportId: "abc123" });

    expect(runner.seen[0]!.url).toBe(`/sessions/${SESSION}/exports/abc123/abort`);
  });

  it("removes a session directory through DELETE", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    await adapter.removeSessionDir(SESSION);

    expect(runner.seen[0]!.method).toBe("DELETE");
    expect(runner.seen[0]!.url).toBe(`/sessions/${SESSION}`);
  });
});

describe("a busy runner is distinguishable from an unreachable one", () => {
  it("reports busy separately from a transport failure", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.answerWith(409, { error: "busy" });
    const busy = await adapter.listNotebooks(SESSION).catch((e: unknown) => e);
    expect((busy as RunnerCallError).failure).toBe("busy");

    runner.answerWith(409, { error: "no_auth" });
    const noAuth = await adapter.listNotebooks(SESSION).catch((e: unknown) => e);
    expect((noAuth as RunnerCallError).failure).toEqual({
      kind: "not-ready",
      reason: "no_auth",
    });
  });

  it("treats a 409 from abort as done, because there was nothing to stop", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.answerWith(409, { error: "no export running" });
    // The erase machine calls abort while an export may or may not exist. A
    // refusal here means it was not running, which is what erase wanted.
    await expect(adapter.abortAny(SESSION)).resolves.toBeUndefined();
  });
});

describe("the event pump", () => {
  it("stops when told, and does not reconnect to a runner that is gone", async () => {
    const runner = await fakeRunner();
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const adapter = adapterFor(runner);

    const sub = subscribe(runner.sse);
    await adapter.submitCredential({
      sessionId: SESSION,
      account: ACCOUNT,
      stream: byteStream("hunter2"),
      correlationId: "corr",
    });
    await sub.received();

    const before = fetchSpy.mock.calls.length;
    adapter.stopPump(SESSION);
    // Long enough for a reconnect to have happened several times over.
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(fetchSpy.mock.calls.length).toBe(before);

    fetchSpy.mockRestore();
    adapter.stopAll();
  });
});
// ---------------------------------------------------------------------------
// The notebook list, as published.
//
// Found by clicking the button. Every step worked —
//
//     api    POST /api/session/notebooks  →  202        (four times)
//     runner [SUCCESS] Found 3 notebooks!
//     runner [DEBUG]  3 of 3 notebooks resolved to a link.
//     user   "clicking List my notebooks has no effect"
//
// — and the result never arrived in a shape anything could read.
//
// The api published `{notebooks: [{name, url}, …]}`. The client reads
// `{state, items: string[]}` (its `parseNotebooks`), which is the shape the api
// **already** publishes for this field on `GET /api/session/status` via
// `notebooksFor()`. So three notebooks were parsed into an empty list: no error, no
// warning, no failed request. Two versions of one field is not a contract, and the
// event stream was the deviant.
//
// These assertions are on the **bytes that arrived at a subscriber**, which is the
// same rule the rest of this file follows and the only one that can catch a shape
// mismatch.

describe("the notebook list, as published", () => {
  /**
   * The client's parser, mirrored.
   *
   * `parseNotebooks` in the frontend's `App.tsx`. Copied rather than imported —
   * two repositories, two build outputs — and the copy is the point: it fails when
   * the published shape and the consumed shape disagree, which is the bug. Named
   * precisely so a future edit knows which file to re-check.
   */
  function clientParseNotebooks(data: unknown): { state: string; items: string[] } {
    if (typeof data !== "object" || data === null) return { state: "loaded", items: [] };
    const raw = data as Record<string, unknown>;
    const state = raw.state;
    return {
      state:
        state === "idle" || state === "listing" || state === "loaded" || state === "failed"
          ? state
          : "loaded",
      items: Array.isArray(raw.items)
        ? (raw.items as unknown[]).filter((i): i is string => typeof i === "string")
        : [],
    };
  }

  async function published(payload: {
    notebooks: ReadonlyArray<Record<string, unknown>>;
  }): Promise<unknown> {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);
    // The runner's real wire frame, per `formatSse` in `runner/src/events.ts`.
    runner.sseFrames = [`id: 1\ndata: ${JSON.stringify({ type: "notebooks-listed", ...payload })}\n\n`];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    const events = await sub.received();
    adapter.stopAll();

    const listed = events.find((e) => e.type === "notebooks-listed");
    if (listed === undefined) throw new Error("no notebooks-listed event reached a subscriber");
    return listed.data;
  }

  it("is the shape the client parses, not a second shape", async () => {
    const data = await published({
      notebooks: [
        { name: "Work", url: "https://onenote.cloud.microsoft/notebooks/1" },
        { name: "Personal", url: "https://onenote.cloud.microsoft/notebooks/2" },
        { name: "Research", url: "https://onenote.cloud.microsoft/notebooks/3" },
      ],
    });

    // Stated first, so a shape change is a visible diff rather than a silently
    // different object.
    expect(data).toEqual({ state: "loaded", items: ["Work", "Personal", "Research"] });
  });

  // The bug in one assertion: before the fix this payload was `{notebooks: [...]}` and
  // the mirror returned three notebooks' worth of nothing.
  it("survives the client's own parser", async () => {
    const data = await published({ notebooks: [{ name: "Work", url: "x" }] });

    expect(clientParseNotebooks(data).items).toEqual(["Work"]);
  });

  it("does not emit a `notebooks` key at all", async () => {
    // Named explicitly because its absence *is* the fix: an edit that added the old
    // key back beside the new one would pass every other test here.
    const data = await published({ notebooks: [{ name: "Work", url: "x" }] });

    expect(Object.keys(data as object).sort()).toEqual(["items", "state"]);
  });

  it("carries names, because export is asked for a name", async () => {
    // `POST /api/export` takes `{notebook: string}`, and the client's
    // `NotebookList.items` is `string[]`. A list of objects would parse into an
    // empty `items` and offer nothing selectable.
    const data = await published({ notebooks: [{ name: "Work", url: "x" }] });

    expect(clientParseNotebooks(data).items.every((i) => typeof i === "string")).toBe(true);
  });

  it("drops a nameless notebook rather than rendering a blank row", async () => {
    const data = await published({
      notebooks: [{ name: "   ", url: "x" }, { name: "Work", url: "y" }],
    });

    expect(clientParseNotebooks(data).items).toEqual(["Work"]);
  });

  it("trims a name, so what is shown is what is sent", async () => {
    const data = await published({ notebooks: [{ name: "  Work  ", url: "x" }] });

    expect(clientParseNotebooks(data).items).toEqual(["Work"]);
  });

  it("is an empty list, not a malformed one, when the runner reports none", async () => {
    const data = await published({ notebooks: [] });

    // A real list of none, which the picker can render — as against a shape it
    // cannot read at all, which is what it used to be.
    expect(data).toEqual({ state: "loaded", items: [] });
  });
});
