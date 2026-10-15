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

import { Db } from "../src/db.js";
import { completeExport, type ExportCompletionDeps } from "../src/export-completion.js";
import { hashSecret } from "../src/session.js";
import {
  HttpRunnerAdapter,
  RunnerCallError,
  type ExportFinishedInput,
} from "../src/runner-adapter-http.js";
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
  overrides: {
    addressFor?: (id: string) => string | null;
    /** Stand-in for `index.ts`'s `db.setNotebooks` wiring. */
    onNotebooksListed?: (sessionId: string, names: readonly string[]) => void;
    /** Stand-in for `index.ts`'s progress writer. */
    onExportProgress?: (
      sessionId: string,
      id: string,
      progress: { pages: number; sections: number; assets: number },
    ) => void;
    /** Stand-in for `index.ts`'s `completeExport` wiring. */
    onExportFinished?: (input: ExportFinishedInput) => Promise<void> | void;
    now?: () => number;
  } = {},
): HttpRunnerAdapter {
  return new HttpRunnerAdapter({
    addressFor: overrides.addressFor ?? (() => runner.aliasUrl),
    token: TOKEN,
    sse: runner.sse,
    ...(overrides.onNotebooksListed === undefined
      ? {}
      : { onNotebooksListed: overrides.onNotebooksListed }),
    ...(overrides.onExportProgress === undefined
      ? {}
      : { onExportProgress: overrides.onExportProgress }),
    ...(overrides.onExportFinished === undefined
      ? {}
      : { onExportFinished: overrides.onExportFinished }),
    ...(overrides.now === undefined ? {} : { now: overrides.now }),
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

  it("carries a code challenge instead of failing the login", async () => {
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

    // Carried. This used to emit `login-failed {reason: "challenge-not-supported"}`
    // instead — which told a user with a working password that their sign-in had
    // failed, at the exact moment the runner was waiting for the code in their hand.
    const challenge = events.find((e) => e.type === "challenge");
    expect((challenge?.data as { kind?: string }).kind).toBe("code");
    expect((challenge?.data as { label?: string }).label).toBe("Enter the code we sent you");

    // And no failure is invented. A `login-failed` here would also call
    // `onAuthOutcome("failed")` in production, marking the session's auth state
    // refused while the login it belongs to is still waiting.
    expect(events.find((e) => e.type === "login-failed")).toBeUndefined();
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

  it("carries a listing's log line through, with its level", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "listing-log",
        line: "Network idle timeout - continuing anyway...",
        level: "warn",
      })}\n\n`,
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    const events = await sub.received();

    // The whole point of the level. Both warnings this listing can emit are ones
    // it continues past anyway, so without the level the frame says nothing a
    // client could act on and the two cases read identically.
    const log = events.find((e) => e.type === "listing-log");
    expect(log?.data).toEqual({
      line: "Network idle timeout - continuing anyway...",
      level: "warn",
    });
  });

  it("files a listing's line under no export, and invents no id for it", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "listing-log",
        line: "Found 3 notebooks!",
        level: "info",
      })}\n\n`,
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    const events = await sub.received();

    // **Not an `export-log` with a missing id.** `export-log` carries the artifact
    // id that tells two lines apart; a listing has no artifact, so a blank id
    // would file this line under an export the session never started.
    expect(events.map((e) => e.type)).toEqual(["listing-log"]);
    expect(events[0]?.data).not.toHaveProperty("id");
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

  it("hands an MFA code to the runner on the session's own route", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    await adapter.answerChallenge(SESSION, "123456");

    // The far side is the assertion. A method that built the right URL and dropped
    // the value on the floor would pass every assertion about the request's shape.
    expect(runner.seen[0]!.method).toBe("POST");
    expect(runner.seen[0]!.url).toBe(`/sessions/${SESSION}/mfa`);
    expect(runner.seen[0]!.contentType).toContain("application/json");
    const body = JSON.parse(runner.seen[0]!.body.toString("utf8")) as Record<string, unknown>;
    expect(body).toEqual({ code: "123456" });
    // The token is the control on this route too, and it is why the assertion is on
    // the request that arrived rather than on the call that was made.
    expect(runner.seen[0]!.token).toBe(TOKEN);
  });

  it("reports a runner with no prompt pending, rather than a silent success", async () => {
    // The runner answers 409 when nothing is waiting — the challenge expired, or it
    // was a push approval that needs no code. Resolving here would tell the user
    // "we are still waiting for your code" when the wait is over.
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.answerWith(409, { error: "no challenge is waiting for a code" });
    const error = await adapter.answerChallenge(SESSION, "123456").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(RunnerCallError);
    expect(((error as RunnerCallError).failure as { kind: string }).kind).toBe(
      "not-ready",
    );
  });

  it("sends no challenge event of its own, because the api publishes that", async () => {
    // `challenge-seen` is the api's event, emitted by `routes.ts`. An adapter that
    // emitted it as well would give the browser two of them — the same duplication
    // `login-started` already had a comment about, and one no route-level test would
    // see because they drive a fake adapter.
    //
    // Settled rather than read immediately: `received(0)` returns on the first call,
    // so asserting against it before the call settles would pass for the wrong
    // reason.
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    const sub = subscribe(runner.sse);
    await adapter.answerChallenge(SESSION, "123456");
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(framesFrom(sub.res)).toEqual([]);
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

// ---------------------------------------------------------------------------
// The notebook list has to survive a status refresh.
//
// The shape fix (#38) made the list *readable*. It did not make it **durable**: the
// names reached the browser only on the event stream, while the client rebuilds its
// whole state from `GET /api/session/status` — on page load, and again on
// `login-success`, `session-status`, `auth-state` and `snapshot`. That route read
// `session.notebook`, one notebook recorded per export, so every refresh replaced three
// notebooks with `[]` and a reload lost them for good.
//
// So these assert the durable half: the names are on the session row, and the REST
// route — the one the client actually trusts — hands them back.

describe("the notebook list is persisted, not just published", () => {
  /** The secret the test presents, and the only session it will authenticate. */
  const SECRET = "S".repeat(43);

  /** A session with no notebooks recorded yet. */
  function seededDb(): Db {
    const db = new Db(":memory:");
    db.createSession({
      guid: SESSION,
      // The real hash, because the status route authenticates by comparing the
      // presented secret against this column. A placeholder would answer 401 and the
      // test would be asserting on an authorisation failure.
      secretHash: hashSecret(SECRET),
      csrfKey: "C".repeat(43),
      now: Date.now(),
      expiresAt: Date.now() + 3_600_000,
    });
    return db;
  }

  /** `GET /api/session/status`, read as a client would. */
  async function statusRoute(db: Db): Promise<Record<string, unknown>> {
    const { buildServer } = await import("../src/server.js");
    const { SseHub } = await import("../src/sse.js");
    const { SESSION_COOKIE } = await import("../src/csrf.js");
    const { RateLimiter } = await import("../src/rate-limit.js");

    const app = buildServer(
      {
        allowedOrigins: new Set(["https://one.example.com"]),
        csrfKey: "C".repeat(43),
        sessionTtlHours: 12,
        minFreeDiskMb: 2048,
        publicOrigin: "https://one-backend.example.com",
        orchestratorUrl: "http://orchestrator:9100",
        orchestratorSecret: "B".repeat(43),
        orchestratorReplayWindowSeconds: 60,
        logLevel: "silent",
        listen: "127.0.0.1:0",
        databasePath: ":memory:",
        sseBufferEvents: 10,
        sseKeepaliveMs: 60_000,
        runnerToken: "R".repeat(43),
      } as never,
      {
        db,
        sse: new SseHub({ bufferEvents: 10, keepaliveMs: 60_000 }),
        limiter: new RateLimiter(),
        orchestrator: { healthz: async () => ({ ok: true, value: {} }) } as never,
      } as never,
    );
    await app.ready();
    try {
      const response = await app.inject({
        method: "GET",
        url: "/api/session/status",
        headers: {
          origin: "https://one.example.com",
          cookie: `${SESSION_COOKIE}=${SESSION}:${SECRET}`,
        },
      });
      expect(response.statusCode).toBe(200);
      return response.json() as Record<string, unknown>;
    } finally {
      await app.close();
    }
  }

  // **What this does not cover, stated rather than implied:** the adapter's
  // `onNotebooksListed` option is supplied *here*, so this proves the adapter calls it
  // and `Db.setNotebooks` stores the names. It does **not** prove `index.ts` wires the
  // two together — a test cannot, because the adapter is built inside `boot` with a real
  // fetch and there is no runner to publish an event in a unit test. That link is held
  // by the type checker (the option name and signature have to match) and by a
  // deployment. Asserting it here would be a test that cannot fail, which is worse than
  // the gap it hides.
  it("writes the names onto the session row when a listing arrives", async () => {
    const db = new Db(":memory:");
    db.createSession({
      guid: SESSION,
      secretHash: hashSecret("S".repeat(43)),
      csrfKey: "C".repeat(43),
      now: Date.now(),
      expiresAt: Date.now() + 3_600_000,
    });

    const runner = await fakeRunner();
    const adapter = adapterFor(runner, {
      onNotebooksListed: (guid, names) => db.setNotebooks(guid, names),
    });
    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "notebooks-listed",
        notebooks: [{ name: "Work", url: "x" }, { name: "Personal", url: "y" }],
      })}\n\n`,
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    await sub.received();
    adapter.stopAll();

    expect(JSON.parse(db.get<{ notebooks: string }>(
      `SELECT notebooks FROM sessions WHERE guid = ?`,
      SESSION,
    )!.notebooks)).toEqual(["Work", "Personal"]);
  });

  it("hands them back on the REST route, which is what a refresh reads", async () => {
    // Through the route, not through a helper. The point of this bug is that the two
    // routes disagreed; asserting on one of them directly would only re-assert the
    // helper. The client reads `GET /api/session/status`, so that is what is asked.
    const db = seededDb();
    db.setNotebooks(SESSION, ["Work", "Personal", "Research"]);

    const body = await statusRoute(db);

    expect(body.notebooks).toEqual({
      state: "loaded",
      items: ["Work", "Personal", "Research"],
    });
  });

  it("reports idle before anything has been listed", async () => {
    const body = await statusRoute(seededDb());

    // An honest empty, which is what the client can render, rather than a shape it
    // cannot read.
    expect(body.notebooks).toEqual({ state: "idle", items: [] });
  });

  it("degrades to the exported notebook when the stored value is unreadable", async () => {
    const db = seededDb();
    db.run(`UPDATE sessions SET notebook = 'Work', notebooks = 'not json' WHERE guid = ?`, SESSION);

    // Better than an empty list, which reads as "this account has no notebooks".
    const body = await statusRoute(db);
    expect(body.notebooks).toEqual({ state: "loaded", items: ["Work"] });
  });

  it("replaces rather than accumulating across refreshes", async () => {
    const db = seededDb();
    db.setNotebooks(SESSION, ["Work", "Personal"]);
    db.setNotebooks(SESSION, ["Work", "Personal"]);

    // Two listings of one account are the same list. Merging would double it.
    const body = await statusRoute(db);
    expect((body.notebooks as { items: string[] }).items).toEqual(["Work", "Personal"]);
  });

  it("clears the list when the session is erased", async () => {
    const db = new Db(":memory:");
    db.createSession({
      guid: SESSION,
      secretHash: "S".repeat(64),
      csrfKey: "C".repeat(43),
      now: Date.now(),
      expiresAt: Date.now() + 3_600_000,
    });
    db.setNotebooks(SESSION, ["Work"]);
    expect(db.deleteSession(SESSION)).toBe(1);

    // The row is gone, so there is nothing left that could name a notebook — which is
    // the point of `deleteSession` destroying the row at all.
    expect(db.getSession(SESSION)).toBeUndefined();
  });
});

/**
 * The in-flight counts, and the writer that remembers them.
 *
 * ## The same bug, one field along
 *
 * The block above is about a **finished** export never reaching the database.
 * This one is about a **running** one: `export-progress` was published to the hub
 * and discarded, so the browser watched the card count up while
 * `GET /api/session/status` kept answering the zeros `routes.ts` wrote at queue
 * time — and every refresh, every second tab and the client's own status poll
 * replaced real numbers with `0 / 0 / 0`.
 *
 * ## Why the adapter tests *the seam* and not just the callback
 *
 * "The adapter calls the callback" is the easy half and it is already implied by
 * the existing progress test. The half that actually decides what the user sees
 * is what the **writer** does with a frame it has already been handed — in
 * particular that it does not write a frame whose counts are older than the ones
 * already stored, because `#pump` replays from its last sequence number on every
 * reconnect. So the monotonic and rate-limit cases are driven *through the
 * adapter* with the real writer attached, and assert on what reached the write
 * function. Asserting the callback in isolation would leave the replay case
 * untested and it is the one that can make the card count down.
 */
describe("an export's live counts are handed on, not just published", () => {
  /** A runner frame of the given type, with the runner's own wire format. */
  function frame(seq: number, payload: Record<string, unknown>): string {
    return `id: ${seq}\ndata: ${JSON.stringify(payload)}\n\n`;
  }

  it("calls the callback once per export-progress frame, with the session, id and counts", async () => {
    const runner = await fakeRunner();
    const seen: Array<[string, string, { pages: number; sections: number; assets: number }]> = [];
    const adapter = adapterFor(runner, {
      onExportProgress: (sessionId, id, progress) => seen.push([sessionId, id, progress]),
    });

    runner.sseFrames = [
      frame(1, {
        type: "export-progress",
        id: "artifact-id",
        progress: { pages: 12, sections: 3, assets: 40 },
      }),
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    await sub.received();
    adapter.stopAll();

    expect(seen).toEqual([
      [SESSION, "artifact-id", { pages: 12, sections: 3, assets: 40 }],
    ]);
  });

  it("never fires it for another event type", async () => {
    // Every other frame in this suite's vocabulary carries no counts: firing the
    // callback for `export-log` would write a row per line of exporter output,
    // and firing it for `export-done` would race `completeExport` for the same
    // key.
    const runner = await fakeRunner();
    const seen: string[] = [];
    const adapter = adapterFor(runner, {
      onExportProgress: (_sessionId, id) => seen.push(id),
    });

    runner.sseFrames = [
      frame(1, { type: "export-started", id: "artifact-id" }),
      frame(2, { type: "export-log", id: "artifact-id", line: "exported page 1/29" }),
      frame(3, { type: "export-progress", id: "artifact-id", progress: { pages: 1 } }),
      frame(4, { type: "notebooks-listed", notebooks: [{ name: "Work" }] }),
      frame(5, { type: "login-success" }),
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    await sub.received(4);
    adapter.stopAll();

    expect(seen).toEqual(["artifact-id"]);
  });

  it("a runner export-started frame reaches the wire as the api's export-started", async () => {
    // **A characterization test, and the first assertion of this frame at all.**
    //
    // The test above is the only other place `export-started` appears here, and it
    // is a negative one: `onExportProgress` must not fire for it. Nothing asserted
    // that the frame is published, or that it carries the id the client's export
    // card is keyed on.
    //
    // It is **not** a revert-red pin, and it would be dishonest to claim otherwise:
    // `export-started` reached this very emit through the chain's trailing `else`,
    // so naming the branch explicitly changed no behaviour and this passes against
    // the code from before that change as readily as after it. What it pins is the
    // frame on the wire — so the next edit to this chain, a seventh case label
    // added above it, has to fail here rather than quietly publish it under a name
    // that belongs to a different event.
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    runner.sseFrames = [frame(1, { type: "export-started", id: "artifact-id" })];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    await adapter.drain();
    // `drain()` settles what the frame started, and starting nothing. The pump
    // itself is opened without being awaited, so `listNotebooks` returning is not
    // the stream being open — `received` waits for the frame rather than assuming.
    await sub.received(1);
    adapter.stopAll();

    const frames = framesFrom(sub.res);
    // The whole assertion in one list: one frame, and it is the api's own name
    // rather than a runner name the frontend has no renderer for.
    expect(frames.map((f) => f.type)).toEqual(["export-started"]);
    // And the id with it, and nothing else. The id is what tells a client which
    // export started when two overlap, so an empty payload is a frame it cannot act
    // on — and the emit invents no field the client would have to know about.
    expect(frames[0].data).toEqual({ id: "artifact-id" });
  });

  it("fires once per frame however many browsers are attached", async () => {
    // `#handleFrame` runs on the pump, before any delivery, so the callback
    // counts frames and not subscribers. Two tabs on one session must not double
    // a database write — and the test that cannot distinguish those two is a
    // test that would pass either way.
    const runner = await fakeRunner();
    let calls = 0;
    const adapter = adapterFor(runner, {
      onExportProgress: () => {
        calls += 1;
      },
    });

    runner.sseFrames = [
      frame(1, {
        type: "export-progress",
        id: "artifact-id",
        progress: { pages: 12, sections: 3, assets: 40 },
      }),
    ];

    // Two independent subscribers, exactly as two browser tabs would be.
    const first = subscribe(runner.sse);
    const second = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    await first.received();
    await second.received();
    adapter.stopAll();

    expect(calls).toBe(1);
    // Both saw it — the assertion above is about the writer, not about delivery.
    expect(framesFrom(first.res).some((f) => f.type === "export-progress")).toBe(true);
    expect(framesFrom(second.res).some((f) => f.type === "export-progress")).toBe(true);
  });

  it("survives a callback that throws, and delivers the next frame", async () => {
    // **The load-bearing one.** `#handleFrame` runs inside `#pump`'s `try`, and
    // the pump's catch drops the stream, backs off and reconnects — replaying
    // from the last sequence number it saw, which re-delivers the frame that
    // threw. A throw here is therefore not a crash: it is a session that spins on
    // one frame for ever and never receives another event again, with every log
    // line saying the right thing.
    const runner = await fakeRunner();
    let calls = 0;
    const adapter = adapterFor(runner, {
      onExportProgress: () => {
        calls += 1;
        throw new Error("the writer is on fire");
      },
    });

    runner.sseFrames = [
      frame(1, {
        type: "export-progress",
        id: "artifact-id",
        progress: { pages: 1, sections: 1, assets: 1 },
      }),
      // A different type, so its arrival is proof the pump is still consuming
      // rather than proof that it re-delivered the first frame.
      frame(2, { type: "export-log", id: "artifact-id", line: "still alive" }),
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    const events = await sub.received(2);
    adapter.stopAll();

    expect(calls).toBe(1);
    // The frame *after* the one that threw is still delivered, which is the whole
    // claim: an uncaught throw here would have dropped the stream, and this event
    // would never exist.
    expect(events.map((e) => e.type)).toContain("export-log");
  });

  it("skips a replayed older frame and writes a genuinely newer one", async () => {
    // The real coalescing writer, not a double, driven through the adapter over
    // real frames. `#pump` reconnects and replays from `since`, so the last frame
    // before a dropped connection arrives **again** — and it carries older counts.
    // Writing it would make the card count down, which is a worse lie than the
    // zeros this replaced.
    const { createExportProgressWriter } = await import("../src/index.js");
    const runner = await fakeRunner();
    const writes: Array<{ pages: number; sections: number; assets: number }> = [];
    let clock = 1_000_000;
    const writer = createExportProgressWriter(
      (_guid, progress) => {
        writes.push(progress);
        return 1;
      },
      () => (clock += 2_000), // comfortably past the one-second rate limit
    );
    const adapter = adapterFor(runner, { onExportProgress: writer.onExportProgress });

    runner.sseFrames = [
      frame(1, {
        type: "export-progress",
        id: "artifact-id",
        progress: { pages: 12, sections: 3, assets: 40 },
      }),
      // The replay: the same numbers the runner had when the stream dropped.
      frame(1, {
        type: "export-progress",
        id: "artifact-id",
        progress: { pages: 12, sections: 3, assets: 40 },
      }),
      // And an older one still, which is what a runner restarting its own
      // counter looks like.
      frame(0, {
        type: "export-progress",
        id: "artifact-id",
        progress: { pages: 2, sections: 1, assets: 5 },
      }),
      frame(2, {
        type: "export-progress",
        id: "artifact-id",
        progress: { pages: 29, sections: 1, assets: 8 },
      }),
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    await sub.received(4);
    adapter.stopAll();

    expect(writes).toEqual([
      { pages: 12, sections: 3, assets: 40 },
      { pages: 29, sections: 1, assets: 8 },
    ]);
  });

  it("writes at most one frame per second, and skips a throttled frame rather than queueing it", async () => {
    // The runner announces once per **section**, so a burst inside one second is
    // not a burst — it is one export moving fast. And the frame that is skipped is
    // not lost: `completeExport` writes the final counts on its own path, which is
    // why a drop is safe here and would not be if the terminal went through the
    // same throttle.
    const { createExportProgressWriter } = await import("../src/index.js");
    const runner = await fakeRunner();
    const writes: number[] = [];
    const writer = createExportProgressWriter(
      (_guid, progress) => {
        writes.push(progress.pages);
        return 1;
      },
      // Frozen: every frame arrives in the same millisecond, so only the rate
      // limit can be what is doing the skipping.
      () => 5_000,
    );
    const adapter = adapterFor(runner, { onExportProgress: writer.onExportProgress });

    runner.sseFrames = [
      frame(1, { type: "export-progress", id: "a", progress: { pages: 1 } }),
      frame(2, { type: "export-progress", id: "a", progress: { pages: 2 } }),
      frame(3, { type: "export-progress", id: "a", progress: { pages: 3 } }),
    ];

    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    await sub.received(3);
    adapter.stopAll();

    expect(writes).toEqual([1]);
  });

  it("forgets a session the database refuses, so the next export of it starts clean", async () => {
    // `updateExportProgress` answers 0 for exactly one reason: this row's export
    // is not `queued`/`running` any more, or the row is gone. Done, partial,
    // aborted, stranded and erased all read that way, so this one return value is
    // what ends the coalescing without any of those paths knowing it exists.
    const { createExportProgressWriter } = await import("../src/index.js");
    const runner = await fakeRunner();
    let refused = false;
    const writes: number[] = [];
    // The clock moves, so what is being observed here is the **refusal** and not
    // the rate limit: with a frozen clock every later frame is throttled away and
    // the test would pass for the wrong reason.
    let clock = 1_000;
    const writer = createExportProgressWriter(
      (_guid, progress) => {
        if (refused) return 0;
        writes.push(progress.pages);
        return 1;
      },
      () => (clock += 2_000),
    );
    const adapter = adapterFor(runner, { onExportProgress: writer.onExportProgress });

    runner.sseFrames = [
      frame(1, { type: "export-progress", id: "a", progress: { pages: 29 } }),
    ];
    const sub = subscribe(runner.sse);
    await adapter.listNotebooks(SESSION);
    await sub.received();
    adapter.stopAll();
    expect(writes).toEqual([29]);

    // The export finishes: `completeExport` has moved the row to `done`, so a
    // later frame for this session is refused — and that refusal is the only
    // signal the writer gets that the export is over.
    refused = true;
    writer.onExportProgress(SESSION, "a", { pages: 40, sections: 2, assets: 9 });
    expect(writes).toEqual([29]);

    // A second export of the same session starts from zero, and its first frame
    // must not be skipped as "not ahead of" the first export's 40 pages. A writer
    // that had forgotten nothing would drop it, and the card would sit at the
    // *previous* export's totals for its whole run.
    refused = false;
    writer.onExportProgress(SESSION, "b", { pages: 1, sections: 1, assets: 1 });
    expect(writes).toEqual([29, 1]);
  });

  it("forgets on the terminal, so a next export is not compared against the last one's totals", async () => {
    // The eager half. `onExportFinished` calls `forget` in its `finally`, because
    // `completeExport` has four endings that never reach `db.completeExport` — a
    // thrown walk, an empty notebook, a total loss of pages, a failed publish —
    // and each of those leaves `export_state` at `failed`, not `running`. Without
    // the forget, the entry survives the whole session and the second export's
    // first frames are skipped as "not ahead of".
    const { createExportProgressWriter } = await import("../src/index.js");
    const writes: number[] = [];
    const writer = createExportProgressWriter(
      (_guid, progress) => {
        writes.push(progress.pages);
        return 1;
      },
      () => 1_000,
    );

    writer.onExportProgress(SESSION, "a", { pages: 29, sections: 1, assets: 8 });
    expect(writes).toEqual([29]);
    // Still remembered while the export is running — forgetting here would let a
    // rate-limited burst through.
    writer.onExportProgress(SESSION, "a", { pages: 31, sections: 1, assets: 8 });
    expect(writes).toEqual([29]);

    writer.forget(SESSION);
    writer.onExportProgress(SESSION, "b", { pages: 2, sections: 1, assets: 1 });
    expect(writes).toEqual([29, 2]);
  });
});

/**
 * The one assertion whose absence shipped the bug.
 *
 * Every test above this block asserted that an export's **events** reached the SSE
 * hub. That was true, and it was not the thing a user depends on. A finished export
 * has to change a row on disk; nothing did, so the session reported `running` with
 * `finishedAt: null` for ever and no download was ever authorised.
 *
 * So these assert that `export-done` reaches the completion callback — and the one
 * that really matters asserts the **bytes at the far side**: that the runner is
 * actually asked to stage the archive, at the right path, with the api's own id in
 * the body.
 */
describe("a finished export is handed on, not just published", () => {
  const ARTIFACT = "A".repeat(43);

  function doneFrames(id = ARTIFACT): string[] {
    return [
      `id: 1\ndata: ${JSON.stringify({
        type: "export-done",
        id,
        notebook: "Notebook",
        pages: 20,
        sections: 7,
        assets: 55,
        failedSections: 0,
        failedPages: 0,
        failedGroups: 0,
      })}\n\n`,
    ];
  }

  it("calls the completion callback when export-done arrives", async () => {
    const runner = await fakeRunner();
    const seen: ExportFinishedInput[] = [];
    const adapter = adapterFor(runner, {
      now: () => 1_700_000_005_000,
      onExportFinished: (input) => {
        seen.push(input);
      },
    });

    runner.sseFrames = doneFrames();
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    // The load-bearing assertion. Before this existed, `export-done` was published
    // to the hub and discarded, and every export ended with nothing recorded.
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      sessionId: SESSION,
      artifactId: ARTIFACT,
      partial: false,
      partialReason: null,
      notebook: "Notebook",
      finishedAt: 1_700_000_005_000,
    });
  });

  it("asks the runner to stage the archive, and puts the id in the body", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner, {
      onExportFinished: async (input) => {
        // Stands in for `completeExport`'s first step, which is the call this test
        // is really about: the runner's staging route had no caller at all.
        await adapter.publishArtifact({
          sessionId: input.sessionId,
          artifactId: input.artifactId,
        });
      },
    });

    runner.sseFrames = doneFrames();
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    const staging = runner.seen.find((r) => r.url.includes("/artifacts"));
    expect(staging).toBeDefined();
    expect(staging!.method).toBe("POST");
    // In the path, not the body: the path names the session, and the artifact id is
    // the caller's own opaque value that the runner validates by shape.
    expect(staging!.url).toBe(`/sessions/${SESSION}/artifacts`);
    expect(staging!.token).toBe(TOKEN);
    // **The bytes**, not the handler: what the runner reads is exactly the api's id.
    expect(JSON.parse(staging!.body.toString("utf8"))).toEqual({ artifactId: ARTIFACT });
  });

  it("hands on a partial export, labelled, rather than discarding it", async () => {
    const runner = await fakeRunner();
    const seen: ExportFinishedInput[] = [];
    const adapter = adapterFor(runner, {
      onExportFinished: (input) => {
        seen.push(input);
      },
    });

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "export-partial",
        id: ARTIFACT,
        reason: "aborted",
      })}\n\n`,
    ];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    // §8.2 preserves what is on disk, so a partial vault is still published —
    // labelled. The orchestrator trusts this bit for the `.partial.zip` name and
    // cannot check it, so it has to arrive as the runner reported it.
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ partial: true, partialReason: "aborted" });
  });

  it("publishes once when the same terminal event arrives twice", async () => {
    const runner = await fakeRunner();
    const seen: ExportFinishedInput[] = [];
    const adapter = adapterFor(runner, {
      onExportFinished: (input) => {
        seen.push(input);
      },
    });

    // **Not** the abort pair. An abort sends `export-aborted` then
    // `export-partial`, and only the latter reaches the callback, so that case
    // produces exactly one publish whether or not the guard exists — a test built
    // on it passes with the guard removed and guards nothing.
    //
    // The real duplicate source is the pump's own reconnect: `#pump` retries with
    // `since=<last seq>`, and anything the runner replays past that point is
    // delivered again. Zipping and finalising one vault twice would race two
    // renames of one staging directory, and the second would 409.
    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "export-done",
        id: ARTIFACT,
        notebook: "Notebook",
        pages: 20,
        sections: 7,
        assets: 55,
      })}\n\n`,
      `id: 2\ndata: ${JSON.stringify({
        type: "export-done",
        id: ARTIFACT,
        notebook: "Notebook",
        pages: 20,
        sections: 7,
        assets: 55,
      })}\n\n`,
    ];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    expect(seen).toHaveLength(1);
  });

  it("keeps consuming events after a completion callback fails", async () => {
    const runner = await fakeRunner();
    const sub = subscribe(runner.sse);
    const adapter = adapterFor(runner, {
      onExportFinished: async () => {
        throw new Error("archive failed: ENOSPC");
      },
    });

    runner.sseFrames = [
      ...doneFrames(),
      `id: 2\ndata: ${JSON.stringify({
        type: "export-log",
        id: ARTIFACT,
        line: "after the failure",
      })}\n\n`,
    ];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    // `#handleFrame` runs inside `#pump`'s try. A rejection from the publish would
    // tear down the event stream and silently lose every later event for the
    // session — the user would see an export that stopped reporting for ever.
    const events = await sub.received(2);
    expect(events.map((e) => e.type)).toContain("export-done");
    expect(events.map((e) => e.type)).toContain("export-log");
    // And the failure is reported, rather than swallowed: a user whose export
    // finished but cannot be downloaded is otherwise told nothing.
    expect(events.some((e) => e.type === "error")).toBe(true);
  });

  it("gives the archiving call its own budget, not the control-verb default", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner);

    // Every other call in the adapter returns 202 in milliseconds. Archiving zips
    // the whole vault, so sharing the short default would abort almost every real
    // export at the archiving step — after the work succeeded — and report a
    // completed export as a failure.
    const started = Date.now();
    await adapter
      .publishArtifact({ sessionId: SESSION, artifactId: ARTIFACT })
      .catch(() => undefined);

    // The fake answers immediately, so this only proves the call is made at all;
    // the timeout itself is asserted in the source and is not observable here
    // without a slow fake. Recorded rather than pretended at.
    expect(runner.seen.some((r) => r.url.includes("/artifacts"))).toBe(true);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("parses the new failure counts and notebookNotFound from export-done", async () => {
    const runner = await fakeRunner();
    const seen: ExportFinishedInput[] = [];
    const adapter = adapterFor(runner, {
      onExportFinished: (input) => {
        seen.push(input);
      },
    });

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "export-done",
        id: ARTIFACT,
        notebook: "Notebook",
        pages: 10,
        sections: 5,
        assets: 20,
        failedSections: 2,
        failedPages: 3,
        failedGroups: 1,
        notebookNotFound: false,
      })}\n\n`,
    ];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      failedSections: 2,
      failedPages: 3,
      failedGroups: 1,
      notebookNotFound: false,
    });
  });

  it("sets partial true only when some pages exported but some failed", async () => {
    const runner = await fakeRunner();
    const adapter = adapterFor(runner, {
      onExportFinished: () => undefined, // don't collect, just test the logic
    });

    // 0 pages, 2 failed sections → partial = false (no artifact)
    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "export-done",
        id: ARTIFACT,
        notebook: "Notebook",
        pages: 0,
        sections: 0,
        assets: 0,
        failedSections: 2,
        failedPages: 0,
        failedGroups: 0,
      })}\n\n`,
    ];
    await adapter.listNotebooks(SESSION);
    // The first export with 0 pages should produce a terminal that is marked as failure (partial=false)
    // and won't actually invoke publishArtifact - that's tested in export-completion.test.ts
  });

  it("parses the new fields from export-partial", async () => {
    const runner = await fakeRunner();
    const seen: ExportFinishedInput[] = [];
    const adapter = adapterFor(runner, {
      onExportFinished: (input) => {
        seen.push(input);
      },
    });

    runner.sseFrames = [
      `id: 1\ndata: ${JSON.stringify({
        type: "export-partial",
        id: ARTIFACT,
        reason: "aborted",
        failedSections: 1,
        failedPages: 2,
        failedGroups: 0,
        notebookNotFound: false,
      })}\n\n`,
    ];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      partial: true,
      partialReason: "aborted",
      failedSections: 1,
      failedPages: 2,
      failedGroups: 0,
      notebookNotFound: false,
    });
  });
});

// ---------------------------------------------------------------------------

/**
 * The terminal is emitted **after** the artifact it announces.
 *
 * ## What was wrong, and how it was known
 *
 * `publish` emitted `export-done` to the hub and only then called the completion
 * callback. The browser received the terminal, correctly called `refreshStatus()`,
 * and read a snapshot taken before `completeExport` had written the row. Nothing
 * triggers a second refresh, so the card sat on "Exporting 0 pages, 0 sections,
 * 0 assets" with no link until the user reloaded by hand.
 *
 * Proved far-side in one run, not inferred from the handler: the instrumented
 * stream showed the terminal **arriving**, SQLite read-only showed `done` with an
 * `artifact_id` and `export published` in the log, and the browser showed no link.
 * The architecture documents the opposite order — *completeExport → record id +
 * counts + finished_at*, then *SSE export-done → the snapshot gains
 * `artifact.downloadUrl`* — and the code did it backwards.
 *
 * ## Why these tests run the real chain
 *
 * The ordering asserted is the ordering of the three steps that produce a
 * download, so the wiring here is the **real** `completeExport`, with the adapter
 * standing in as its runner and only the orchestrator's HTTP client and the
 * database's row writer recorded. A hand-rolled callback that pushes a string would
 * assert a mock's order, which is the mistake this file was written to stop.
 *
 * The timeline is recorded by wrapping the subscriber's `write`, which `SseHub.emit`
 * calls synchronously — so each entry is the moment the event was published, not the
 * moment a test got round to looking. Polling for the frame instead would let the
 * very ordering under test slip past unremarked.
 */
describe("the terminal is emitted after the artifact it announces", () => {
  const ARTIFACT = "A".repeat(43);

  function doneFrame(id = ARTIFACT): string {
    return `id: 1\ndata: ${JSON.stringify({
      type: "export-done",
      id,
      notebook: "Notebook",
      pages: 20,
      sections: 7,
      assets: 55,
      failedSections: 0,
      failedPages: 0,
      failedGroups: 0,
    })}\n\n`;
  }

  function partialFrame(id = ARTIFACT, seq = 1): string {
    return `id: ${seq}\ndata: ${JSON.stringify({
      type: "export-partial",
      id,
      reason: "aborted",
    })}\n\n`;
  }

  function abortedFrame(id = ARTIFACT): string {
    return `id: 1\ndata: ${JSON.stringify({ type: "export-aborted", id })}\n\n`;
  }

  /**
   * The real completion chain, wired to a recording db and orchestrator.
   *
   * Staging is not recorded by a spy but delegated to the adapter, so the first
   * step is a real HTTP request to the fake runner — the same "the bytes arrived"
   * discipline as the rest of this file. The `stage` marker is pushed before it, so
   * the timeline shows where in the chain the request was made.
   */
  function completionDeps(adapter: HttpRunnerAdapter, order: string[]): ExportCompletionDeps {
    return {
      runner: {
        publishArtifact: (request) => {
          order.push("stage");
          return adapter.publishArtifact(request);
        },
      },
      orchestrator: {
        finalize: vi.fn(async (request) => {
          order.push("finalize");
          return {
            ok: true,
            value: {
              artifactId: request.artifactId,
              archiveName: request.partial ? "vault.partial.zip" : "vault.zip",
              bytes: 2048,
              partial: request.partial,
            },
          };
        }),
      },
      db: {
        completeExport: vi.fn(() => {
          order.push("record");
          return true;
        }),
        markExportUnpublishable: vi.fn(() => {
          order.push("unpublishable");
          return true;
        }),
      },
      log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    };
  }

  /** A subscriber that appends `emit:<type>` to the timeline as frames are written. */
  function timeline(sse: SseHub, order: string[] = []): ReturnType<typeof subscribe> {
    const sub = subscribe(sse);
    const write = sub.res.write;
    sub.res.write = ((chunk: string) => {
      for (const frame of framesFrom({ written: [String(chunk)] })) {
        order.push(`emit:${frame.type}`);
      }
      return write(chunk);
    }) as ServerResponse["write"];
    return sub;
  }

  it("emits export-done after completeExport has recorded the artifact", async () => {
    const order: string[] = [];
    const runner = await fakeRunner();
    const sub = timeline(runner.sse, order);
    const adapter = adapterFor(runner, {
      onExportFinished: (input) => completeExport(completionDeps(adapter, order), input),
    });

    runner.sseFrames = [doneFrame()];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    // The whole assertion, in one list: stage, finalise, record, **then** the
    // terminal. The browser's refresh — which this event triggers — now reads a row
    // that exists. Before the fix the first entry was `emit:export-done` and the
    // refresh read a session that was still `running` with `finishedAt: null`.
    expect(order).toEqual(["stage", "finalize", "record", "emit:export-done"]);

    // And `drain()` observes the emit: the frame is on the wire the moment
    // `drain()` resolves, read **without polling** so that is asserted rather than
    // waited for. `drain()` awaits the tracked task, and the terminal is emitted
    // inside it — what releases this await is the export's own completion.
    const frames = framesFrom(sub.res);
    expect(frames.map((f) => f.type)).toEqual(["export-done"]);
    // The payload is the one the frame handler read, counts and all — captured at
    // frame-handling time rather than re-derived when the chain finally settled.
    expect(frames[0].data).toMatchObject({
      id: ARTIFACT,
      notebook: "Notebook",
      pages: 20,
      sections: 7,
      assets: 55,
    });
  });

  it("emits export-partial after the partial vault is recorded, because it raced identically", async () => {
    const order: string[] = [];
    const runner = await fakeRunner();
    timeline(runner.sse, order);
    const adapter = adapterFor(runner, {
      onExportFinished: (input) => completeExport(completionDeps(adapter, order), input),
    });

    // An abort's vault goes through the same chain and was emitted by the same
    // early line, so fixing `export-done` alone would have left half the terminal
    // events announcing an artifact that did not exist yet.
    runner.sseFrames = [partialFrame()];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    expect(order).toEqual(["stage", "finalize", "record", "emit:export-partial"]);
  });

  it("still emits the terminal when the completion callback throws", async () => {
    const order: string[] = [];
    const runner = await fakeRunner();
    const sub = timeline(runner.sse, order);
    const adapter = adapterFor(runner, {
      onExportFinished: async () => {
        order.push("callback");
        throw new Error("archive failed: ENOSPC");
      },
    });

    runner.sseFrames = [doneFrame()];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    // The card must **end**, not hang. `completeExport` is documented never to
    // throw, but the callback is injected and a card stuck on "Exporting" for ever
    // is the worst outcome available — so the emit is in the `finally`, and the
    // failure is reported afterwards rather than swallowed.
    expect(order).toEqual(["callback", "emit:export-done", "emit:error"]);
    expect(framesFrom(sub.res).map((f) => f.type)).toEqual(["export-done", "error"]);
  });

  it("emits nothing while a completion that has not settled is still running", async () => {
    const order: string[] = [];
    const runner = await fakeRunner();
    const sub = timeline(runner.sse, order);
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const adapter = adapterFor(runner, { onExportFinished: () => held });

    runner.sseFrames = [doneFrame()];
    await adapter.listNotebooks(SESSION);
    // `drain()` is not awaited here and could not be: the chain has not settled,
    // and until it does there is no artifact to announce. This is the other half
    // of the throwing case — deferred, not dropped.
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(framesFrom(sub.res)).toHaveLength(0);

    // And it was deferred rather than cancelled: the terminal arrives as soon as
    // the chain settles, which is the whole contract.
    release();
    await adapter.drain();
    expect(framesFrom(sub.res).map((f) => f.type)).toEqual(["export-done"]);
  });

  it("keeps consuming frames while the completion is still running", async () => {
    const order: string[] = [];
    const runner = await fakeRunner();
    const sub = timeline(runner.sse, order);
    let settled = false;
    const adapter = adapterFor(runner, {
      onExportFinished: async () => {
        await new Promise((resolve) => setTimeout(resolve, 300));
        settled = true;
      },
    });

    runner.sseFrames = [
      doneFrame(),
      `id: 2\ndata: ${JSON.stringify({
        type: "export-log",
        id: ARTIFACT,
        line: "the pump kept going",
      })}\n\n`,
    ];
    await adapter.listNotebooks(SESSION);
    await sub.received(1);

    // The property the fire-and-forget design protects, and the reason the fix is
    // "emit inside the tracked task" rather than "await it in the frame handler":
    // `readEvents` awaits frame handling, so a frame arriving minutes into a
    // multi-gigabyte zip must still be consumed. A user's abort click is exactly
    // such a frame. The terminal has not been announced yet, and the pump has
    // already moved on.
    expect(settled).toBe(false);
    expect(framesFrom(sub.res).map((f) => f.type)).toEqual(["export-log"]);
  });

  it("emits one terminal per artifact id, across the abort pair and a replay", async () => {
    const runner = await fakeRunner();
    const sub = timeline(runner.sse);
    const seen: ExportFinishedInput[] = [];
    const adapter = adapterFor(runner, {
      onExportFinished: (input) => {
        seen.push(input);
      },
    });

    // The abort pair alone would prove nothing here — only `export-partial` reaches
    // the publish path, so that case emits one terminal whether or not the dedupe
    // exists ("publishes once when the same terminal event arrives twice" says so
    // at length). The third frame is the pump's own reconnect replaying past its
    // last sequence number, and that is what the guard is for: two renames of one
    // staging directory, the second 409ing.
    runner.sseFrames = [
      abortedFrame(),
      partialFrame(),
      partialFrame(ARTIFACT, 2),
    ];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    expect(seen).toHaveLength(1);
    // One terminal per artifact id — and `export-aborted` still goes out, because
    // it has no completion chain and so nothing to be ordered after.
    expect(framesFrom(sub.res).map((f) => f.type)).toEqual(["export-aborted", "export-partial"]);
  });

  it("emits the terminal even when no completion callback is configured", async () => {
    const runner = await fakeRunner();
    const sub = timeline(runner.sse);
    // No `onExportFinished` at all — a test double, or a deployment with publishing
    // switched off. There is no chain to wait for, so the terminal is emitted
    // straight away; dropping it instead would be the same bug one layer down, and
    // a quieter one: a card that never ends, with nothing in the logs.
    const adapter = adapterFor(runner);

    runner.sseFrames = [doneFrame()];
    await adapter.listNotebooks(SESSION);
    await sub.received(1);

    expect(framesFrom(sub.res).map((f) => f.type)).toEqual(["export-done"]);
  });

  it("explains a failed publish after the terminal, not before it", async () => {
    const runner = await fakeRunner();
    const sub = timeline(runner.sse);
    const adapter = adapterFor(runner, {
      onExportFinished: async () => {
        throw new Error("archive failed: ENOSPC");
      },
    });

    runner.sseFrames = [doneFrame()];
    await adapter.listNotebooks(SESSION);
    await adapter.drain();

    // Pinned rather than tolerated. The emit is in the task body's `finally`, which
    // runs before the rejection reaches the `.catch` that reports the failure — so
    // the card ends and *then* says why the file is not there, which is the order a
    // user can act on. Moving the emit into the outer `.finally` looks like a
    // tidy-up, and it flips this to `error` then `export-done`: the card told it is
    // broken before it was ever told it finished. The throwing-callback test above
    // fails the same way, and the existing "keeps consuming events after a
    // completion callback fails" asserts with `toContain`, which would notice
    // neither.
    expect(framesFrom(sub.res).map((f) => f.type)).toEqual(["export-done", "error"]);
  });
});
