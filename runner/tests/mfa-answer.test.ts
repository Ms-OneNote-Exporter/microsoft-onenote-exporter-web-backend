/**
 * `POST /sessions/:guid/mfa` — handing a typed MFA code to a login that is waiting
 * for one.
 *
 * ## Why the route is not optional
 *
 * `@msout/microsoft-webauth` asks for a code by calling `promptUser`, which reads
 * `process.stdin`. **In a container there is no stdin**, so the prompt is a promise
 * nothing will ever resolve: a `challenge` of kind `code` became a login that hung
 * until the package's own timeout and then failed with a message naming a timeout
 * rather than a missing way to answer. A user with a typed code on their phone could
 * not complete sign-in at all.
 *
 * `answerChallenge` (0.1.12) is the out-of-band half of that — it resolves the
 * pending prompt from outside the process — and this route is the outside.
 *
 * ## The mock is the package's own contract, transcribed
 *
 * `answerChallenge(code)` returns `true` when a prompt was waiting and `false` when
 * none was. The tests below drive the real route against a mock with that exact
 * signature rather than against a hand-written one, because the interesting
 * assertions are about which branch the *return value* selects — and a mock that
 * always returned `true` would pass against a route that ignored it.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const GUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
const TOKEN = "t".repeat(43);

/**
 * Mirrors the package's contract: `true` only when a prompt was pending.
 *
 * Held as a mutable pair rather than a fixed `true` so a test can put the package in
 * the state a real login is in — waiting, or not waiting — instead of every request
 * answering identically.
 */
let promptWaiting = false;

vi.mock("@msout/microsoft-webauth", () => ({
  login: vi.fn(async () => true),
  LOGIN_REASONS: ["unknown"],
  answerChallenge: vi.fn((code: string) => {
    if (!promptWaiting) return false;
    promptWaiting = false;
    seenCodes.push(code);
    return true;
  }),
}));

vi.mock("@msout/microsoft-onenote-list-notebooks", () => ({
  listNotebooks: vi.fn(async () => []),
}));

vi.mock("@msout/microsoft-onenote-export-notebook", () => ({
  runExport: vi.fn(async () => ({})),
}));

import { answerChallenge } from "@msout/microsoft-webauth";
import { buildApp } from "../src/index.js";

/** Every code that actually reached the package. */
let seenCodes: string[] = [];

let dataRoot: string;
let artifactRoot: string;

function app() {
  return buildApp({
    dataRoot,
    artifactRoot,
    port: 0,
    host: "127.0.0.1",
    token: TOKEN,
    credentialBodyLimit: 4096,
    ringSize: 64,
  } as never);
}

function post(body: unknown, headers: Record<string, string> = {}) {
  return app().inject({
    method: "POST",
    url: `/sessions/${GUID}/mfa`,
    headers: {
      "content-type": "application/json",
      "x-runner-token": TOKEN,
      ...headers,
    },
    ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
  });
}

beforeEach(() => {
  promptWaiting = true;
  seenCodes = [];
  vi.mocked(answerChallenge).mockClear();
  dataRoot = mkdtempSync(join(tmpdir(), "runner-mfa-"));
  artifactRoot = mkdtempSync(join(tmpdir(), "runner-mfa-artifacts-"));
});

afterEach(() => {
  rmSync(dataRoot, { recursive: true, force: true });
  rmSync(artifactRoot, { recursive: true, force: true });
});

describe("POST /sessions/:guid/mfa", () => {
  it("hands the code to the package and accepts", async () => {
    const response = await post({ code: "123456" });

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ accepted: true });
    // The far side is the assertion. A route that validated the body and dropped it
    // on the floor would answer 202 to every one of these tests.
    expect(seenCodes).toEqual(["123456"]);
  });

  it("requires the bearer token, like every route but the health check", async () => {
    const response = await post({ code: "123456" }, { "x-runner-token": "wrong" });

    expect(response.statusCode).toBe(401);
    // A refused request must not have reached the package. This is the control the
    // token exists for: an unauthenticated caller must not be able to resolve
    // somebody else's pending prompt.
    expect(seenCodes).toEqual([]);
  });

  it("409s when nothing is waiting, and says so in words", async () => {
    // The package's `false`: the challenge expired, or it was a push-approval that
    // needs no code. "no challenge is waiting for a code" is a different thing to
    // tell a user from "sign-in failed", and only this process can tell them apart.
    promptWaiting = false;
    const response = await post({ code: "123456" });

    expect(response.statusCode).toBe(409);
    expect(response.json().error).toBe("no challenge is waiting for a code");
    expect(seenCodes).toEqual([]);
  });

  it("refuses a missing or blank code without disturbing the pending prompt", async () => {
    for (const body of [{}, { code: "" }, { code: "   " }, { code: 42 }, { code: null }]) {
      const response = await post(body);
      expect(response.statusCode, JSON.stringify(body)).toBe(400);
      // The prompt must still be there afterwards. A validation failure that resolved
      // it would have burned the user's only chance to answer.
      expect(seenCodes, JSON.stringify(body)).toEqual([]);
      expect(answerChallenge).not.toHaveBeenCalled();
    }
  });

  it("refuses a code longer than the bound, which the api applies too", async () => {
    const response = await post({ code: "1".repeat(33) });

    expect(response.statusCode).toBe(400);
    expect(seenCodes).toEqual([]);
    // 32 is accepted, 33 is not: the boundary is the assertion, because a bound that
    // only rejects the obviously-wrong values is not a bound.
    expect((await post({ code: "1".repeat(32) })).statusCode).toBe(202);
  });

  it("forwards the code exactly as typed rather than trimming it", async () => {
    // Same rule as the credential: what the user typed is what the package receives.
    // A trailing space is part of what they typed, and quietly removing it is a
    // transformation of a value nobody can see again once it has been handed over.
    const response = await post({ code: " 123456 " });

    expect(response.statusCode).toBe(202);
    expect(seenCodes).toEqual([" 123456 "]);
  });

  it("refuses a guid that is not one", async () => {
    const response = await app().inject({
      method: "POST",
      url: "/sessions/not-a-guid/mfa",
      headers: { "content-type": "application/json", "x-runner-token": TOKEN },
      payload: JSON.stringify({ code: "123456" }),
    });

    expect(response.statusCode).toBe(400);
    expect(seenCodes).toEqual([]);
  });

  it("does not claim the job slot, so it works while a login holds it", async () => {
    // The regression a slot check here would have caused: the login holds the slot
    // for its whole duration — including the minutes it waits for this code — so a
    // `busy` refusal would reject every code the route exists to deliver.
    const instance = app();
    const claimed = await instance.inject({
      method: "POST",
      url: `/sessions/${GUID}/login`,
      headers: {
        "content-type": "text/plain",
        "x-runner-token": TOKEN,
        "x-microsoft-account": "someone@example.com",
      },
      payload: "hunter2",
    });
    expect(claimed.statusCode).toBe(202);

    const answered = await instance.inject({
      method: "POST",
      url: `/sessions/${GUID}/mfa`,
      headers: { "content-type": "application/json", "x-runner-token": TOKEN },
      payload: JSON.stringify({ code: "123456" }),
    });

    expect(answered.statusCode).toBe(202);
    expect(seenCodes).toEqual(["123456"]);
    await instance.close();
  });
});