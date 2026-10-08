// A refused login was answered as "wait a moment".
//
// ## What the user saw
//
// They signed in, clicked "List my notebooks", and got:
//
//     "Still signing in — the service is not ready to list notebooks yet. Try again in a moment."
//
// ## What was true
//
//     auth_state: "failed"
//
// The runner had already reported `outcome: "failed"` — Microsoft had refused the
// credential, in its own words ("We couldn't find an account with that username"). There
// was no "in a moment". The only thing that could change the state was a new sign-in.
//
// ## Cause
//
// `auth_state` has five values — `none`, `authenticating`, `valid`, `expired`, `failed` —
// and both runner routes collapsed the four unusable ones into one answer:
//
//     if (session.auth_state !== "valid") {
//       return reply.code(409).send({ error: "not authenticated" });
//     }
//
// So `authenticating` and `failed` were byte-identical to a client, and they want
// **opposite** advice: one says wait, the other says sign in again. The client cannot
// infer which it is, so it picked "wait" and was wrong.
//
// ## Why this is my bug
//
// #34 added `markAuthFailed`, which made `failed` a state a session can actually reach.
// Before it, the state existed in the type and nothing could enter it, so the collapsed
// guard was harmless by accident. Making a field distinguishable in storage is not the
// same as anything reading it — every consumer of `auth_state` was left blind.
//
// ## What these tests assert
//
// That each unusable state gets its own words and, critically, its own `retryable`.

import { beforeEach, describe, expect, it } from "vitest";

import { Db } from "../src/db.js";
import { buildServer } from "../src/server.js";
import type { ServerDeps } from "../src/server.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { deriveCsrfToken, hashSecret } from "../src/session.js";

const SECRET = "S".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const ORIGIN = "https://one.example.com";

let db: Db;

beforeEach(() => {
  db = new Db(":memory:");
});

/** A session in `authState`, bound to a runner so only the auth guard can refuse it. */
async function post(
  url: string,
  authState: string,
  csrfToken: string,
): Promise<{ statusCode: number; body: Record<string, unknown> }> {
  // Cleared first, so a test may ask the same question twice with two different
  // answers - which is how "distinguishable" and "both routes" are asserted.
  db.deleteSession(GUID);
  db.createSession({
    guid: GUID,
    secretHash: hashSecret(SECRET),
    csrfKey: "C".repeat(43),
    now: Date.now(),
    expiresAt: Date.now() + 3_600_000,
  });
  db.run(
    `UPDATE sessions SET state = ?, auth_state = ?, runner_id = 'slot-1' WHERE guid = ?`,
    authState === "authenticating" ? "authenticating" : "authenticated",
    authState,
    GUID,
  );

  const app = buildServer(
    {
      allowedOrigins: new Set([ORIGIN]),
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
      runner: {
        listNotebooks: async () => {},
        startExport: async () => {},
      } as never,
    } as unknown as ServerDeps,
  );
  await app.ready();
  try {
    const response = await app.inject({
      method: "POST",
      url,
      headers: {
        origin: ORIGIN,
        "content-type": "application/json",
        cookie: `${SESSION_COOKIE}=${GUID}:${SECRET}`,
        "x-csrf-token": deriveCsrfToken("C".repeat(43), GUID),
      },
      ...(csrfToken === "" ? {} : { payload: JSON.stringify({ notebook: csrfToken }) }),
    });
    return { statusCode: response.statusCode, body: response.json() as Record<string, unknown> };
  } finally {
    await app.close();
  }
}

const LIST = "/api/session/notebooks";
const EXPORT = "/api/export";

describe("a login that is still running", () => {
  it("says to wait, and that waiting can work", async () => {
    const r = await post(LIST, "authenticating", "");

    expect(String(r.body.error)).toMatch(/still signing in/i);
    expect(r.body.retryable).toBe(true);
    expect(r.body.reason).toBe("authenticating");
  });
});

describe("a login that was refused", () => {
  it("does not say to wait — there is no moment to wait for", async () => {
    // The bug, in one assertion. `failed` and `authenticating` produced byte-identical
    // answers, so the client said "wait" about a credential Microsoft had already
    // rejected.
    const r = await post(LIST, "failed", "");

    expect(String(r.body.error)).not.toMatch(/still signing in|not ready|try again/i);
  });

  it("says to sign in again, which is the only thing that helps", async () => {
    const r = await post(LIST, "failed", "");

    expect(String(r.body.error)).toMatch(/sign in again/i);
  });

  it("is not retryable, because repeating a refused credential cannot succeed", async () => {
    // Telling a user to retry this sends them round a loop that cannot end.
    const r = await post(LIST, "failed", "");

    expect(r.body.retryable).toBe(false);
    expect(r.body.reason).toBe("failed");
  });

  it("answers the export route the same way", async () => {
    // Two routes, one guard. If only listing was fixed, the next click would have said
    // the opposite thing.
    const r = await post(EXPORT, "failed", "Work");

    expect(r.body.retryable).toBe(false);
    expect(r.body.reason).toBe("failed");
  });
});

describe("an expired sign-in", () => {
  it("also asks for a new sign-in, and is not retryable", async () => {
    const r = await post(LIST, "expired", "");

    expect(String(r.body.error)).toMatch(/sign in again/i);
    expect(r.body.retryable).toBe(false);
  });

  it("is distinguishable from a refused one", async () => {
    // Microsoft invalidating a cookie and a credential being rejected produce the same
    // observable failure, so the client cannot honestly tell them apart — but the
    // backend can, and `reason` is how it says so.
    const failed = await post(LIST, "failed", "");
    const expired = await post(LIST, "expired", "");

    expect(failed.body.reason).not.toBe(expired.body.reason);
  });
});

describe("a session that never signed in", () => {
  it("asks for a sign-in rather than pretending one is running", async () => {
    const r = await post(LIST, "none", "");

    expect(String(r.body.error)).toMatch(/sign in/i);
    expect(String(r.body.error)).not.toMatch(/still signing in/i);
    expect(r.body.retryable).toBe(false);
  });
});

describe("a valid session", () => {
  it("passes the guard, on both routes", async () => {
    // So the distinction above is not just "everything is 409 now".
    expect((await post(LIST, "valid", "")).statusCode).toBe(202);
    expect((await post(EXPORT, "valid", "Work")).statusCode).toBe(202);
  });
});
