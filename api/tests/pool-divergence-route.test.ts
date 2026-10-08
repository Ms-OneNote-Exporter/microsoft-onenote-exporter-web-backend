// What the user saw, and what it should have said.
//
//     3. logged in
//     → "The service returned 502 (runner control plane unreachable)."
//
// The control plane was reachable the whole time. It answered in milliseconds, with a
// 409, saying it did not have the slot the api asked for. The api reported that refusal
// as a transport failure.
//
// Two separate faults, and the message is the one the user could see:
//
//   - the status was 5xx and `retryable: true`, so the frontend invited a retry that
//     could not succeed, and an operator reading the log would look for a component
//     that was down while it was answering 409s
//   - nothing in the payload said the two processes disagreed about the pool, which is
//     the actual fault and the one that has an actual fix
//
// The recovery is covered in `pool-divergence.test.ts`; this file covers the answer, on
// the theory that a correct internal distinction the user is never shown is not a fix.

import { describe, expect, it } from "vitest";

import { buildServer } from "../src/server.js";
import type { ServerDeps } from "../src/server.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { deriveCsrfToken, generateCsrfKey, hashSecret } from "../src/session.js";

const SECRET = "S".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const ALLOWED = "https://one.example.com";

const config = {
  allowedOrigins: new Set([ALLOWED]),
  csrfKey: "C".repeat(43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  publicOrigin: "https://one.example.com",
  orchestratorUrl: "http://orchestrator:9100",
  orchestratorSecret: "B".repeat(43),
  orchestratorReplayWindowSeconds: 60,
  logLevel: "silent",
  listen: "127.0.0.1:0",
  databasePath: ":memory:",
  sseBufferEvents: 10,
  sseKeepaliveMs: 60_000,
} as never;

/** A binder that refuses, with the reason under test. */
function binderRefusing(reason: string): ServerDeps["poolBinder"] {
  return {
    claimForLogin: async () =>
      reason === "pool-exhausted"
        ? { ok: false as const, reason: "pool-exhausted" as const }
        : { ok: false as const, reason: reason as "orchestrator-unreachable" },
  } as never;
}

async function postCredential(
  db: Db,
  binder: ServerDeps["poolBinder"],
): Promise<{ statusCode: number; json: () => Record<string, unknown> }> {
  const app = buildServer(config, {
    db,
    sse: new SseHub({ bufferEvents: 10, keepaliveMs: 60_000 }),
    limiter: new RateLimiter(),
    orchestrator: { healthz: async () => ({ ok: true, value: {} }) } as never,
    runner: { submitCredential: async () => {}, listNotebooks: async () => {} } as never,
    poolBinder: binder,
  } as ServerDeps);
  await app.ready();
  try {
    const csrfKey = db.get<{ csrf_key: string }>(
      `SELECT csrf_key FROM sessions WHERE guid = ?`,
      GUID,
    )!.csrf_key;
    const response = await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: {
        "content-type": "text/plain",
        // The same shape `routes.test.ts` uses: `<guid>:<secret>`.
        cookie: `${SESSION_COOKIE}=${GUID}:${SECRET}`,
        origin: ALLOWED,
        "x-csrf-token": deriveCsrfToken(csrfKey, GUID),
        "x-microsoft-account": "someone@example.com",
      },
      payload: "account\npassword",
    });
    return { statusCode: response.statusCode, json: () => response.json() };
  } finally {
    await app.close();
  }
}

function seededDb(): Db {
  const db = new Db(":memory:");
  db.createSession({
    guid: GUID,
    secretHash: hashSecret(SECRET),
    csrfKey: generateCsrfKey(),
    now: Date.now(),
    expiresAt: Date.now() + 3_600_000,
  });
  db.run(`UPDATE sessions SET runner_id = NULL WHERE guid = ?`, GUID);
  return db;
}

describe("the answer when the two processes disagree about the pool", () => {
  it("is a 409, not a 5xx", async () => {
    // The status code is the part a client acts on. A 5xx says "the far side is broken,
    // try again", and retrying here cannot work: the api will offer the same stale slot
    // again.
    const response = await postCredential(seededDb(), binderRefusing("slot-conflict"));

    expect(response.statusCode).toBe(409);
  });

  it("says retrying will not help", async () => {
    const response = await postCredential(seededDb(), binderRefusing("slot-conflict"));

    expect(response.json().retryable).toBe(false);
  });

  it("names the fault, so it can be found", async () => {
    // The user-facing string is deliberately not "unreachable". The cause is that this
    // process's record of the pool is out of date, which is an operator problem with a
    // known fix, and the payload is where anyone would look for it.
    const response = await postCredential(seededDb(), binderRefusing("slot-conflict"));

    expect(response.json().cause).toBe("pool-diverged");
    expect(String(response.json().error)).not.toMatch(/unreachable/i);
  });

  it("still reports a busy pool as retryable", async () => {
    // Exhaustion is not divergence. Overloading the 409 onto it would tell a user
    // waiting for a slot to give up on something that clears on its own.
    const response = await postCredential(seededDb(), binderRefusing("pool-exhausted"));

    expect(response.statusCode).toBe(503);
    expect(response.json().retryable).toBe(true);
  });

  it("still reports an unreachable control plane as retryable", async () => {
    const response = await postCredential(seededDb(), binderRefusing("orchestrator-unreachable"));

    expect(response.statusCode).toBe(502);
    expect(response.json().retryable).toBe(true);
  });
});