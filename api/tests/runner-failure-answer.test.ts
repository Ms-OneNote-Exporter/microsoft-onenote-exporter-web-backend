// The runner said "no". The api said "502 Bad Gateway".
//
// ## What happened
//
// A user clicked "List my notebooks" repeatedly. One click was accepted and the runner
// began scraping — it takes tens of seconds, because it launches a browser and waits
// for OneNote to settle. The next clicks arrived while it was still working.
//
//     runner  POST /sessions/…/notebooks → 409   (responseTime 2.1ms)
//     api     "notebook listing failed"  → 502    (responseTime 20ms)
//
// The runner was not broken. It was **busy**, and it said so in 2.1 ms. The route caught
// every failure, discarded the cause, and answered the same 502 for all of them.
//
// ## Why that is worse than a wrong status code
//
// The adapter already distinguishes these — `busy`, `not-ready`/`no_auth`, `rejected`,
// `no-address` — and `retryable` differs between them:
//
//   - `busy`     → retrying is exactly right, the wait is seconds
//   - `no_auth`  → the container lost its `auth.json`; **no retry helps**, only signing
//                  in again does, and telling the user to retry sends them round the loop
//
// And the log line carried no cause at all. Finding this took reading three logs in
// sequence; a cause in the line would have ended it. That is the same defect as every
// other one in this project: the *handler ran*, the answer was wrong, and nothing said so.
//
// ## What these tests assert
//
// That each distinct runner failure gets its own status, its own words, and an honest
// `retryable` — and that the log names the cause.

import { beforeEach, describe, expect, it } from "vitest";

import { Db } from "../src/db.js";
import { RunnerCallError } from "../src/runner-adapter-http.js";
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
let logged: Array<{ msg: string; payload: Record<string, unknown> }>;

beforeEach(() => {
  db = new Db(":memory:");
  logged = [];
});

async function list(
  failure: unknown,
): Promise<{ statusCode: number; body: Record<string, unknown> }> {
  db.createSession({
    guid: GUID,
    secretHash: hashSecret(SECRET),
    csrfKey: "C".repeat(43),
    now: Date.now(),
    expiresAt: Date.now() + 3_600_000,
  });
  // The state both route guards require, so the request reaches the runner at all.
  db.run(
    `UPDATE sessions SET state = 'authenticated', auth_state = 'valid', runner_id = 'slot-1' WHERE guid = ?`,
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
        listNotebooks: async () => {
          throw failure;
        },
      } as never,
      logger: {
        level: "error",
        hooks: {
          logMethod: (...all: unknown[]) => {
            for (const arg of all) {
              if (Array.isArray(arg)) {
                const msg = arg.find((a) => typeof a === "string");
                const rest = arg.filter(
                  (a): a is Record<string, unknown> =>
                    a !== null && typeof a === "object" && !Array.isArray(a),
                );
                logged.push({
                  msg: typeof msg === "string" ? msg : "",
                  payload: Object.assign({}, ...rest),
                });
              }
            }
          },
        },
      },
    } as unknown as ServerDeps,
    {
      logger: {
        level: "error",
        hooks: {
          logMethod: (...all: unknown[]) => {
            for (const arg of all) {
              if (Array.isArray(arg)) {
                const msg = arg.find((a) => typeof a === "string");
                const rest = arg.filter(
                  (a): a is Record<string, unknown> =>
                    a !== null && typeof a === "object" && !Array.isArray(a),
                );
                logged.push({
                  msg: typeof msg === "string" ? msg : "",
                  payload: Object.assign({}, ...rest),
                });
              }
            }
          },
        },
      },
    },
  );
  await app.ready();
  try {
    const response = await app.inject({
      method: "POST",
      url: "/api/session/notebooks",
      headers: {
        origin: ORIGIN,
        "content-type": "application/json",
        cookie: `${SESSION_COOKIE}=${GUID}:${SECRET}`,
        "x-csrf-token": deriveCsrfToken("C".repeat(43), GUID),
      },
    });
    return { statusCode: response.statusCode, body: response.json() as Record<string, unknown> };
  } finally {
    await app.close();
  }
}

describe("the runner is busy", () => {
  it("is 503 and retryable, not 502", async () => {
    // The exact case from the live host: a second click while the first is scraping.
    const r = await list(new RunnerCallError("busy", "runner is busy"));

    expect(r.statusCode).toBe(503);
  });

  it("says retrying is the right thing to do", async () => {
    const r = await list(new RunnerCallError("busy", "runner is busy"));

    expect(r.body.retryable).toBe(true);
  });

  it("does not claim a gateway is broken", async () => {
    const r = await list(new RunnerCallError("busy", "runner is busy"));

    expect(String(r.body.error)).not.toMatch(/bad gateway|could not be reached/i);
    expect(r.body.reason).toBe("busy");
  });
});

describe("the runner has lost its auth.json", () => {
  it("is not retryable — signing in again is the only thing that helps", async () => {
    // A recycle replaces the container, and the cookie jar went with it. Retrying sends
    // the user round a loop that cannot end.
    const r = await list(
      new RunnerCallError({ kind: "not-ready", reason: "no_auth" }, "no auth"),
    );

    expect(r.body.retryable).toBe(false);
  });

  it("says so in the words the user can act on", async () => {
    const r = await list(
      new RunnerCallError({ kind: "not-ready", reason: "no_auth" }, "no auth"),
    );

    expect(String(r.body.error)).toMatch(/sign in again/i);
    expect(r.statusCode).toBe(409);
  });
});

describe("no runner could be reached at all", () => {
  it("is 502, and says why", async () => {
    // The only genuine transport failure in the set: nothing was dialled.
    const r = await list(new RunnerCallError("no-address", "no address"));

    expect(r.statusCode).toBe(502);
    expect(r.body.retryable).toBe(false);
  });

  it("reports unreachable distinctly from a refused request", async () => {
    const r = await list(new RunnerCallError({ kind: "unreachable", cause: "timeout" }, "no"));

    expect(r.body.reason).toBe("unreachable");
    expect(r.statusCode).toBe(502);
    // A transport failure is the one worth retrying: the container may come back.
    expect(r.body.retryable).toBe(true);
  });
});

describe("the log", () => {
  it("names the cause, which the old line discarded", async () => {
    // The whole reason this took three log files to diagnose.
    await list(new RunnerCallError("busy", "runner is busy"));

    const entry = logged.find((l) => l.msg.includes("notebook listing"));
    expect(entry).toBeDefined();
    expect(entry?.payload.failure).toBe("busy");
  });

  it("records the runner's own status when it refused with one", async () => {
    await list(new RunnerCallError({ kind: "rejected", status: 422, error: "bad" }, "rejected"));

    const entry = logged.find((l) => l.msg.includes("notebook listing"));
    expect(entry?.payload.failure).toBe("rejected");
    expect(entry?.payload.status).toBe(422);
  });
});
