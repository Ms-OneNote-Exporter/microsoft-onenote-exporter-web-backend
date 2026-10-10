/**
 * The Microsoft account travels in a header, and leaves nowhere.
 *
 * mac proposed it after the user pointed out a real product bug: we only ever
 * asked for a password, and a Microsoft sign-in needs an account identifier too.
 * He asked for agreement on the transport before building, because it changes this
 * side, which is the right way round.
 *
 * Three things are asserted here, and the third is the one that is easy to believe
 * rather than check:
 *
 *   1. the preflight **allowlists** the header — without which the browser never
 *      sends the request at all, producing a failure with no cause in our logs;
 *   2. it is required, bounded, and passes through unmodified;
 *   3. nothing logs it.
 *
 * The third has a companion CI grep, because "nothing logs it" is not something a
 * unit test can establish on its own — it is a property of every line of code, now
 * and in whatever comes after.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildServer } from "../src/server.js";
import { ApiConfig, validateOrigins } from "../src/config.js";
import { Db } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { FakeOrchestrator } from "../mock/fake-orchestrator.js";
import { MockRunner } from "../mock/mock-runner.js";
import { PoolBinder, syncPool } from "../src/sweep.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { deriveCsrfToken, generateCsrfKey, hashSecret } from "../src/session.js";
import { MAX_ACCOUNT_CHARS } from "../src/credentials-header.js";

const ORIGIN = "https://microsoft-onenote-exporter.phttp.com";
const SECRET = "A".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const ACCOUNT = "someone@example.com";

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
let runner: MockRunner;
let csrfKey: string;
let app: Awaited<ReturnType<typeof build>>;

async function build() {
  const orchestrator = new FakeOrchestrator({ size: 1 });
  syncPool(db, orchestrator.slotIds());
  const sse = new SseHub({ now: () => Date.now() });
  const instance = buildServer(config, {
    db,
    sse,
    limiter: new RateLimiter({ logSalt: "t" }),
    orchestrator,
    runner,
    eraseRunner: runner,
    poolBinder: new PoolBinder({ db, orchestrator, sse, now: () => Date.now() }),
  });
  await instance.ready();
  return instance;
}

beforeEach(async () => {
  db = new Db(":memory:");
  runner = new MockRunner({ db, sse: new SseHub({ now: () => Date.now() }), speed: 0 });
  csrfKey = generateCsrfKey();
  db.createSession({
    guid: GUID,
    secretHash: hashSecret(SECRET),
    csrfKey,
    now: Date.now(),
    expiresAt: Date.now() + 43_200_000,
  });
  app = await build();
});

afterEach(async () => {
  await app.close();
  db.close();
});

function headers(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "content-type": "text/plain",
    cookie: `${SESSION_COOKIE}=${GUID}:${SECRET}`,
    origin: ORIGIN,
    "x-csrf-token": deriveCsrfToken(csrfKey, GUID),
    ...extra,
  };
}

// ---- 1. the preflight allowlist ------------------------------------------

describe("the credential route's preflight", () => {
  it("allowlists x-microsoft-account", async () => {
    // The failure this prevents is the worst one in the route: a header the
    // preflight does not allowlist means the **preflight fails**, so the browser
    // never transmits the request. No 4xx from us, nothing in our logs, just a
    // console line in his app. mac asked for this to be confirmed and it is the
    // single most confusing outcome available.
    const response = await app.inject({
      method: "OPTIONS",
      url: "/api/session/credential",
      headers: {
        origin: ORIGIN,
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type,x-csrf-token,x-microsoft-account",
      },
    });

    expect(response.statusCode).toBe(204);
    const allowed = String(response.headers["access-control-allow-headers"] ?? "").toLowerCase();
    expect(allowed).toContain("x-microsoft-account");
    // The two it already needed must still be there; adding a third is exactly the
    // kind of edit that loses one.
    expect(allowed).toContain("x-csrf-token");
    expect(allowed).toContain("content-type");
  });

  it("does not reflect whatever the caller asks for", async () => {
    // Reflection would let any origin enumerate what this service accepts, which is
    // reconnaissance for free. The list is fixed.
    const response = await app.inject({
      method: "OPTIONS",
      url: "/api/session/credential",
      headers: {
        origin: ORIGIN,
        "access-control-request-method": "POST",
        "access-control-request-headers": "x-arbitrary-probe",
      },
    });
    const allowed = String(response.headers["access-control-allow-headers"] ?? "").toLowerCase();
    expect(allowed).not.toContain("x-arbitrary-probe");
  });
});

// ---- 2. required, bounded, unmodified --------------------------------------

describe("the account on the credential route", () => {
  it("is required, and refused before anything is forwarded", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: headers({ "x-microsoft-account": "" }),
      payload: "hunter2",
    });
    // 400 rather than 415 or 501: the request is well-formed in every other way.
    expect(response.statusCode).toBe(400);
    expect(runner.lastAccount).toBeNull();
  });

  it("is refused when absent entirely", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: headers(),
      payload: "hunter2",
    });
    expect(response.statusCode).toBe(400);
  });

  it("is bounded, so an unbounded header is not an unbounded thing to log", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: headers({ "x-microsoft-account": "a".repeat(MAX_ACCOUNT_CHARS + 1) }),
      payload: "hunter2",
    });
    expect(response.statusCode).toBe(400);
    expect(runner.lastAccount).toBeNull();
  });

  it("arrives at the runner unmodified", async () => {
    // Not just "accepted". A trim or a case-fold here would be invisible at every
    // layer above and would break the login at the far end.
    for (const account of [
      "someone@example.com",
      "SOMEONE@EXAMPLE.COM",
      "someone@example.co.uk",
      "DOMAIN\\someone", // a UPN, not an address — Microsoft accepts these
      "someone@example.com ",
    ]) {
      await app.close();
      app = await build();
      // **Each iteration must be a first submit, not a replay of the previous one.**
      // The row survives the rebuild above — `beforeEach` seeded the session once and
      // `build()` only makes a new server and SSE hub — so after iteration one the
      // scripted login has written `auth_state = 'valid'`. That is the state the
      // credential route now refuses in §4.7 ("no retry on the credential route"),
      // so without this reset iterations two to five answer 409 and the loop stops
      // testing byte equality at all. It is five different account spellings, not
      // five sign-ins, that is the subject here.
      db.run(
        `UPDATE sessions SET state = 'created', auth_state = 'none' WHERE guid = ?`,
        GUID,
      );
      const response = await app.inject({
        method: "POST",
        url: "/api/session/credential",
        headers: headers({ "x-microsoft-account": account }),
        payload: "hunter2",
      });
      expect(response.statusCode).toBe(202);
      // Byte equality, trailing space and all.
      expect(runner.lastAccount).toBe(account);
    }
  });

  it("does not disturb the password, which stays the only thing in the body", async () => {
    // The whole reason for the header. If an account line ever appears in the body,
    // the delimiter idea has crept back in and the 20 verbatim cases stop meaning
    // what they say.
    await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: headers({ "x-microsoft-account": ACCOUNT }),
      payload: "hunter2",
    });
    expect(runner.lastAccount).toBe(ACCOUNT);
    // The mock discards the bytes by design, so the assertion is structural: the
    // credential-verbatim suite proves they are untouched, over a real socket.
  });

  it("leaves no trace in the database", async () => {
    await app.inject({
      method: "POST",
      url: "/api/session/credential",
      headers: headers({ "x-microsoft-account": "private-address@example.com" }),
      payload: "hunter2",
    });
    for (const row of db.all<Record<string, unknown>>(`SELECT * FROM sessions`)) {
      expect(JSON.stringify(row)).not.toContain("private-address@example.com");
    }
  });
});