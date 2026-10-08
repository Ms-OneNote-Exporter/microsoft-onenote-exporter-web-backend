// `/api/session/notebooks` could never answer 202.
//
// ## Why this file exists
//
// Found by making a real login work against Microsoft for the first time, then
// pressing the button. The login succeeded — Microsoft asked "Stay signed in?", the
// runner clicked Yes, detected the authenticated notebooks interface, and wrote a
// 52 KB `auth.json` — and listing still answered, on every attempt:
//
//     409 {"error":"not authenticated"}
//
// while the frontend had been sent `login-success` and believed otherwise.
//
// ## The contradiction
//
// Two guards, on the same route:
//
//     if (session.auth_state !== "valid")  → 409 "not authenticated"
//     if (session.runner_id === null)      → 409 "no runner bound to this session"
//
// `auth_state` became `'valid'` in exactly **one** place: `releaseForIdle`, which sets
// `runner_id = NULL` in the same statement. So:
//
//   - while a runner is bound → `auth_state` is `'authenticating'`; the first guard fails
//   - after release         → `auth_state` is `'valid'`;     the second guard fails
//
// **No session state satisfies both.** The route was unreachable, and so was
// `/api/export`, which carries the identical pair.
//
// ## Why every existing test passed
//
// `routes.test.ts` seeds state directly, so it could write `auth_state: 'valid'` and
// `runner_id: 'slot-1'` **together** — a combination no state machine produces, and
// precisely the one that made the route look reachable. The unit under test was the
// guard; what was broken was the path that *sets* the state the guard reads.
//
// So these tests drive the adapter's **public** surface, over the runner's real wire
// format, and assert what the database holds afterwards. No private access and no
// test-only seam in production code: the flow under test is the one that runs.

import { Readable } from "node:stream";
import { beforeEach, describe, expect, it } from "vitest";

import { Db } from "../src/db.js";
import { HttpRunnerAdapter } from "../src/runner-adapter-http.js";
import { SseHub } from "../src/sse.js";

const SECRET = "S".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

let db: Db;

/**
 * One session in the state `claimForLogin` leaves behind: bound to a runner, mid-login.
 *
 * Deliberately not a convenient combination: this is the only state a session is in at
 * this point in a login, and it is the state the two route guards disagreed about.
 */
function dbWithLoggingInSession(): Db {
  const fresh = new Db(":memory:");
  fresh.createSession({
    guid: GUID,
    secretHash: SECRET,
    csrfKey: "C".repeat(43),
    now: Date.now(),
    expiresAt: Date.now() + 3_600_000,
  });
  fresh.run(
    `UPDATE sessions SET state = 'authenticating', auth_state = 'authenticating',
                        runner_id = 'slot-1'
      WHERE guid = ?`,
    GUID,
  );
  return fresh;
}

/** The runner's real inline `data:` form — no `{seq, event}` envelope. */
const frame = (event: Record<string, unknown>): string =>
  `data: ${JSON.stringify(event)}\n\n`;

/**
 * An adapter wired as `index.ts` wires it, over a stub runner that answers the login
 * POST and then publishes `events`.
 *
 * `fetchImpl` is the seam the class already has, so this is the public path: the pump
 * opens `/events`, the stub answers with a stream, and the frame travels the same path
 * it travels in production.
 */
function adapterServing(events: string): HttpRunnerAdapter {
  return new HttpRunnerAdapter({
    // The real per-slot alias, not a convenient hostname: the adapter refuses any
    // address that is not `msout-runner-<slot>`, and a test that used `http://runner`
    // would be exercising a shape production never sends.
    addressFor: () => `http://msout-runner-slot-1:3100`,
    token: "T".repeat(43),
    sse: new SseHub({ bufferEvents: 10, keepaliveMs: 60_000 }),
    onAuthOutcome: (sessionId, outcome) => {
      if (outcome === "authenticated") db.markAuthenticated(sessionId, Date.now());
      else db.markAuthFailed(sessionId, Date.now());
    },
    fetchImpl: (async (input: string | URL | Request) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith("/login")) return new Response("{}", { status: 202 });
      if (url.pathname === "/events") {
        // **Left open on purpose.** A real event stream does not end, and a closed one
        // sends the pump into its bounded-backoff reconnect loop — which is correct
        // behaviour and made this file hang. Holding it open models production and
        // lets `stopPump` be the thing that ends it, which is what ends it there too.
        const encoder = new TextEncoder();
        return new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(encoder.encode(events));
            },
          }),
          { status: 200, headers: { "content-type": "text/event-stream" } },
        );
      }
      return new Response("{}", { status: 404 });
    }) as typeof fetch,
  });
}

/**
 * Polls a condition, failing rather than hanging.
 *
 * `expect.poll` is not used because a condition that never becomes true must produce a
 * *failure with the state it was stuck at*, not a timeout with no explanation — and
 * "auth_state is still authenticating" is the whole diagnosis.
 */
async function waitFor(
  condition: () => boolean,
  what = "the runner's outcome to be recorded",
): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`timed out waiting for ${what}; session row is ${JSON.stringify(row(db))}`);
}

/**
 * Runs a whole login: submit the credential, then let the runner report the outcome.
 *
 * The wait is for the pump to have read the stream, not for a timer — the frame is
 * already in memory, so this is a microtask's worth of work and a `setTimeout` would
 * only add a way for this test to be slow and still pass.
 */
async function loginReporting(
  events: string,
): Promise<void> {
  const adapter = adapterServing(events);
  await adapter.submitCredential({
    sessionId: GUID,
    account: "someone@example.com",
    stream: Readable.from(["account\npassword"]) as never,
  });
  // The pump reads the stream on its own task; one turn of the macrotask queue is
  // enough for an already-buffered stream, and `stopPump` afterwards keeps the test
  // from holding a reconnect timer open.
  await new Promise((resolve) => setTimeout(resolve, 0));
  adapter.stopPump(GUID);
}

function row(fresh: Db): { auth_state: string; runner_id: string | null } | undefined {
  return fresh.get<{ auth_state: string; runner_id: string | null }>(
    `SELECT auth_state, runner_id FROM sessions WHERE guid = ?`,
    GUID,
  );
}

beforeEach(() => {
  db = dbWithLoggingInSession();
});

describe("a login the runner reports as successful", () => {
  it("marks the session valid — the state no other path produced", async () => {
    await loginReporting(frame({ type: "login-success", at: 1 }));

    expect(row(db)?.auth_state).toBe("valid");
  });

  // The bug in one assertion: `valid` and a bound runner were unreachable *together*.
  // If this ever needs loosening, the route is broken again.
  it("keeps the runner bound, so both route guards can pass at once", async () => {
    await loginReporting(frame({ type: "login-success", at: 1 }));

    const after = row(db);
    expect(after?.auth_state === "valid").toBe(true);
    expect(after?.runner_id === null).toBe(false);
  });

  it("moves the session out of authenticating, which is what the idle TTL keys on", async () => {
    await loginReporting(frame({ type: "login-success", at: 1 }));

    expect(row(db)).toBeDefined();
    expect(
      db.get<{ state: string }>(`SELECT state FROM sessions WHERE guid = ?`, GUID)?.state,
    ).toBe("authenticated");
  });

  it("works with nobody subscribed to the api's own event stream", async () => {
    // The database write must not depend on a browser being connected. A missed write
    // is silent, and the frontend that missed it still saw `login-success`.
    await loginReporting(frame({ type: "login-success", at: 1 }));

    expect(row(db)?.auth_state).toBe("valid");
  });
});

describe("a login the runner reports as failed", () => {
  it("records failed rather than leaving the session mid-login", async () => {
    await loginReporting(frame({ type: "login-failed", reason: "network", at: 1 }));

    expect(row(db)?.auth_state).toBe("failed");
  });

  it("does not become valid", async () => {
    // `releaseForIdle` promotes `authenticating` → `valid` on release. With no
    // terminal state for a failure, a login that failed and then idled out was recorded
    // as *authenticated*, with no auth.json anywhere.
    await loginReporting(frame({ type: "login-failed", reason: "network", at: 1 }));

    expect(row(db)?.auth_state === "valid").toBe(false);
  });
});

describe("markAuthenticated", () => {
  it("promotes a session that is mid-login", () => {
    expect(db.markAuthenticated(GUID, Date.now())).toBe(true);
    expect(row(db)?.auth_state).toBe("valid");
  });

  it("does not revive an expired session from a straggler event", () => {
    db.run(`UPDATE sessions SET auth_state = 'expired' WHERE guid = ?`, GUID);

    expect(db.markAuthenticated(GUID, Date.now())).toBe(false);
    expect(row(db)?.auth_state).toBe("expired");
  });

  it("does not drag a released session back to authenticated", () => {
    db.run(`UPDATE sessions SET auth_state = 'none', runner_id = NULL WHERE guid = ?`, GUID);

    expect(db.markAuthenticated(GUID, Date.now())).toBe(false);
    expect(row(db)).toEqual({ auth_state: "none", runner_id: null });
  });

  it("touches last_activity_at, so the session is not swept as idle", () => {
    db.run(`UPDATE sessions SET last_activity_at = 1 WHERE guid = ?`, GUID);

    db.markAuthenticated(GUID, 9_999_999);

    expect(
      db.get<{ last_activity_at: number }>(
        `SELECT last_activity_at FROM sessions WHERE guid = ?`,
        GUID,
      )?.last_activity_at,
    ).toBe(9_999_999);
  });

  it("is idempotent, so a duplicate event is not reported as a change", () => {
    expect(db.markAuthenticated(GUID, Date.now())).toBe(true);
    expect(db.markAuthenticated(GUID, Date.now())).toBe(false);
  });
});

describe("markAuthFailed", () => {
  it("records the failure rather than leaving the session mid-login", () => {
    expect(db.markAuthFailed(GUID, Date.now())).toBe(true);
    expect(row(db)?.auth_state).toBe("failed");
  });

  it("leaves a session already valid alone", () => {
    db.markAuthenticated(GUID, Date.now());

    expect(db.markAuthFailed(GUID, Date.now())).toBe(false);
    expect(row(db)?.auth_state).toBe("valid");
  });
});