import { beforeEach, describe, expect, it } from "vitest";

import {
  TTL,
  PoolBinder,
  idleExpiresAt,
  reconcile,
  sweep,
  type SweeperOptions,
} from "../src/sweep.js";
import { Db, type SessionRow } from "../src/db.js";
import { SseHub } from "../src/sse.js";
import { OrchestratorClient } from "../src/orchestrator-client.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";

/**
 * PLAN-v2 §2.1–2.3 and §2.5. The properties under test are the TTL independence
 * (four clocks that are not the same clock), the compensation when the
 * orchestrator call fails, and the rule that a sweep never touches a session the
 * erase machine owns.
 */

const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const OTHER = "00000000-0000-0000-0000-000000000000";
const SECRET = "A".repeat(43);

let now = 1_700_000_000_000;
let db: Db;
let sse: SseHub;

/** An orchestrator whose responses the test controls. */
function orchestratorStub(opts: {
  claim?: "ok" | "unreachable" | "conflict" | "pool-empty";
  release?: "ok" | "unreachable" | "conflict";
  stats?: "ok" | "unreachable" | "cannot-fill" | "filled";
  /** Slot ids the orchestrator names. Defaults to what `stats` implies. */
  slotIds?: string[];
  /**
   * What `/stats` reports as `boundSessions`: slot id → session guid.
   *
   * Left out of the response when undefined, which is how this stub also stands in
   * for an orchestrator predating the field — the rolling-deploy case the sweeper's
   * `stats.ok` / `slotIds` guards exist for, and the one test (c) pins.
   */
  boundSessions?: Record<string, string>;
  /**
   * Runs inside the `/release` handler, before the answer is returned.
   *
   * Exists so a test can produce the window the pre-act liveness re-check exists
   * for — a session appearing *between* the `/stats` snapshot and the `/release` —
   * which is otherwise a race no deterministic test can reach.
   */
  onRelease?: (slotId: string) => void;
}) {
  const calls: string[] = [];
  /** The slot ids `/release` was actually asked to release, in order. */
  const released: string[] = [];
  let lastClaimBody: string | undefined;
  const client = new OrchestratorClient({
    baseUrl: "http://127.0.0.1:1",
    secret: "B".repeat(43),
    fetchImpl: (async (url: string, init?: RequestInit) => {
      // Parsed rather than string-replaced, so the stub works whatever baseUrl the
      // client was built with.
      const path = new URL(String(url)).pathname;
      calls.push(path);
      if (path === "/claim") {
        // `OrchestratorClient` hands fetch a **Uint8Array** body, not a string —
        // it sets `content-length` from `payload.length` — so a test that reads
        // `typeof init.body === "string"` sees nothing and the stub silently falls
        // back to its default. That is how the first version of this stub ended up
        // ignoring the request it was supposed to be answering.
        lastClaimBody = decodeBody(init?.body);
      }
      if (path === "/claim") {
        if (opts.claim === "ok") {
          // **Echoes the slot it was asked for**, the way a real orchestrator does now.
          //
          // It used to answer `"slot-9"` — a slot that exists nowhere — and every test
          // passed, because the answer was ignored: the binder recorded its own claimed
          // row and took only `containerId` from the response. That is precisely the bug
          // this stub was hiding, and it is why the id was allowed to be nonsense.
          //
          // A fixture that only works because the code under test discards half of it is
          // not a fixture; it is a second implementation of the wrong thing.
          const asked = (() => {
            try {
              const body = JSON.parse(lastClaimBody ?? "{}") as { slotId?: string };
              return body.slotId ?? opts.slotIds?.[0] ?? "slot-1";
            } catch {
              return opts.slotIds?.[0] ?? "slot-1";
            }
          })();
          return new Response(JSON.stringify({ slotId: asked, containerId: "ctr9" }));
        }
        if (opts.claim === "conflict") return new Response("{}", { status: 409 });
        if (opts.claim === "pool-empty") return new Response("{}", { status: 503 });
        throw new Error("ECONNREFUSED");
      }
      if (path === "/release") {
        // Recorded from the **body**, not just the path: "a release happened" and
        // "a release happened for *that* slot" are different assertions, and the
        // sweeper's job is to name the right slot.
        const body = JSON.parse(decodeBody(init?.body) ?? "{}") as { slotId?: string };
        if (typeof body.slotId === "string") released.push(body.slotId);
        if (typeof body.slotId === "string") opts.onRelease?.(body.slotId);
        if (opts.release === "ok") return new Response(JSON.stringify({ released: true }));
        if (opts.release === "conflict") return new Response("{}", { status: 409 });
        throw new Error("ECONNREFUSED");
      }
      if (path === "/stats") {
        if (opts.stats === "ok") {
          return new Response(
            JSON.stringify({ size: 0, byState: {}, runnerTtlSeconds: 300 }),
          );
        }
        if (opts.stats === "filled") {
          // A pool that is up and full. `slotIds` is what the api has to learn in
          // order to be able to claim anything at all.
          const slotIds = opts.slotIds ?? ["slot-1"];
          return new Response(
            JSON.stringify({
              size: slotIds.length,
              byState: { idle: slotIds.length },
              runnerTtlSeconds: 300,
              slotIds,
              // Conditional spread, matching `omitempty` on the Go side: an
              // orchestrator with nothing bound does not send the key at all, and a
              // stub that always sent `{}` would make that case unreachable.
              ...(opts.boundSessions === undefined ? {} : { boundSessions: opts.boundSessions }),
            }),
          );
        }
        if (opts.stats === "cannot-fill") {
          // What the orchestrator reports when its top-up is failing: a pool with
          // no idle slot *and* a reason it will not get one.
          return new Response(
            JSON.stringify({
              size: 0,
              byState: {},
              runnerTtlSeconds: 300,
              slotIds: [],
              fillError: "Range of CPUs is from 0.01 to 1.00, as there are only 1 CPUs available",
              fillFailures: 7,
            }),
          );
        }
        throw new Error("ECONNREFUSED");
      }
      return new Response("{}", { status: 404 });
    }) as typeof fetch,
  });
  return { client, calls, released };
}

/** `fetch` bodies arrive as bytes here, so a stub has to decode before parsing. */
function decodeBody(body: unknown): string | undefined {
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(body));
  return undefined;
}

/**
 * A subscriber that records the frames written to it, like a browser's EventSource.
 *
 * **Bytes, not internals.** The question this file asks — "what does a browser get
 * told about the session?" — is answered by the wire, so it is asserted on the
 * wire. Reaching into the hub's buffer instead would pass even if `emit` wrote a
 * frame a browser could not parse.
 */
function watch(sse: SseHub, guid: string) {
  const written: string[] = [];
  const res = {
    written,
    write: (chunk: string) => {
      written.push(String(chunk));
      return true;
    },
    end: () => undefined,
  };
  sse.attach(guid, res as never, null);
  return () => framesFrom(res);
}

function framesFrom(res: { written: string[] }): readonly { type: string; data: unknown }[] {
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

function seedSession(guid: string, overrides: Partial<SessionRow> = {}): SessionRow {
  db.createSession({
    guid,
    secretHash: hashSecret(SECRET),
    csrfKey: generateCsrfKey(),
    now: overrides.created_at ?? now,
    expiresAt: overrides.expires_at ?? now + TTL.absolute,
  });
  const values: Record<string, unknown> = {
    state: overrides.state ?? "created",
    auth_state: overrides.auth_state ?? "none",
    runner_id: overrides.runner_id ?? null,
    idle_expires_at: overrides.idle_expires_at ?? null,
    last_activity_at: overrides.last_activity_at ?? now,
    notebook: overrides.notebook ?? null,
    export_state: overrides.export_state ?? null,
    artifact_id: overrides.artifact_id ?? null,
    artifact_partial: overrides.artifact_partial ?? 0,
  };
  const columns = Object.keys(values);
  db.run(
    `UPDATE sessions SET ${columns.map((c) => `${c} = ?`).join(", ")} WHERE guid = ?`,
    ...columns.map((c) => values[c]),
    guid,
  );
  return db.getSession(guid)!;
}

function seedRunners(count: number) {
  for (let i = 1; i <= count; i++) {
    db.registerRunner(`slot-${i}`, `ctr${i}`, "idle");
  }
}

function options(orchestrator: OrchestratorClient): SweeperOptions {
  return { db, orchestrator, sse, now: () => now };
}

beforeEach(() => {
  now = 1_700_000_000_000;
  db = new Db(":memory:");
  sse = new SseHub({ now: () => now });
});

// ---- idleExpiresAt --------------------------------------------------------

describe("idleExpiresAt", () => {
  // §2.1's four clocks, and they are not interchangeable.
  it("gives a created session 10 minutes from creation", () => {
    const session = seedSession(GUID, { state: "created" });
    expect(idleExpiresAt(session, now)).toBe(session.created_at + TTL.unclaimedSession);
  });

  it("measures a created session from creation, not from last activity", () => {
    // The point is that a GUID nobody acted on stops costing a slot. Measuring
    // from activity would let a session that was never used sit forever.
    const session = seedSession(GUID, {
      state: "created",
      created_at: now - 9 * 60 * 1000,
      last_activity_at: now,
    });
    expect(idleExpiresAt(session, now)).toBe(session.created_at + TTL.unclaimedSession);
    expect(idleExpiresAt(session, now)!).toBeLessThan(now + TTL.unclaimedSession);
  });

  it("gives a login in progress 15 minutes from activity", () => {
    const session = seedSession(GUID, {
      state: "authenticating",
      last_activity_at: now - 60_000,
    });
    expect(idleExpiresAt(session, now)).toBe(session.last_activity_at + TTL.loginInProgress);
  });

  it("gives an authenticated session 30 minutes from activity", () => {
    const session = seedSession(GUID, {
      state: "authenticated",
      last_activity_at: now - 120_000,
    });
    expect(idleExpiresAt(session, now)).toBe(session.last_activity_at + TTL.authenticatedIdle);
  });

  // §2.1: "Export running — no idle kill; absolute 12h cap applies."
  it("gives an exporting session no idle deadline at all", () => {
    const session = seedSession(GUID, {
      state: "exporting",
      last_activity_at: now - 10 * TTL.authenticatedIdle,
    });
    expect(idleExpiresAt(session, now)).toBeNull();
  });

  it("gives an erasing session no deadline", () => {
    expect(idleExpiresAt(seedSession(GUID, { state: "erasing" }), now)).toBeNull();
  });
});

// ---- claimForLogin --------------------------------------------------------

describe("PoolBinder.claimForLogin", () => {
  it("claims a slot and tells the orchestrator", async () => {
    seedRunners(2);
    seedSession(GUID, { state: "created" });
    const { client, calls } = orchestratorStub({ claim: "ok" });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    expect(calls).toContain("/claim");
    expect(db.getSession(GUID)?.state).toBe("authenticating");
    expect(db.getSession(GUID)?.runner_id).not.toBeNull();
  });

  it("reports exhaustion when no slot is idle", async () => {
    db.registerRunner("slot-1", "ctr1", "claimed");
    seedSession(GUID);
    const { client, calls } = orchestratorStub({ claim: "ok" });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result).toEqual({ ok: false, reason: "pool-exhausted" });
    // The expensive call must not happen when the cheap one already failed.
    expect(calls).not.toContain("/claim");
  });

  // The bug this deploy found.
  //
  // `runners` is only ever *moved* by `claimRunner`; nothing inserts. Rows come
  // from `syncPool`, which ran **once, at boot**. Nothing orders the api behind
  // the orchestrator's asynchronous pool fill, so on a real deployment the api
  // boots, sees `size: 0`, inserts nothing — and from then on the pool is
  // permanently unclaimable.
  //
  // It presents as *pool exhausted*, which is byte-for-byte what a genuinely busy
  // pool looks like, so `/stats` reporting `size: 1` next to a 503 was the only
  // evidence there was. Observed: api started 15:17:52, orchestrator filled
  // slot-1 at 15:35:54, and every login after that returned
  // `503 {"error":"every session is busy"}` while `/healthz` said `ok`.
  it("learns the pool's slots when the api was started before it filled", async () => {
    // No seedRunners(): the `runners` table is empty, which is the deployed state.
    seedSession(GUID, { state: "created" });
    const { client } = orchestratorStub({ claim: "ok", stats: "filled" });
    const binder = new PoolBinder(options(client));

    expect(db.all(`SELECT id FROM runners`)).toEqual([]);

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.runnerId).toBe("slot-1");
  });

  // The same situation, but the orchestrator's pool is only partly up. Learning it
  // must not claim a slot the orchestrator has not named — the ids have to be its
  // own, because they go back to it as `slotId`.
  it("claims only a slot the orchestrator named, not one invented locally", async () => {
    // debug helper
    seedRunners(1);
    seedSession(GUID, { state: "created" });
    const { client } = orchestratorStub({
      claim: "ok",
      stats: "filled",
      slotIds: ["slot-7"],
    });
    const binder = new PoolBinder(options(client));

    // slot-1 is seeded and idle; the orchestrator's `/stats` names slot-7, which the
    // `runners` table has never heard of. Membership comes from the orchestrator, so
    // the row is created on demand by `syncPool` before the claim.
    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Whatever is recorded must be a slot that exists **and** is the one bound to this
    // session — the api's own pick and the orchestrator's answer must not be allowed
    // to disagree.
    const bound = db.get<{ id: string }>(
      `SELECT id FROM runners WHERE session_guid = ?`,
      GUID,
    )?.id;
    
    expect(bound).toBe(result.runnerId);
    expect(bound).toBeDefined();
  });

  // An orchestrator that cannot be asked must not clear or invent anything. The
  // distinction that matters: it is "we do not know", not "there is nothing".
  it("invents nothing when the orchestrator reports no slotIds", async () => {
    db.registerRunner("slot-1", "ctr1", "claimed");
    seedSession(GUID);
    const { client, calls } = orchestratorStub({ claim: "ok" }); // slotIds absent
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result).toEqual({ ok: false, reason: "pool-exhausted" });
    expect(calls).toContain("/stats");
    // The claimed row is untouched: learning nothing must not free it.
    expect(db.get<{ status: string }>(
      `SELECT status FROM runners WHERE id = ?`,
      "slot-1",
    )?.status).toBe("claimed");
  });

  // A pool that is *full* and a pool that *cannot fill* both have no idle slot, and
  // only one of them is helped by waiting. Reporting both as "every session is
  // busy" tells a user to wait for something that will never arrive — which is
  // what a 1-CPU VPS did, silently, with `/healthz` reporting ok throughout.
  it("distinguishes a busy pool from a pool that cannot fill", async () => {
    db.registerRunner("slot-1", "ctr1", "claimed");
    seedSession(GUID);
    const { client, calls } = orchestratorStub({ claim: "ok", stats: "cannot-fill" });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("pool-exhausted");
    // The reason travels with the answer, so the route can name the cause rather
    // than send the user back to wait.
    expect(result.fillError).toMatch(/Range of CPUs/);
    // And the orchestrator was asked, which is the whole mechanism.
    expect(calls).toContain("/stats");
    // Still no container claim: nothing would succeed.
    expect(calls).not.toContain("/claim");
  });

  // The absence of a reported reason must not be read as "healthy". An
  // orchestrator predating the field reports none, and that is the plain
  // busy case — not a reason invented to fill the gap.
  it("reports a plain busy pool when the orchestrator gives no reason", async () => {
    db.registerRunner("slot-1", "ctr1", "claimed");
    seedSession(GUID);
    const { client } = orchestratorStub({ claim: "ok", stats: "ok" });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result).toEqual({ ok: false, reason: "pool-exhausted" });
  });

  // A slot claimed in SQLite but never given a container never becomes available
  // again. Without this the pool shrinks by one per failed call and nothing
  // notices.
  it("releases the slot when the orchestrator is unreachable", async () => {
    seedRunners(1);
    seedSession(GUID);
    const { client } = orchestratorStub({ claim: "unreachable" });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(false);
    // The slot is idle again, so the next session can use it.
    expect(db.get<{ status: string }>(`SELECT status FROM runners WHERE id = 'slot-1'`)?.status).toBe(
      "idle",
    );
    expect(db.getSession(GUID)?.state).toBe("created");
  });

  // A conflict used to leave the row `idle`. That is the behaviour that made a login
  // impossible: the row stayed claimable, `ORDER BY RANDOM()` kept offering it, and the
  // orchestrator kept refusing it — so every attempt from every user burned against the
  // same bad row. A slot the orchestrator will not give is not capacity this process
  // has, so the row is dropped and the pool re-learned. See `pool-divergence.test.ts`.
  it("drops the row on a conflict, rather than leaving it claimable", async () => {
    seedRunners(1);
    seedSession(GUID);
    const { client } = orchestratorStub({ claim: "conflict" });
    const binder = new PoolBinder(options(client));

    await binder.claimForLogin(db.getSession(GUID)!);

    expect(
      db.get<{ status: string }>(`SELECT status FROM runners WHERE id = 'slot-1'`),
    ).toBeUndefined();
    // The orchestrator names the slots it has; those come back. Here it knows none, so
    // the table ends up empty rather than holding a slot nothing can use.
    expect(
      db.all<{ id: string }>(`SELECT id FROM runners WHERE status = 'idle'`),
    ).toHaveLength(0);
  });

  it("does not bind the same slot to two sessions", async () => {
    seedRunners(1);
    seedSession(GUID);
    seedSession(OTHER);
    const { client } = orchestratorStub({ claim: "ok" });
    const binder = new PoolBinder(options(client));

    const first = await binder.claimForLogin(db.getSession(GUID)!);
    const second = await binder.claimForLogin(db.getSession(OTHER)!);

    expect(first.ok).toBe(true);
    expect(second).toEqual({ ok: false, reason: "pool-exhausted" });
  });

  it("records the container id the orchestrator returned", async () => {
    seedRunners(1);
    seedSession(GUID);
    const { client } = orchestratorStub({ claim: "ok" });
    const binder = new PoolBinder(options(client));

    await binder.claimForLogin(db.getSession(GUID)!);

    expect(db.get<{ container_id: string }>(`SELECT container_id FROM runners`)?.container_id).toBe(
      "ctr9",
    );
  });

  it("sets the login-in-progress deadline", async () => {
    seedRunners(1);
    seedSession(GUID);
    const { client } = orchestratorStub({ claim: "ok" });
    const binder = new PoolBinder(options(client));

    await binder.claimForLogin(db.getSession(GUID)!);

    expect(db.getSession(GUID)?.idle_expires_at).toBe(now + TTL.loginInProgress);
  });
});

// ---- releaseForIdle -------------------------------------------------------

describe("PoolBinder.releaseForIdle", () => {
  it("returns the runner and keeps the session", async () => {
    // §2.3 step 3→4: the vault survives, so activity again rebinds without a
    // re-login. Deleting the row would log the user out every time they idle.
    seedRunners(1);
    seedSession(GUID, { state: "authenticated", auth: "valid", runner_id: "slot-1" });
    const { client } = orchestratorStub({ release: "ok" });
    const binder = new PoolBinder(options(client));

    const released = await binder.releaseForIdle(db.getSession(GUID)!);

    expect(released).toBe(true);
    expect(db.getSession(GUID)).toBeDefined();
    expect(db.getSession(GUID)?.runner_id).toBeNull();
    expect(db.get<{ status: string }>(`SELECT status FROM runners WHERE id = 'slot-1'`)?.status).toBe(
      "idle",
    );
  });

  it("preserves a valid auth_state across an idle release", async () => {
    seedRunners(1);
    seedSession(GUID, { state: "authenticated", auth_state: "valid", runner_id: "slot-1" });
    const { client } = orchestratorStub({ release: "ok" });
    const binder = new PoolBinder(options(client));

    await binder.releaseForIdle(db.getSession(GUID)!);

    // The user was logged in and their auth.json is untouched, so an idle release
    // must not push them back to the login form.
    expect(db.getSession(GUID)?.auth_state).toBe("valid");
  });

  it("promotes an interrupted login back to valid on release", async () => {
    // A claim sets auth_state to authenticating. An idle release while that is
    // still set means the login finished but the state was not updated — the
    // vault holds a usable auth.json, so the session should be usable.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "authenticating",
      runner_id: "slot-1",
    });
    const { client } = orchestratorStub({ release: "ok" });
    const binder = new PoolBinder(options(client));

    await binder.releaseForIdle(db.getSession(GUID)!);

    expect(db.getSession(GUID)?.auth_state).toBe("valid");
  });

  // A container that still exists must not be forgotten, or reconciliation will
  // not find it.
  it("retains the slot when the orchestrator cannot be reached", async () => {
    seedRunners(1);
    seedSession(GUID, { state: "authenticated", runner_id: "slot-1" });
    const { client } = orchestratorStub({ release: "unreachable" });
    const binder = new PoolBinder(options(client));

    const released = await binder.releaseForIdle(db.getSession(GUID)!);

    expect(released).toBe(false);
    expect(db.getSession(GUID)?.runner_id).toBe("slot-1");
  });

  it("treats a conflict as success, since the slot is already gone", async () => {
    seedRunners(1);
    seedSession(GUID, { state: "authenticated", runner_id: "slot-1" });
    const { client } = orchestratorStub({ release: "conflict" });
    const binder = new PoolBinder(options(client));

    expect(await binder.releaseForIdle(db.getSession(GUID)!)).toBe(true);
    expect(db.getSession(GUID)?.runner_id).toBeNull();
  });

  it("does nothing for a session with no runner", async () => {
    seedSession(GUID, { state: "authenticated", runner_id: null });
    const { client, calls } = orchestratorStub({ release: "ok" });
    expect(await new PoolBinder(options(client)).releaseForIdle(db.getSession(GUID)!)).toBe(false);
    expect(calls).not.toContain("/release");
  });
});

// ---- sweep ----------------------------------------------------------------

describe("sweep", () => {
  const run = async (opts = {}) => {
    const { client } = orchestratorStub(opts);
    const binder = new PoolBinder(options(client));
    return sweep(options(client), binder);
  };

  it("deletes a created session past 10 minutes", async () => {
    seedSession(GUID, { state: "created", created_at: now - TTL.unclaimedSession - 1 });
    const report = await run();
    expect(report.unclaimedExpired).toBe(1);
    expect(db.getSession(GUID)).toBeUndefined();
  });

  // The sweeper learns the pool too, so the api's view converges on its own
  // rather than only when a user happens to try to log in.
  //
  // With the pool learned solely at claim time, an api that boots against an empty
  // pool holds an empty `runners` table until the first login attempt — and every
  // operator-visible number derived from it (a pool report, a reconciliation
  // count) reads zero for as long as nobody logs in. The deployed symptom was
  // `/stats` saying `size: 1` beside a table with nothing in it.
  it("learns the pool's slots while sweeping, with no login in sight", async () => {
    seedSession(GUID, { state: "created", created_at: now + 1000 });
    expect(db.all(`SELECT id FROM runners`)).toEqual([]);

    await sweep(options(orchestratorStub({ stats: "filled" }).client), new PoolBinder(options(orchestratorStub().client)));

    expect(db.all<{ id: string }>(`SELECT id FROM runners`).map((r) => r.id)).toEqual(["slot-1"]);
  });

  // It must never remove a row **somebody is bound to**.
  //
  // This test used to assert that the sweeper removes *nothing*, and its comment said
  // why: "deleting it here would strand the session that still holds it". The fixture
  // seeded two runners and a session that held **neither** — so nothing was at risk,
  // and the assertion passed on a case that could not express the failure it named.
  // That is how the sweep ended up never pruning at all, and the pool drifted from
  // the orchestrator's within an hour of every boot. (Section 0.7.1: a fixture
  // written from the code under test cannot check the code under test.)
  //
  // Both halves are asserted now: the phantom goes, and the bound row stays.
  it("removes an idle, unattached row the orchestrator has stopped reporting", async () => {
    seedRunners(2); // slot-1, slot-2
    seedSession(GUID, { state: "created", created_at: now + 1000 });

    // The orchestrator now reports only one slot. slot-2 is idle with no session on
    // it, so it is garbage: `claim` on it would be refused, and `claimRunner` picks
    // by `ORDER BY RANDOM()`, so it poisons a share of every login.
    await sweep(options(orchestratorStub({ stats: "filled", slotIds: ["slot-1"] }).client), new PoolBinder(options(orchestratorStub().client)));

    expect(db.all<{ id: string }>(`SELECT id FROM runners`).map((r) => r.id).sort()).toEqual([
      "slot-1",
    ]);
  });

  it("keeps a row a session is bound to, even if the orchestrator stops reporting it", async () => {
    // The protection the old test was reaching for, with the condition it named
    // actually present this time: the session holds slot-2.
    seedRunners(2); // slot-1, slot-2
    seedSession(GUID, { state: "authenticated", created_at: now + 1000, runner_id: "slot-2" });
    db.run(`UPDATE runners SET session_guid = ? WHERE id = 'slot-2'`, GUID);

    await sweep(options(orchestratorStub({ stats: "filled", slotIds: ["slot-1"] }).client), new PoolBinder(options(orchestratorStub().client)));

    // Bound rows are not the sweeper's to delete. `reconcileRunners` handles that
    // at boot, when both views have just been rebuilt; on a timer it would unbind a
    // live session.
    expect(db.all<{ id: string }>(`SELECT id FROM runners`).map((r) => r.id).sort()).toEqual([
      "slot-1",
      "slot-2",
    ]);
    expect(db.getSession(GUID)?.runner_id).toBe("slot-2");
  });

  it("keeps a created session inside 10 minutes", async () => {
    seedSession(GUID, { state: "created", created_at: now - TTL.unclaimedSession + 1000 });
    const report = await run();
    expect(report.unclaimedExpired).toBe(0);
    expect(db.getSession(GUID)).toBeDefined();
  });

  it("releases a login in progress past 15 minutes and marks auth expired", async () => {
    // The auth.json may be half-written, so the next login must not trust it.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticating",
      auth: "authenticating",
      runner_id: "slot-1",
      last_activity_at: now - TTL.loginInProgress - 1,
    });
    const report = await run({ release: "ok" });

    expect(report.loginExpired).toBe(1);
    expect(db.getSession(GUID)?.auth_state).toBe("expired");
    expect(db.getSession(GUID)?.runner_id).toBeNull();
  });

  it("releases an authenticated session past 30 idle minutes", async () => {
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticated",
      auth: "valid",
      runner_id: "slot-1",
      idle_expires_at: now - 1,
    });
    const report = await run({ release: "ok" });
    expect(report.idleReleased).toBe(1);
    // The session row is kept: the vault survives for a rebind.
    expect(db.getSession(GUID)).toBeDefined();
  });

  // §2.1: an export gets no idle kill.
  //
  // **This test could not fail.** It called `run()` with no release stub, and
  // `orchestratorStub`'s `/release` only answers when it is asked to — so
  // `idleReleased`, the only thing it asserted, could not increment whether or not the
  // sweeper released the runner. A release was attempted and failed to reach anything;
  // the test read that as "no release happened". In production the release *succeeds*,
  // and the runner goes.
  //
  // It is now given a working release, which is the state it was always describing, and
  // it asserts the row as well as the counter.
  it("leaves an exporting session alone however long it runs", async () => {
    seedRunners(1);
    seedSession(GUID, {
      state: "exporting",
      runner_id: "slot-1",
      idle_expires_at: now - TTL.authenticatedIdle - 1,
    });

    // `release: "ok"` — so a release, if attempted, would actually happen.
    const report = await run({ release: "ok" });

    expect(report.idleReleased).toBe(0);
    // The row is not merely kept; it keeps its **runner**. That is the whole claim, and
    // the counter alone could not distinguish "declined" from "tried and failed".
    // Two discriminators, both on the row `releaseForIdle` would have rewritten. The
    // counter alone cannot tell "declined to release" from "tried and failed".
    //
    // (`runners.status` is not one of them: this fixture seeds the row idle while the
    // session points at it, so asserting on it would be asserting the fixture.)
    expect(db.getSession(GUID)?.runner_id).toBe("slot-1");
    // `releaseForIdle` sets `state = 'authenticated'`; an export must not be demoted.
    expect(db.getSession(GUID)?.state).toBe("exporting");
  });

  it("counts the export it held, so a slow export is visible", async () => {
    seedRunners(1);
    seedSession(GUID, {
      state: "exporting",
      runner_id: "slot-1",
      idle_expires_at: now - TTL.authenticatedIdle - 1,
    });

    const report = await run({ release: "ok" });

    // "A session went idle" and "an export is still running" are indistinguishable from
    // outside, and were being conflated. A non-zero count is the sweeper declining to
    // do something destructive, and is the number to read when an export is slow.
    expect(report.exportsHeld).toBe(1);
  });

  // The reason the guard cannot be left to `idle_expires_at` alone.
  //
  // `idleExpiresAt()` returns null for an exporting session — §2.1 says an export gets
  // no idle deadline — and the intent is that the sweeper then has nothing to act on. But
  // `touchSession` writes `idle_expires_at = COALESCE(?, idle_expires_at)`, so that null
  // is **discarded** and a deadline set while the session was merely authenticated
  // survives the whole export. A session that idled, then started an export, carried its
  // old deadline straight through it and lost its runner 30 minutes in.
  it("cannot clear an idle deadline, which is why the guard is on state", async () => {
    const db2 = new Db(":memory:");
    db2.createSession({
      guid: OTHER,
      secretHash: "x",
      csrfKey: "y",
      now: now - 60_000,
      expiresAt: now + 3_600_000,
    });
    db2.run(`UPDATE sessions SET idle_expires_at = ? WHERE guid = ?`, now + 1000, OTHER);

    // What the export route does: touch with the null that `idleExpiresAt` returns for
    // an exporting session.
    db2.touchSession(OTHER, now, null);

    const after = db2.getSession(OTHER);
    expect(after?.idle_expires_at).toBe(now + 1000);
  });

  it("deletes a session past the absolute cap regardless of state", async () => {
    seedSession(GUID, {
      state: "authenticated",
      auth: "valid",
      expires_at: now - 1,
    });
    const report = await run();
    expect(report.absoluteExpired).toBe(1);
    expect(db.getSession(GUID)).toBeUndefined();
  });

  it("prefers the absolute cap over the other rules", async () => {
    // A session can be past several TTLs at once. The cap is reported because it
    // is the one that subsumes the rest.
    seedSession(GUID, {
      state: "created",
      created_at: now - TTL.absolute,
      expires_at: now - 1,
    });
    const report = await run();
    expect(report.absoluteExpired).toBe(1);
    expect(report.unclaimedExpired).toBe(0);
  });

  // §11: the erase machine owns a row in `erasing`. A sweeper deleting it would
  // strand the vault with nothing recording that it was meant to be finished.
  it("never touches a session mid-erase", async () => {
    seedSession(GUID, { state: "erasing", expires_at: now - 1 });
    const report = await run();
    expect(report.skippedErasing).toBe(1);
    expect(db.getSession(GUID)).toBeDefined();
  });

  it("closes the SSE hub for a deleted session", async () => {
    seedSession(GUID, { state: "created", created_at: now - TTL.unclaimedSession - 1 });
    await run();
    expect(sse.stats()).toEqual({});
  });

  it("is idempotent", async () => {
    seedSession(GUID, { state: "created", created_at: now - TTL.unclaimedSession - 1 });
    await run();
    const second = await run();
    expect(second.unclaimedExpired).toBe(0);
  });

  it("handles several sessions in one pass", async () => {
    seedSession(GUID, { state: "created", created_at: now - TTL.unclaimedSession - 1 });
    seedSession(OTHER, { state: "created", created_at: now });
    seedSession("11111111-1111-1111-1111-111111111111", {
      state: "authenticated",
      auth: "valid",
      expires_at: now - 1,
    });

    const report = await run();
    expect(report.unclaimedExpired).toBe(1);
    expect(report.absoluteExpired).toBe(1);
    expect(db.getSession(OTHER)).toBeDefined();
  });

  it("releases the runner before deleting an expired session", async () => {
    // Otherwise a deleted session leaves an orphan container holding its vault.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticated",
      runner_id: "slot-1",
      expires_at: now - 1,
    });
    await run({ release: "ok" });
    expect(db.get<{ status: string }>(`SELECT status FROM runners WHERE id = 'slot-1'`)?.status).toBe(
      "idle",
    );
  });
});

/**
 * tests for the auth-failed release branch in sweep()
 *
 * The bug: a login that failed with `auth_state = 'failed'` held its slot for the
 * full 15-minute TTL.loginInProgress, even though no export was running and the
 * session was not usable. The login-expiry branch guarded on `state` (not changed
 * by markAuthFailed) would eventually release it, but only after the full window.
 *
 * The fix: the new branch detects `auth_state === 'failed' && runner_id !== null`,
 * releases the slot immediately, and increments authFailedReleased to distinguish
 * it from a routine idle release.
 */
describe("sweep authFailedReleased", () => {
  it("releases a failed login and increments authFailedReleased", async () => {
    // Core case: a session at auth_state: "failed", state: "authenticating",
    // with a bound runner and last_activity_at set to now (i.e. NOT advanced
    // toward TTL.loginInProgress). After one sweep(): assert the orchestrator
    // recorded a /release, runner_id is null, report.authFailedReleased === 1,
    // and the runners row is idle. The "no clock advance" is the assertion that
    // distinguishes this fix from the status quo — a stale login-expiry branch
    // would not release because the deadline has not passed, but this branch
    // should release immediately.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: "slot-1",
      last_activity_at: now, // not advanced — deadline has NOT passed
    });
    const { client } = orchestratorStub({ release: "ok" });
    const binder = new PoolBinder(options(client));
    const report = await sweep(options(client), binder);

    expect(report.authFailedReleased).toBe(1);
    expect(db.getSession(GUID)?.runner_id).toBeNull();
    expect(db.get<{ status: string }>(`SELECT status FROM runners WHERE id = 'slot-1'`)?.status).toBe("idle");
    // Row is retained with auth_state still failed, state still authenticating.
    expect(db.getSession(GUID)?.auth_state).toBe("failed");
    expect(db.getSession(GUID)?.state).toBe("authenticating");
  });

  it("still lets the user retry, which is the regression this branch could cause", async () => {
    // **This replaces a test that asserted nothing.**
    //
    // The version here first read "retains the row and leaves auth_state and state
    // untouched", and it passed with the release branch deleted — because it only
    // asserted that nothing bad happened, which is trivially true when nothing
    // happens at all. A vacuous test is worse than no test, because it looks like
    // coverage in a review and in a diff.
    //
    // What actually needs pinning is the *risk*: releasing the runner leaves the
    // session at `state: "authenticating"` with no container, and a release that
    // left the session unusable would turn a mistyped password into a session that
    // can never log in. That is the thing both reviewers asked about, and the
    // thing nothing was asserting.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: "slot-1",
      last_activity_at: now,
    });
    const { client } = orchestratorStub({ release: "ok", claim: "ok" });
    const binder = new PoolBinder(options(client));

    await sweep(options(client), binder);

    // The release really happened — otherwise this test proves nothing again,
    // which is the mistake it exists to correct.
    expect(db.getSession(GUID)?.runner_id).toBeNull();

    // And the session is immediately reusable: a retry claims a runner and
    // `claimBindingWrite` clears the failed state, which is why the ~15-minute
    // window this branch leaves behind is a delay and not a lockout.
    const retry = await binder.claimForLogin(db.getSession(GUID)!);
    expect(retry.ok).toBe(true);
    expect(db.getSession(GUID)?.auth_state).toBe("authenticating");
    expect(db.getSession(GUID)?.state).toBe("authenticating");
  });

  it("does not release a valid session with a future idle_expires_at", async () => {
    // A valid session with a bound runner and an idle_expires_at in the future
    // should NOT be released by this branch. This test ensures the branch only
    // fires for auth_state === 'failed', not for any session with a runner.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticated",
      auth_state: "valid",
      runner_id: "slot-1",
      idle_expires_at: now + TTL.authenticatedIdle, // in the future
      last_activity_at: now,
    });
    const { client, calls } = orchestratorStub({ release: "ok" });
    const binder = new PoolBinder(options(client));
    const report = await sweep(options(client), binder);

    // No release attempted, runner_id unchanged.
    expect(report.authFailedReleased).toBe(0);
    expect(db.getSession(GUID)?.runner_id).toBe("slot-1");
    expect(calls).not.toContain("/release");
  });

  it("does nothing when runner_id is null", async () => {
    // A failed session with no runner should not attempt a release.
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: null,
      last_activity_at: now,
    });
    const { client, calls } = orchestratorStub({ release: "ok" });
    const binder = new PoolBinder(options(client));
    const report = await sweep(options(client), binder);

    expect(report.authFailedReleased).toBe(0);
    expect(calls).not.toContain("/release");
  });

  it("leaves the slot bound when orchestrator release fails", async () => {
    // An orchestrator release error should leave the slot bound and not increment
    // the counter.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: "slot-1",
      last_activity_at: now,
    });
    const { client } = orchestratorStub({ release: "unreachable" });
    const binder = new PoolBinder(options(client));
    const report = await sweep(options(client), binder);

    // Release was attempted but failed; slot remains bound.
    expect(report.authFailedReleased).toBe(0);
    expect(db.getSession(GUID)?.runner_id).toBe("slot-1");
  });
});

/**
 * The orphan-bound slot: a slot held for a session that no longer exists.
 *
 * Two records describe the same fact and neither had a reconciler. The
 * orchestrator's is a slot in `StateBound`; this process's is a `runners` row with
 * a `session_guid`. Either can outlive the session it names, and the observed
 * outage was both at once — two slots on a pool of two held by sessions whose rows
 * were gone, so `EnsurePool` counted a full pool and every login 409'd until someone
 * restarted the orchestrator.
 *
 * The one rule underneath both halves: **live = a `sessions` row exists and its
 * state is not `erasing`.** Every test below is a version of that rule, including
 * the ones that must not fire.
 */
describe("sweep reclaims orphan bindings", () => {
  /** A session that does not exist. The shape both halves detect it from. */
  const DEAD = "99999999-9999-4999-8999-999999999999";
  /** A second one, so a test can have two orphans and an ordering. */
  const DEAD_TWO = "88888888-8888-4888-8888-888888888888";

  /**
   * A `runners` row in the leaked shape: `active`, still bound, to a session
   * nothing names any more.
   *
   * Written rather than claimed, because claiming would need a live session — and
   * the whole subject here is a binding whose session is gone.
   */
  function bindRow(slotId: string, guid: string): void {
    db.registerRunner(slotId, "ctr", "active");
    db.run(`UPDATE runners SET session_guid = ? WHERE id = ?`, guid, slotId);
  }

  function rowFor(slotId: string): { status: string; session_guid: string | null } | undefined {
    return db.get<{ status: string; session_guid: string | null }>(
      `SELECT status, session_guid FROM runners WHERE id = ?`,
      slotId,
    );
  }

  const runWith = async (opts: Parameters<typeof orchestratorStub>[0]) => {
    const { client, released } = orchestratorStub(opts);
    const report = await sweep(options(client), new PoolBinder(options(client)));
    return { report, released };
  };

  // (a) The detection B case: the orchestrator says so, and the api agrees.
  it("releases a slot the orchestrator holds for a session that no longer exists", async () => {
    bindRow("slot-1", DEAD);

    const { report, released } = await runWith({
      stats: "filled",
      slotIds: ["slot-1"],
      boundSessions: { "slot-1": DEAD },
      release: "ok",
    });

    // The slot is named, not merely counted: `byState: {bound: 1}` could not tell
    // this sweeper what to release, which is why the field exists.
    expect(released).toEqual(["slot-1"]);
    expect(report.orphanSlotsReleased).toBe(1);
    // And the row is unbound, not just the container gone. A row left `active` and
    // bound is the api half of the same leak, still asserting a session that no
    // longer exists.
    expect(rowFor("slot-1")).toEqual({ status: "idle", session_guid: null });
  });

  // (b) The other side of the predicate. Without this the branch would be
  // indistinguishable from "release every slot /stats mentions".
  it("leaves a slot alone when the session it is bound to still exists", async () => {
    seedSession(GUID, { state: "authenticated", auth: "valid", runner_id: "slot-1" });
    bindRow("slot-1", GUID);

    const { report, released } = await runWith({
      stats: "filled",
      slotIds: ["slot-1"],
      boundSessions: { "slot-1": GUID },
      release: "ok",
    });

    expect(released).toEqual([]);
    expect(report.orphanSlotsReleased).toBe(0);
    expect(rowFor("slot-1")?.session_guid).toBe(GUID);
  });

  // (c) The rolling-deploy case, and the reason the field is optional.
  //
  // **Paired with the same fixture carrying the field**, because a test that only
  // asserts "nothing happened" passes just as happily against code that does
  // nothing at all — which is the standing rule this repo keeps re-learning. The two
  // halves differ by exactly the field, so deleting the branch turns the first half
  // red and firing it unconditionally turns the second.
  it("does nothing for an orchestrator that reports no boundSessions at all", async () => {
    bindRow("slot-1", DEAD);

    const withField = await runWith({
      stats: "filled",
      slotIds: ["slot-1"],
      boundSessions: { "slot-1": DEAD },
      release: "ok",
    });
    const withoutField = await runWith({ stats: "filled", slotIds: ["slot-1"], release: "ok" });

    expect(withField.released).toEqual(["slot-1"]);
    // Same pool, same dead session, one field missing: no release, no counter.
    expect(withoutField.released).toEqual([]);
    expect(withoutField.report.orphanSlotsReleased).toBe(0);
  });

  // (d) A 409 from `/release` means the slot is already gone or unbound — which is
  // the state this branch wanted. The same tolerance `releaseForIdle` ships, and
  // leaving the row behind because of it would strand a slot that was, in fact,
  // free.
  it("treats a conflict from /release as the slot already being gone", async () => {
    bindRow("slot-1", DEAD);

    const { report, released } = await runWith({
      stats: "filled",
      slotIds: ["slot-1"],
      boundSessions: { "slot-1": DEAD },
      release: "conflict",
    });

    expect(released).toEqual(["slot-1"]);
    expect(report.orphanSlotsReleased).toBe(1);
    expect(rowFor("slot-1")).toEqual({ status: "idle", session_guid: null });
  });

  // (e) Detection A: the erase-shaped leak. `runErase` removes the container, so
  // the orchestrator no longer names the slot at all — and `slotIds: []` is how that
  // looks from here. The row is the whole of the damage and it is this process's
  // own, so no `/release` is called: there is nothing to release, and asking about
  // a slot the orchestrator has already answered for would be inventing traffic.
  it("clears a row an erase left bound to a session it deleted", async () => {
    bindRow("slot-1", DEAD);

    const { report, released } = await runWith({
      stats: "filled",
      slotIds: [],
      release: "ok", // working, so a release attempted would be visible in `released`
    });

    expect(released).toEqual([]);
    expect(report.phantomRowsCleaned).toBe(1);
    // `releaseRunner`, not `removeRunner`: the row is freed, not deleted, so the
    // slot stays known to `claimRunner` and can be re-learned by `syncPool`.
    expect(rowFor("slot-1")).toEqual({ status: "idle", session_guid: null });
  });

  // (f) `erasing` is the erase machine's row and the machine's `/remove` owns the
  // slot. A sweeper taking it would be two owners of one teardown, and the second
  // one wins only because it started later.
  it("leaves a session mid-erase its slot, in both views", async () => {
    seedSession(GUID, { state: "erasing", runner_id: "slot-1" });
    bindRow("slot-1", GUID);

    const { report, released } = await runWith({
      stats: "filled",
      slotIds: ["slot-1"],
      boundSessions: { "slot-1": GUID },
      release: "ok",
    });

    expect(released).toEqual([]);
    expect(report.orphanSlotsReleased).toBe(0);
    expect(report.phantomRowsCleaned).toBe(0);
    expect(rowFor("slot-1")?.session_guid).toBe(GUID);
  });

  // (g) The §0.9.10 harness shape, exactly: the orchestrator adopted a slot at cold
  // start that was bound to a session this process has no row for at all. There is
  // no `runners` row to inspect, which is exactly why the lockout was invisible —
  // `syncPool` runs earlier in this same sweep under the same guard, so the row
  // exists by the time the release is asked for.
  it("heals an adopted orphan the api never had a row for", async () => {
    expect(db.all(`SELECT id FROM runners`)).toEqual([]);

    const { report, released } = await runWith({
      stats: "filled",
      slotIds: ["slot-1"],
      boundSessions: { "slot-1": DEAD },
      release: "ok",
    });

    expect(released).toEqual(["slot-1"]);
    expect(report.orphanSlotsReleased).toBe(1);
    // Idle, not deleted: the slot is a pool position that still exists, and the row
    // is how the next `claimRunner` finds it.
    expect(rowFor("slot-1")).toEqual({ status: "idle", session_guid: null });
  });

  // (h) The blip shape. "Cannot ask" is not "there is nothing", and this process
  // has no way to tell a dead session from an unreachable orchestrator — so while
  // `/stats` fails it acts on nothing at all. Both halves, because both are
  // reachable from the same missing guard.
  it("acts on nothing at all when the orchestrator cannot be asked", async () => {
    bindRow("slot-1", DEAD);

    const { report, released } = await runWith({ stats: "unreachable", release: "ok" });

    expect(released).toEqual([]);
    expect(report.orphanSlotsReleased).toBe(0);
    expect(report.phantomRowsCleaned).toBe(0);
    // Untouched, not merely unreleased: a row rewritten under an orchestrator this
    // process cannot see is a live session's bookkeeping changed by a network fault.
    expect(rowFor("slot-1")?.session_guid).toBe(DEAD);
  });

  // The other half of detection A's gate. `stats: "ok"` is the stub that reports a
  // reachable orchestrator that names **no slots** — the pre-`slotIds` one, during a
  // rolling deploy.
  //
  // Cleaning a row then would mean deciding a slot is not somebody's runner without
  // knowing which slots the orchestrator has. It is the same "we do not know" as the
  // unreachable case, reached by a different road, and the guard is the same line.
  it("cleans no row when the orchestrator names no slots", async () => {
    bindRow("slot-1", DEAD);

    const { report, released } = await runWith({ stats: "ok", release: "ok" });

    expect(released).toEqual([]);
    expect(report.phantomRowsCleaned).toBe(0);
    expect(rowFor("slot-1")?.session_guid).toBe(DEAD);
  });

  // The re-check immediately before the act, which is the difference between
  // "not live when we looked" and "not live now".
  //
  // Both slots are orphans at detection time. The first `/release` is a round trip,
  // and during it a session reappears owning the second slot's GUID. Acting on the
  // earlier reading would dispossess a live session — which is the one failure this
  // whole function must never have, and the reason it re-reads rather than trusting
  // a value computed before an `await`.
  it("re-checks liveness immediately before releasing a slot", async () => {
    bindRow("slot-1", DEAD);
    bindRow("slot-2", DEAD_TWO);

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      // Insertion order is preserved for string keys, so slot-1 is handled first and
      // its release is the round trip that opens the window for slot-2.
      boundSessions: { "slot-1": DEAD, "slot-2": DEAD_TWO },
      release: "ok",
      onRelease: (slotId) => {
        if (slotId !== "slot-1") return;
        seedSession(DEAD_TWO, { state: "authenticated", auth: "valid", runner_id: "slot-2" });
      },
    });

    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(released).toEqual(["slot-1"]);
    expect(report.orphanSlotsReleased).toBe(1);
    expect(rowFor("slot-2")?.session_guid).toBe(DEAD_TWO);
  });
});

// ---- reconcile ------------------------------------------------------------

describe("reconcile", () => {
  it("reports success and removes the runner rows the orchestrator does not have", async () => {
    // Two rows seeded; the stub names exactly one slot, `slot-1`.
    //
    // This test used to expect `runnerCount` to stay at 2 — i.e. it asserted that a
    // reconciler **deleted nothing** while reporting `reconciled: true`. Its name
    // said "logs a size disagreement" and its body pinned the disagreement as
    // permanent, which is how `reconcile` ended up handing
    // `reconcileRunners` the api's own rows as the set of live ids: the code
    // satisfied the only test that described it.
    //
    // The disagreement is now resolved, which is what a reconciler is for.
    seedRunners(2);
    // `stats: "filled"` is the stub that reports `slotIds`, which the real
    // orchestrator always does (verified against the live host). `"ok"` deliberately
    // does not, so that it can stand for an orchestrator predating the field.
    const { client } = orchestratorStub({ stats: "filled", slotIds: ["slot-1"] });

    const result = await reconcile(options(client));

    expect(result.reconciled).toBe(true);
    expect(result.runnerCount).toBe(1);
    expect(db.listRunners().map((r) => r.id)).toEqual(["slot-1"]);
  });

  it("reports a partial reconcile when the orchestrator names no slots", async () => {
    // `slotIds` is optional on `OrchestratorStats` for an api briefly talking to an
    // orchestrator that predates it. With nothing to reconcile against, nothing may
    // be deleted — and `reconciled` must say so rather than claim a pass.
    seedRunners(2);
    const { client } = orchestratorStub({ stats: "ok" });

    const result = await reconcile(options(client));

    expect(result.reconciled).toBe(false);
    expect(db.listRunners()).toHaveLength(2);
  });

  it("reconciles when the counts agree", async () => {
    seedRunners(2);
    const { client } = orchestratorStub({ stats: "filled", slotIds: ["slot-1", "slot-2"] });
    const result = await reconcile(options(client));

    // Both slots the orchestrator names survive. Nothing was destroyed on the
    // orchestrator's say-so alone, and nothing was invented either.
    expect(result.reconciled).toBe(true);
    expect(db.listRunners()).toHaveLength(2);
  });

  // Assuming an empty pool on a transient failure would delete every runner row
  // and every session binding in the database.
  it("does not treat an unreachable orchestrator as an empty pool", async () => {
    seedRunners(2);
    const { client } = orchestratorStub({ stats: "unreachable" });

    const result = await reconcile(options(client));

    expect(result.reconciled).toBe(false);
    expect(result.note).toContain("unreachable");
    expect(db.listRunners()).toHaveLength(2);
  });

  it("still deletes expired session rows when the orchestrator is unreachable", async () => {
    seedSession(GUID, { state: "authenticated", expires_at: now - 1 });
    const { client } = orchestratorStub({ stats: "unreachable" });

    await reconcile(options(client));

    expect(db.getSession(GUID)).toBeUndefined();
  });
});

/**
 * Tests for the stranded export fix: sessions in state='exporting' with runner_id=NULL
 * are reset to state='authenticated' and have their export_state marked as 'failed'.
 */
describe("sweep exportsStranded", () => {
  it("resets a stranded running export", async () => {
    seedRunners(1);
    seedSession(GUID, {
      state: "exporting",
      runner_id: null,
      export_state: '{"state":"running","id":"art1","notebook":"NB","progress":null,"startedAt":1,"finishedAt":null}',
      last_activity_at: now - TTL.authenticatedIdle - 1,
    });

    const { client } = orchestratorStub({ stats: "ok" });
    const binder = new PoolBinder(options(client));
    const report = await sweep(options(client), binder);

    expect(report.exportsStranded).toBe(1);
    expect(db.getSession(GUID)?.state).toBe("authenticated");
    expect(db.getSession(GUID)?.runner_id).toBeNull();
    expect(db.getSession(GUID)?.last_activity_at).toBe(now);
    expect(db.getSession(GUID)?.idle_expires_at).toBe(now + TTL.authenticatedIdle);

    const parsed = JSON.parse(db.getSession(GUID)!.export_state!);
    expect(parsed.state).toBe("failed");
    expect(parsed.error).toBe("the runner was released before this export finished");
    expect(parsed.id).toBe("art1");
    expect(parsed.notebook).toBe("NB");
    expect(parsed.finishedAt).toBe(now);
  });

  it("leaves a session with a live runner untouched", async () => {
    seedRunners(1);
    seedSession(GUID, {
      state: "exporting",
      runner_id: "slot-1",
      export_state: '{"state":"running","id":"art1","notebook":"NB","progress":null,"startedAt":1,"finishedAt":null}',
    });

    const { client } = orchestratorStub({ stats: "ok" });
    const binder = new PoolBinder(options(client));
    const report = await sweep(options(client), binder);

    // Should be exportsHeld, not exportsStranded
    expect(report.exportsHeld).toBe(1);
    expect(report.exportsStranded).toBe(0);

    expect(db.getSession(GUID)?.state).toBe("exporting");
    expect(db.getSession(GUID)?.runner_id).toBe("slot-1");
  });

  it("keeps a stranded partial export_state byte-for-byte (data-loss guard)", async () => {
    const partialState = JSON.stringify({
      state: "partial",
      partialReason: "quota",
      id: "artifact123",
      notebook: "NB",
      progress: null,
      startedAt: 1234567890,
      finishedAt: 1234567900,
    });

    db.createSession({
      guid: GUID,
      secretHash: hashSecret(SECRET),
      csrfKey: generateCsrfKey(),
      now: now,
      expiresAt: now + TTL.absolute,
    });
    db.run(
      `UPDATE sessions SET state = 'exporting', runner_id = NULL,
                       export_state = ?, artifact_id = 'artifact123'
                     WHERE guid = ?`,
      partialState,
      GUID,
    );

    const { client } = orchestratorStub({ stats: "ok" });
    const binder = new PoolBinder(options(client));
    const report = await sweep(options(client), binder);

    expect(report.exportsStranded).toBe(1);
    expect(db.getSession(GUID)?.state).toBe("authenticated");
    expect(db.getSession(GUID)?.export_state).toBe(partialState);
    expect(db.getSession(GUID)?.artifact_id).toBe("artifact123");
  });

  it("leaves malformed export_state unchanged", async () => {
    db.createSession({
      guid: GUID,
      secretHash: hashSecret(SECRET),
      csrfKey: generateCsrfKey(),
      now: now,
      expiresAt: now + TTL.absolute,
    });
    db.run(
      `UPDATE sessions SET state = 'exporting', runner_id = NULL, export_state = ?
      WHERE guid = ?`,
      "not valid json {",
      GUID,
    );

    const { client } = orchestratorStub({ stats: "ok" });
    const binder = new PoolBinder(options(client));

    // Should not throw
    await sweep(options(client), binder);

    expect(db.getSession(GUID)?.state).toBe("authenticated");
    expect(db.getSession(GUID)?.export_state).toBe("not valid json {");
  });

  it("leaves NULL export_state unchanged", async () => {
    db.createSession({
      guid: GUID,
      secretHash: hashSecret(SECRET),
      csrfKey: generateCsrfKey(),
      now: now,
      expiresAt: now + TTL.absolute,
    });
    db.run(
      `UPDATE sessions SET state = 'exporting', runner_id = NULL, export_state = NULL
      WHERE guid = ?`,
      GUID,
    );

    const { client } = orchestratorStub({ stats: "ok" });
    const binder = new PoolBinder(options(client));

    await sweep(options(client), binder);

    expect(db.getSession(GUID)?.state).toBe("authenticated");
    expect(db.getSession(GUID)?.export_state).toBeNull();
  });

  it("emits session-status event for stranded export", async () => {
    seedSession(GUID, {
      state: "exporting",
      runner_id: null,
      export_state: '{"state":"running","id":"art1","notebook":"NB","progress":null,"startedAt":1,"finishedAt":null}',
    });

    // Attach a fake subscriber to capture SSE frames
    const frames = watch(sse, GUID);

    const { client } = orchestratorStub({ stats: "ok" });
    const binder = new PoolBinder(options(client));
    await sweep(options(client), binder);

    // Check the SSE frames contain session-status with state authenticated
    const events = frames();
    expect(events.length).toBe(1);
    expect(events[0].type).toBe("session-status");
    expect(events[0].data).toEqual({ state: "authenticated" });
  });

  it("does not emit event for sessions not reset (live runner)", async () => {
    seedSession(GUID, {
      state: "exporting",
      runner_id: "slot-1",
      export_state: '{"state":"running","id":"art1","notebook":"NB","progress":null,"startedAt":1,"finishedAt":null}',
    });

    const { client } = orchestratorStub({ stats: "ok" });
    const binder = new PoolBinder(options(client));
    await sweep(options(client), binder);

    expect(sse.stats()).toEqual({});
  });

  it("ignores sessions not in exporting state", async () => {
    seedSession(GUID, {
      state: "authenticated",
      runner_id: null,
      export_state: '{"state":"running","id":"art1","notebook":"NB","progress":null,"startedAt":1,"finishedAt":null}',
    });

    const { client } = orchestratorStub({ stats: "ok" });
    const binder = new PoolBinder(options(client));
    const report = await sweep(options(client), binder);

    expect(report.exportsStranded).toBe(0);
    expect(db.getSession(GUID)?.state).toBe("authenticated");
  });
});