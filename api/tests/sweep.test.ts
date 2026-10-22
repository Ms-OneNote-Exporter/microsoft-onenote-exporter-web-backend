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
   * `stats.ok` / `slotIds` guards exist for — **and** for the real one, the all-idle
   * pool, where `Stats()` leaves the map nil and `omitempty` drops the key. Tests
   * (c')–(c'''') are that single absent field with different `byState` bodies under
   * it: what the sweeper does with an absence is not one answer but a fallback, and
   * the fallback's input is the field below.
   */
  boundSessions?: Record<string, string>;
  /**
   * What `/stats` reports as `deadSlots`: slot ids whose container died.
   *
   * Omitted from the response when undefined, for the same reason as
   * `boundSessions` above — the stub then stands in for an orchestrator predating
   * the field, which is the rolling-deploy case this branch's `!== undefined` guard
   * exists for and the one test (d) pins.
   */
  deadSlots?: string[];
  /**
   * What `/stats` reports as `byState`: pool-state name → slot count.
   *
   * Spread over the stub's derived `{ idle: slotIds.length }`, so a test can send the
   * real all-idle body (`{ idle: 2 }`), a pool with something bound elsewhere
   * (`{ idle: 1, bound: 1 }`), the shape a `/release` leaves behind (`{ idle: 1,
   * vacant: 1 }`) or a vocabulary this api has never heard of (`{ idle: 1, warming: 1 }`)
   * — the last of which is what makes `poolBindsNobody`'s refusal non-theatrical.
   *
   * The **default carries no `bound` key**, which is what the real `Stats()` sends: it
   * counts with `byState[string(s.State)]++`, so a state with zero slots contributes no
   * key at all. That default is the D6 body — an all-idle pool with `boundSessions`
   * dropped by `omitempty` — and it is why the stub, not the test, is where the strand
   * is reproduced.
   */
  byState?: Record<string, number>;
  /**
   * What `/stats` reports as `slotRemainingSec`: slot id → seconds of budget left.
   *
   * Omitted from the response when undefined, which is how this stub also stands in
   * for an orchestrator predating the field — the rolling-deploy case the claim's
   * post-claim floor check fails open for.
   */
  slotRemainingSec?: Record<string, number>;
  /**
   * Runs inside the `/release` handler, before the answer is returned.
   *
   * Exists so a test can produce the window the pre-act liveness re-check exists
   * for — a session appearing *between* the `/stats` snapshot and the `/release` —
   * which is otherwise a race no deterministic test can reach.
   */
  onRelease?: (slotId: string) => void;
  /**
   * Slot ids the orchestrator refuses with a 409, whatever else is asked for.
   *
   * `claim` is one answer for every slot, which is what most of this file needs and
   * what makes "the retry tried something else" unobservable. Naming the refusals
   * per slot is what makes it a question with an answer — the api believes in a pool
   * of several slots and the orchestrator will give it one of them.
   *
   * Only consulted when `claim` is `"ok"`, so an existing test's single-answer stub
   * behaves exactly as before.
   */
  refuse?: readonly string[];
}) {
  const calls: string[] = [];
  /** The slot ids `/release` was actually asked to release, in order. */
  const released: string[] = [];
  /** The slot ids `/claim` was actually asked for, in order. */
  const claimAttempts: string[] = [];
  /** The sessions whose vault directory the sweeper asked the orchestrator to remove. */
  const deletedSessionDirs: string[] = [];
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
        // Read off the body, not off the api's own view: "which slot was offered" is
        // the question every retry test here asks, and it has to be answered by the
        // wire rather than by whatever the api believes it claimed.
        const asked = (() => {
          try {
            const body = JSON.parse(lastClaimBody ?? "{}") as { slotId?: string };
            return body.slotId ?? opts.slotIds?.[0] ?? "slot-1";
          } catch {
            return opts.slotIds?.[0] ?? "slot-1";
          }
        })();
        claimAttempts.push(asked);
        if (opts.claim === "ok") {
          // Inside the `"ok"` branch, not beside it: a stub that refuses a named slot
          // while every other slot is claimable is exactly what a pool in disagreement
          // looks like, and a refusal list that only applied when the whole endpoint
          // was refusing would never produce one.
          if (opts.refuse?.includes(asked) === true) return new Response("{}", { status: 409 });
          // **Echoes the slot it was asked for**, the way a real orchestrator does now.
          //
          // It used to answer `"slot-9"` — a slot that exists nowhere — and every test
          // passed, because the answer was ignored: the binder recorded its own claimed
          // row and took only `containerId` from the response. That is precisely the bug
          // this stub was hiding, and it is why the id was allowed to be nonsense.
          //
          // A fixture that only works because the code under test discards half of it is
          // not a fixture; it is a second implementation of the wrong thing.
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
      if (path === "/delete-session-dir") {
        // Recorded from the **body**: "the verb was called" and "the verb was
        // called for *that* session" are different assertions, and the whole
        // point of the verb is the session it names.
        const body = JSON.parse(decodeBody(init?.body) ?? "{}") as { sessionGuid?: string };
        if (typeof body.sessionGuid === "string") deletedSessionDirs.push(body.sessionGuid);
        return new Response(JSON.stringify({ deleted: true }));
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
              // The real shape, and it is a *shaped* default rather than `{}`: `Stats`
              // counts with `byState[string(s.State)]++`, so a state holding no slot
              // contributes no key. A stub that sent `bound: 0` would make "nobody is
              // bound anywhere" unreachable, which is the D6 input.
              byState: { idle: slotIds.length, ...opts.byState },
              runnerTtlSeconds: 300,
              slotIds,
              // Conditional spread, matching `omitempty` on the Go side: an
              // orchestrator with nothing bound does not send the key at all, and a
              // stub that always sent `{}` would make that case unreachable.
              ...(opts.boundSessions === undefined ? {} : { boundSessions: opts.boundSessions }),
              // Same rule, same reason. A stub that always sent `deadSlots: []` would
              // make "this orchestrator predates the field" unreachable, which is the
              // half of the pair that has to stay working.
              ...(opts.deadSlots === undefined ? {} : { deadSlots: opts.deadSlots }),
              // And again for the per-slot budget the claim's floor check reads. The
              // real one carries `omitempty` on it, so a stub that always sent `{}`
              // would make "this orchestrator does not say" unreachable — which is
              // the half that has to keep working during a rolling deploy.
              ...(opts.slotRemainingSec === undefined
                ? {}
                : { slotRemainingSec: opts.slotRemainingSec }),
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
  return { client, calls, released, claimAttempts, deletedSessionDirs };
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

/**
 * The ids the orchestrator was offered, counted once per extra offer.
 *
 * Read off the `/claim` bodies, and asserted as "nothing appears twice" rather than
 * as a particular sequence of picks: `claimRunner` draws with `ORDER BY RANDOM()`, so
 * the order is not a property of the code and pinning it would be pinning a seed. The
 * absence of a repeat is.
 */
function repeats(claimAttempts: readonly string[]): string[] {
  const seen = new Set<string>();
  const twice: string[] = [];
  for (const id of claimAttempts) {
    if (seen.has(id)) twice.push(id);
    seen.add(id);
  }
  return twice;
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

// ---- the retry's exclusion set ----------------------------------------------
//
// ## The failure
//
// A slot the orchestrator refuses (409) is dropped from `runners` — and the retry's
// own re-sync puts it straight back, because `/stats` still lists it. So the next
// `claimRunner` draws from a pool that contains the row just refused, and
// `ORDER BY RANDOM()` makes that a coin flip rather than a certainty. On a two-slot
// pool the login succeeds `(1/2)³ = 12.5%` of the time: **seven of every eight
// sign-ins fail**, on a disagreement a single other row could have fixed.
//
// Dropping the row and *not* re-offering it are two different facts, and only the
// second one makes progress. These tests are about which slots the api is willing to
// offer again, so every one of them reads the `/claim` bodies off the wire rather
// than trusting the api's own bookkeeping.
//
// ## Why the assertions here look like they do
//
// `claimRunner` picks at random, so a single two-slot draw cannot tell a working
// exclusion from a lucky one — the file above had to be rewritten once for exactly
// that reason. The assertions are therefore chosen to hold **every** time with the
// behaviour in place and to fail for the old behaviour, rather than to describe one
// particular sequence of picks:
//   - "no slot is offered twice" is exactly the property, and is independent of which
//     slot is drawn first
//   - the repeated login asks the question forty times, so the old behaviour has to
//     get lucky on every single one of them to pass it

describe("PoolBinder's retry exclusion set", () => {
  it("never offers the orchestrator a slot it has already refused", async () => {
    seedRunners(2);
    seedSession(GUID, { state: "created" });
    // The pool is `slot-1` and `slot-2`, `/stats` names both — so the retry's
    // re-learn really does put the refused row back, which is the whole situation.
    // Only `slot-1` is refused, so a login that respects the exclusion always ends
    // on `slot-2` and one that ignores it ends there only half the time.
    const { client, claimAttempts } = orchestratorStub({
      claim: "ok",
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      refuse: ["slot-1"],
    });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    // The property, and it is the whole one: no slot is ever offered twice. Whether
    // this login needed a retry at all depends on which slot the draw reached first,
    // so nothing here asserts that it did — only that a refused slot never comes
    // round again. Asking the question forty times over is how the same property is
    // asked when it cannot be assumed; that is the test below.
    expect(repeats(claimAttempts)).toEqual([]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Never the refused one, whichever way the draw went — and always the other one,
    // because there are only two.
    expect(result.runnerId).toBe("slot-2");
    expect(result.runnerId).not.toBe("slot-1");
  });

  it("narrows the draw again after each refusal rather than bouncing between two", async () => {
    seedRunners(3);
    seedSession(GUID, { state: "created" });
    // Two refusals and one usable slot. A retry that remembered only the *last*
    // refusal would still be free to re-offer `slot-1`, and a retry that remembered
    // neither has to draw `slot-3` three times running, which is `1/27`. So this
    // pins accumulation rather than mere exclusion, and it does so for 26 runs in 27
    // against the old behaviour.
    const { client, claimAttempts } = orchestratorStub({
      claim: "ok",
      stats: "filled",
      slotIds: ["slot-1", "slot-2", "slot-3"],
      refuse: ["slot-1", "slot-2"],
    });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    // Each refused slot asked for at most once, which is the accumulation: after the
    // second refusal both `slot-1` and `slot-2` are out of the draw.
    expect(repeats(claimAttempts)).toEqual([]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.runnerId).toBe("slot-3");
  });

  it("signs a session in on a slot the orchestrator has not refused", async () => {
    // Three slots, one refused, both draws reachable — so the answer may be either
    // of the two good slots. What it may not be is the refused one, which is what
    // makes this a statement about the draw rather than about a lucky seed.
    seedRunners(3);
    seedSession(GUID, { state: "created" });
    const { client, claimAttempts } = orchestratorStub({
      claim: "ok",
      stats: "filled",
      slotIds: ["slot-1", "slot-2", "slot-3"],
      refuse: ["slot-1"],
    });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(["slot-2", "slot-3"]).toContain(result.runnerId);
    expect(repeats(claimAttempts)).toEqual([]);
    // And the binding is the slot the orchestrator answered with, so nothing is left
    // bound to a row that was refused.
    expect(db.getSession(GUID)?.runner_id).toBe(result.runnerId);
  });

  // The question asked many times rather than once.
  //
  // With the exclusion in place this is *certain* — a refused slot cannot come back,
  // so every one of these sign-ins lands on `slot-2`. Without it, each login has to
  // draw `slot-2` on every one of its three attempts, which is `2^-3`; a run of forty
  // sign-ins passing is therefore something the old behaviour can only manage by
  // getting lucky every time, `2^-120`.
  it("recovers on the first retry for every sign-in, not just the lucky ones", async () => {
    let recovered = 0;
    for (let i = 0; i < 40; i++) {
      // A fresh pool and a fresh session each time, so one login cannot leave the
      // next one a gift.
      db.run(`DELETE FROM runners`);
      seedRunners(2);
      const guid = `3f2504e0-4f89-11d3-9a0c-${String(i).padStart(12, "0")}`;
      seedSession(guid, { state: "created" });
      const { client } = orchestratorStub({
        claim: "ok",
        stats: "filled",
        slotIds: ["slot-1", "slot-2"],
        refuse: ["slot-1"],
      });

      const result = await new PoolBinder(options(client)).claimForLogin(db.getSession(guid)!);

      if (result.ok && result.runnerId === "slot-2") recovered++;
    }
    expect(recovered).toBe(40);
  });

  // A pool whose every slot has been refused is a pool the two sides disagree about,
  // and saying so is the point. Reported as exhaustion it would send the user off to
  // wait for capacity that cannot admit them, and tell an operator nothing is wrong.
  it("reports the disagreement rather than a busy pool once every slot is refused", async () => {
    seedRunners(2);
    seedSession(GUID, { state: "created" });
    const { client } = orchestratorStub({
      claim: "ok",
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      refuse: ["slot-1", "slot-2"],
    });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("slot-conflict");
  });

  // The other half of that condition, and the case that would be broken by a
  // broader rule. A pool with **no** slots is not a disagreement — the two views
  // agree perfectly well — so excluding refused slots must not turn it into one.
  it("still reports plain exhaustion when the orchestrator has no slots at all", async () => {
    seedRunners(1);
    seedSession(GUID, { state: "created" });
    const { client } = orchestratorStub({
      claim: "ok",
      stats: "filled",
      slotIds: [],
      refuse: ["slot-1"],
    });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result).toEqual({ ok: false, reason: "pool-exhausted" });
  });
});

// ---- the claim's post-claim floor check -------------------------------------
//
// A claim creates a container and takes ~57 s worst case. A slot whose container is
// about to be recycled out from under it turns that login into a sign-in that dies on
// its own — and this process cannot see the age at all: it holds no container
// identity (§2.1) and the clock lives on the orchestrator's side. `slotRemainingSec`
// is the orchestrator's answer, and this is the check that acts on it.
//
// Every case below is a case where the check must **not** fire unless it has
// evidence. The metrics are advisory: turning a missing field into a refusal would
// make a rolling deploy an outage, and would refuse hardest exactly when the
// orchestrator is least reachable.

describe("PoolBinder's claim floor check", () => {
  /** A pool of one slot the orchestrator names, so nothing has to be seeded. */
  function oneSlot(opts: {
    remainingSec?: Record<string, number>;
    stats?: "ok" | "unreachable" | "filled";
  }) {
    return orchestratorStub({
      claim: "ok",
      release: "ok",
      stats: opts.stats ?? "filled",
      slotIds: ["slot-1"],
      ...(opts.remainingSec === undefined ? {} : { slotRemainingSec: opts.remainingSec }),
    });
  }

  it("refuses a slot with less than the floor left, and says which reason", async () => {
    seedSession(GUID, { state: "created" });
    const { client } = oneSlot({ remainingSec: { "slot-1": 30 } });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result).toEqual({ ok: false, reason: "slot-expiring", retryable: true });
  });

  it("gives the slot back on both sides rather than keeping a container it distrusts", async () => {
    seedSession(GUID, { state: "created" });
    const { client, released } = oneSlot({ remainingSec: { "slot-1": 30 } });
    const binder = new PoolBinder(options(client));

    await binder.claimForLogin(db.getSession(GUID)!);

    // The orchestrator's half. It is the side that holds the container, and a
    // one-sided release would leave a slot bound to a session this process no longer
    // offers — which is the divergence the `slot-conflict` path repairs by refusing
    // the user's next login.
    expect(released).toEqual(["slot-1"]);
    // This process's half: the row is idle and unattached again, so the next
    // `claimRunner` can offer it and nothing has to wait for a sweep to notice.
    const row = db.get<{ status: string; session_guid: string | null }>(
      `SELECT status, session_guid FROM runners WHERE id = 'slot-1'`,
    );
    expect(row?.status).toBe("idle");
    expect(row?.session_guid).toBeNull();
  });

  it("leaves the session exactly as it found it, so a retry is a clean attempt", async () => {
    seedSession(GUID, { state: "created" });
    const { client } = oneSlot({ remainingSec: { "slot-1": 30 } });
    const binder = new PoolBinder(options(client));

    await binder.claimForLogin(db.getSession(GUID)!);

    // `claimBindingWrite` never ran, so the session was never demoted to
    // `authenticating` and never given a `runner_id` pointing at a container that is
    // about to be destroyed. A retry draws another slot rather than inheriting this.
    expect(db.getSession(GUID)?.state).toBe("created");
    expect(db.getSession(GUID)?.runner_id).toBeNull();
    expect(db.getSession(GUID)?.idle_expires_at).toBeNull();
  });

  // It is a refusal, not a conflict: `#claimWithRetries` retries only the one a
  // different row could fix, and re-drawing here would just draw from a pool that has
  // not had a container replaced yet.
  it("does not retry a refusal — one claim, one answer", async () => {
    seedSession(GUID, { state: "created" });
    const { client, calls } = oneSlot({ remainingSec: { "slot-1": 30 } });
    const binder = new PoolBinder(options(client));

    await binder.claimForLogin(db.getSession(GUID)!);

    expect(calls.filter((path) => path === "/claim")).toHaveLength(1);
  });

  // The floor is a floor, not an off-by-one. Exactly 60 s is enough, because the
  // claim it has to cover costs ~57 s.
  it("accepts a slot sitting exactly on the floor", async () => {
    seedSession(GUID, { state: "created" });
    const { client, released } = oneSlot({ remainingSec: { "slot-1": 60 } });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    expect(released).toEqual([]);
  });

  it("accepts a freshly created container", async () => {
    seedSession(GUID, { state: "created" });
    const { client } = oneSlot({ remainingSec: { "slot-1": 300 } });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.runnerId).toBe("slot-1");
  });

  // A failed `/stats` is "we do not know". It must never read as "this slot has no
  // budget left", which is the failure that would refuse every login during an
  // orchestrator outage — exactly when a login cannot be deferred instead.
  it("proceeds when the orchestrator cannot be asked at all", async () => {
    // Seeded rather than learned, so the SQLite claim succeeds without consulting
    // `/stats`: the only `/stats` this test makes is the floor check's.
    seedRunners(1);
    seedSession(GUID, { state: "created" });
    const { client } = orchestratorStub({ claim: "ok", stats: "unreachable" });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
  });

  // The rolling deploy: an api that shipped the check talking to an orchestrator that
  // has not shipped the field. Absence means "this orchestrator does not say".
  it("proceeds against an orchestrator that does not report a budget", async () => {
    seedSession(GUID, { state: "created" });
    const { client } = oneSlot({});
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
  });

  // A slot missing from the map has no container yet — an age of nothing. That is
  // not the same claim as "no budget left", and reading it as one would refuse the
  // very slots that were about to be handed over.
  it("proceeds when the claimed slot is absent from the map", async () => {
    seedSession(GUID, { state: "created" });
    const { client } = oneSlot({ remainingSec: {} });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    expect(result.ok).toBe(true);
  });

  // ---- a bad draw, not a bad slot ------------------------------------------
  //
  // The floor refusal and a `conflict` both answer "no", and they mean opposite
  // things. A conflict says the orchestrator does not have this slot, and that is a
  // fact about the slot: the retry must not offer it again. The floor says this slot
  // is fine and its container is simply about to be replaced — so it goes back into
  // the pool and stays there.
  //
  // What this pins is the consequence that is reachable: the slot is **given back**,
  // it is **not deleted** as a refused slot would be, and it is **claimable** by the
  // next sign-in. What it cannot pin is the exclusion set itself — that set lives for
  // one `claimForLogin`, and the loop returns on `slot-expiring` rather than
  // retrying, so nothing here survives into a later draw to be asserted on. The
  // code keeps the two refusals apart anyway, because the day the retry does honour
  // `retryable`, a floor refusal written into the exclusion set would shrink the
  // draw by one per bad draw until a login that could have been served reported
  // `pool-exhausted`.
  it("returns an expiring slot to the pool rather than treating it as refused", async () => {
    seedRunners(2);
    seedSession(GUID, { state: "created" });
    // `slot-1` claims fine but is nearly out of budget; `slot-2` is refused with a 409
    // and so is dropped from the draw. Either can be reached first —
    // `ORDER BY RANDOM()` — so the floor is hit on the first attempt or, after
    // `slot-2` is refused, on the retry. Both paths must land in the same place, so
    // neither the answer nor the released slot is asserted conditionally.
    const remaining: Record<string, number> = { "slot-1": 30, "slot-2": 300 };
    const { client, released, claimAttempts } = orchestratorStub({
      claim: "ok",
      release: "ok",
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      refuse: ["slot-2"],
      slotRemainingSec: remaining,
    });
    const binder = new PoolBinder(options(client));

    const result = await binder.claimForLogin(db.getSession(GUID)!);

    // Still its own answer: the retry does not swallow it, and the conflict it may
    // have passed through on the way does not relabel it.
    expect(result).toEqual({ ok: false, reason: "slot-expiring", retryable: true });
    // Given back on the orchestrator's side — the half that holds the container.
    expect(released).toEqual(["slot-1"]);
    // Whatever the draw did, no slot was offered twice: the retry that got here went
    // to `slot-1` rather than back to the `slot-2` that had been refused.
    expect(repeats(claimAttempts)).toEqual([]);

    // And here on ours: `idle`, unattached, and **still present**. A slot recorded
    // as refused would have been deleted, and one recorded as excluded would be
    // about to be withheld from the next draw.
    const row = db.get<{ status: string; session_guid: string | null }>(
      `SELECT status, session_guid FROM runners WHERE id = 'slot-1'`,
    );
    expect(row?.status).toBe("idle");
    expect(row?.session_guid).toBeNull();

    // Which is the property, asserted: with the rest of the pool gone and the slot's
    // budget replenished, the next sign-in takes *that* slot. An exclusion that had
    // swallowed the floor refusal would leave nothing to claim.
    db.run(`DELETE FROM runners WHERE id <> 'slot-1'`);
    remaining["slot-1"] = 300;
    seedSession(OTHER, { state: "created" });

    const second = await binder.claimForLogin(db.getSession(OTHER)!);

    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.runnerId).toBe("slot-1");
  });
});

// ---- releaseForIdle -------------------------------------------------------

describe("PoolBinder.releaseForIdle", () => {
  it("returns the runner and keeps the session", async () => {
    // §2.3 step 3→4: the vault survives, so activity again rebinds without a
    // re-login. Deleting the row would log the user out every time they idle.
    seedRunners(1);
    seedSession(GUID, { state: "authenticated", auth_state: "valid", runner_id: "slot-1" });
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

  // §4.9. The whole safety argument of a guarded write is that it is a no-op when
  // the snapshot it came from has aged, and the only way to see that is to hand the
  // binder a `SessionRow` that disagrees with the row.
  //
  // Constructed rather than raced, because the window it describes is a `/release`
  // round trip wide: `sweep` reads every session at the top of the tick, then walks
  // that list with an orchestrator call between the decision and the write. The
  // snapshot below is exactly what the binder holds in that window.
  it("leaves a binding that has moved on alone, because the snapshot is stale", async () => {
    seedRunners(2);
    seedSession(GUID, { state: "authenticated", auth_state: "valid", runner_id: "slot-2" });
    // The tick read the session before slot-2 was claimed; it is deciding about the
    // idle deadline of slot-1, which is what the row said then.
    const stale = { ...db.getSession(GUID)!, runner_id: "slot-1" };
    const { client } = orchestratorStub({ release: "ok" });

    expect(await new PoolBinder(options(client)).releaseForIdle(stale)).toBe(true);

    // The unguarded `WHERE guid = ?` cleared this, and the session was left naming a
    // slot the orchestrator had never been asked to release — so a container it was
    // actively using became unreachable, and the pool handed the slot to somebody
    // else. Both records agreed afterwards, which is what makes it unrepairable.
    expect(db.getSession(GUID)?.runner_id).toBe("slot-2");
  });

  it("still releases the slot it decided about, stale snapshot or not", async () => {
    // The complement, and the reason the guard is a WHERE clause rather than an
    // early return: "this is no longer the session's binding" says nothing about
    // "the container should not have been released".
    seedRunners(2);
    seedSession(GUID, { state: "authenticated", auth_state: "valid", runner_id: "slot-2" });
    const stale = { ...db.getSession(GUID)!, runner_id: "slot-1" };
    const { client, released } = orchestratorStub({ release: "ok" });

    await new PoolBinder(options(client)).releaseForIdle(stale);

    expect(released).toEqual(["slot-1"]);
  });
});

/**
 * releaseForAuthFailure's guard — §4.9 again, and the window is wider here.
 *
 * A failed login is precisely the state a user leaves by signing in again, so this
 * branch is the one a re-login is most likely to land in the middle of: the snapshot
 * says `runner_id = slot-1`, the `/release` round trip runs, and the user submits a
 * credential that claims slot-2 and writes it.
 */
describe("PoolBinder.releaseForAuthFailure", () => {
  it("leaves a binding that has moved on alone, because the snapshot is stale", async () => {
    seedRunners(2);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: "slot-2",
    });
    const stale = { ...db.getSession(GUID)!, runner_id: "slot-1" };
    const { client } = orchestratorStub({ release: "ok" });

    expect(await new PoolBinder(options(client)).releaseForAuthFailure(stale)).toBe(true);

    expect(db.getSession(GUID)?.runner_id).toBe("slot-2");
  });

  it("still releases the slot it decided about, stale snapshot or not", async () => {
    seedRunners(2);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: "slot-2",
    });
    const stale = { ...db.getSession(GUID)!, runner_id: "slot-1" };
    const { client, released } = orchestratorStub({ release: "ok" });

    await new PoolBinder(options(client)).releaseForAuthFailure(stale);

    expect(released).toEqual(["slot-1"]);
  });

  // ...and the guarded form has to leave the *other* fields alone too, because the
  // reason this method exists is that its delta is deliberately the smallest one:
  // `releaseForIdle`'s UPDATE would write `state = 'authenticated'` beside an
  // `auth_state = 'failed'`, which is a signed-in-looking snapshot for a refused
  // login.
  it("writes nothing at all when the binding has moved on", async () => {
    seedRunners(2);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: "slot-2",
      idle_expires_at: now + 1000,
    });
    const stale = { ...db.getSession(GUID)!, runner_id: "slot-1" };
    const before = db.getSession(GUID)!;
    const { client } = orchestratorStub({ release: "ok" });

    await new PoolBinder(options(client)).releaseForAuthFailure(stale);

    expect(db.getSession(GUID)).toEqual(before);
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
    // **The key was `auth`, not `auth_state`, and the test was passing anyway.**
    //
    // `seedSession` reads `overrides.auth_state`; `auth` is not a key of
    // `SessionRow` at all, so the fixture silently seeded `auth_state = 'none'` —
    // no login in progress — and this branch fired on `state` alone. The moment the
    // branch was also guarded on `auth_state` (issue #49) the fixture stopped
    // describing the case and the test went red, which is the only reason anyone
    // finds out that a fixture was a fiction. It now says what it meant.
    //
    // The auth.json may be half-written, so the next login must not trust it.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "authenticating",
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
      auth_state: "valid",
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
      auth_state: "valid",
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
    expect(report.pendingErases).toBe(1);
    expect(db.getSession(GUID)).toBeDefined();
  });

  it("closes the SSE hub for a deleted session", async () => {
    seedSession(GUID, { state: "created", created_at: now - TTL.unclaimedSession - 1 });
    await run();
    expect(sse.stats()).toEqual({});
  });

  // B6: the sweeper's unclaimed-expiry branch emits session-status {state:"expired"} before dropping the stream
  it("emits session-status expired for unclaimed sessions", async () => {
    const watchFrames = watch(sse, GUID);
    seedSession(GUID, { state: "created", created_at: now - TTL.unclaimedSession - 1 });
    await run();

    const frames = watchFrames();
    // The expired frame should be emitted before the stream is dropped
    expect(frames).toEqual([{ type: "session-status", data: { state: "expired" } }]);
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
      auth_state: "valid",
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
 * Issue #49: a login Microsoft **refused** is not a login that timed out.
 *
 * ## The shape
 *
 * `markAuthFailed` writes `auth_state = 'failed'` and deliberately does not touch
 * `state` — the login is still the session's current phase, so retrying from the
 * sign-in screen is not a new session. The sweeper's login-expiry branch was guarded
 * on `state` alone, so fifteen minutes after a mistyped password it fired, overwrote
 * `auth_state` with `'expired'` and emitted `challenge-expired`. The user was told
 * their MFA window had closed; the truth was that their password was wrong, and the
 * refusal had been sitting unreadable in the database the whole time.
 *
 * The fix adds `auth_state === "authenticating"` to the guard, so the branch is now
 * only about a login genuinely still in flight. **Removing either term turns the
 * first test below red** — that is what makes it a regression test and not a
 * description.
 *
 * ## What falls through once it no longer matches
 *
 * A refused login now reaches the idle branch and the auth-failed branch below it,
 * which it used to skip over via the expiry branch's `continue`. Both are pinned
 * here, because "does not do the wrong thing" is only half a claim — the other half
 * is that the right thing still happens to the row.
 */
describe("sweep does not reclassify a refused login", () => {
  it("leaves auth_state failed past 15 minutes instead of expiring it", async () => {
    // The bug, as one scenario: a wrong password, the clock run forward past
    // `TTL.loginInProgress`, one sweep. Before the fix this ended with
    // `loginExpired === 1`, `auth_state === "expired"` and a `challenge-expired`
    // frame on the wire.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: "slot-1",
      // Past the login deadline, which is the whole point: this is the clock that
      // used to decide the password had "expired".
      last_activity_at: now - TTL.loginInProgress - 1,
      // Controlled explicitly so the idle branch cannot decide this test's outcome.
      idle_expires_at: now + TTL.authenticatedIdle,
    });
    const frames = watch(sse, GUID);
    const { client, released } = orchestratorStub({ release: "ok" });
    const binder = new PoolBinder(options(client));

    const report = await sweep(options(client), binder);

    // The branch did not fire — not the counter alone, which a changed
    // implementation could satisfy some other way, but the row it would have written.
    expect(report.loginExpired).toBe(0);
    expect(db.getSession(GUID)?.auth_state).toBe("failed");
    // The lie the user was told, asserted on the wire rather than on the counter:
    // no MFA prompt was ever outstanding, so nothing expired.
    expect(frames().map((f) => f.type)).not.toContain("challenge-expired");
    // And the slot was freed anyway, on the very tick the failure was noticed —
    // which is the other half of the same fix. A quarter-hour of lockout on a
    // two-slot pool was the cost of the branch that must not fire.
    expect(report.authFailedReleased).toBe(1);
    expect(released).toEqual(["slot-1"]);
    expect(db.getSession(GUID)?.runner_id).toBeNull();
  });

  it("releases a refused login whose idle deadline has passed, without promoting it", async () => {
    // **The fall-through case: the refused login now reaches the idle branch.**
    //
    // Before the fix the expiry branch `continue`d, so a failed session never got
    // here. Now it does, and `releaseForIdle`'s UPDATE does three things to this
    // row — releases the slot, writes `state = 'authenticated'`, and promotes
    // `auth_state` `'authenticating'` → `'valid'`. The last one is the one that
    // would have turned a refused login into a working session, and `auth_state` is
    // already `'failed'`, so its `CASE` leaves it alone. That is the property worth
    // pinning, because the alternative — a failed login reachable through
    // `/api/export` with no auth.json anywhere — is silent.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: "slot-1",
      last_activity_at: now - TTL.loginInProgress - 1,
      idle_expires_at: now - 1,
    });
    const { client } = orchestratorStub({ release: "ok" });
    const binder = new PoolBinder(options(client));

    const report = await sweep(options(client), binder);

    // It really released — asserted here because "nothing happened" and "the right
    // thing happened" both end in a row nobody can use, and only the counter and
    // the nulled `runner_id` tell them apart.
    expect(report.idleReleased).toBe(1);
    expect(db.getSession(GUID)?.runner_id).toBeNull();
    // Not promoted. This is the gate every authenticated route reads
    // (`routes.ts`: `if (session.auth_state === "valid")`), so `auth_state` alone
    // decides whether this row is a signed-in session — and `releaseForIdle` does
    // rewrite `state` to `'authenticated'` on the way past, which is precisely why
    // the assertion cannot be made on `state`.
    expect(db.getSession(GUID)?.auth_state).toBe("failed");
    expect(db.getSession(GUID)?.auth_state === "valid").toBe(false);
    // And the auth-failed branch still runs: the in-memory row read at the top of
    // the loop still names the slot, so its counter is what an operator reads.
    expect(report.authFailedReleased).toBe(1);
  });

  it("leaves a runner-less refused login alone entirely, until the 12h cap", async () => {
    // **The other fall-through case, and the one production actually hits.**
    //
    // The previous tick's auth-failed branch already released the slot, so this is
    // what most refused logins look like on their next sweep: no runner, a failed
    // auth_state, a `state` that is still `authenticating` — which is a row no
    // login-expiry branch may act on. It must survive untouched until the absolute
    // cap, because a retry on the sign-in screen claims a fresh slot onto this same
    // session (the `claimForLogin` test above).
    seedSession(GUID, {
      state: "authenticating",
      auth_state: "failed",
      runner_id: null,
      last_activity_at: now - TTL.loginInProgress - 1,
      // Past, deliberately: this is the idle branch's own deadline and the case
      // where it must turn out to be a no-op rather than a rewrite.
      idle_expires_at: now - 1,
    });
    const { client, calls } = orchestratorStub({ release: "ok" });
    const binder = new PoolBinder(options(client));

    const report = await sweep(options(client), binder);

    // Nothing to release, so nothing was asked for — `releaseForIdle` returns
    // early on a null `runner_id` rather than calling the orchestrator.
    expect(report.idleReleased).toBe(0);
    expect(report.authFailedReleased).toBe(0);
    expect(calls).not.toContain("/release");
    // The row is untouched and still there: not deleted by any branch, and still
    // short of the 12-hour cap.
    expect(db.getSession(GUID)).toBeDefined();
    expect(db.getSession(GUID)?.state).toBe("authenticating");
    expect(db.getSession(GUID)?.auth_state).toBe("failed");
    expect(report.absoluteExpired).toBe(0);
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
    seedSession(GUID, { state: "authenticated", auth_state: "valid", runner_id: "slot-1" });
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
        seedSession(DEAD_TWO, { state: "authenticated", auth_state: "valid", runner_id: "slot-2" });
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

  // A live runner is a **bound** slot, and the orchestrator has to say so. This used to
  // answer `stats: "ok"` — a pool of *zero* slots — and stand down only because the old
  // code had no way to read the answer. It can now, and a pool of zero slots says
  // plainly that nothing is bound to anybody: the fixture was contradicting its own name,
  // and the unread field was the only thing hiding it.
  it("leaves a session with a live runner untouched", async () => {
    seedRunners(1);
    seedSession(GUID, {
      state: "exporting",
      runner_id: "slot-1",
      export_state: '{"state":"running","id":"art1","notebook":"NB","progress":null,"startedAt":1,"finishedAt":null}',
    });

    const { client } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      byState: { bound: 1 },
    });
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
/**
 * Tests for the dead-runner fix: a session in state='exporting' whose runner
 * container died while its row was still intact.
 *
 * ## The gap this closes
 *
 * The suite above repairs an exporting session with **no** runner id. This one is
 * the shape that branch deliberately cannot reach, and it was the one that actually
 * wedged sessions: `runner_id` set, a `runners` row saying the slot was bound, and
 * both records *true* — of a container that no longer existed. Nothing was
 * inconsistent, so nothing was repairable by a reconciler comparing two records. The
 * export's own runner is the only writer of `export-done`, so the walk could never
 * finish, and `POST /api/export` refused every future export with a 409 until the
 * 12-hour absolute cap erased the session.
 *
 * The orchestrator is the only side that can see the container is gone; this process
 * is the only side that can act on it. `deadSlots` is the whole conversation.
 */
describe("sweep exportsRunnerDied", () => {
  const RUNNING =
    '{"state":"running","id":"art1","notebook":"NB","progress":null,"startedAt":1,"finishedAt":null}';

  /** The exported session, plus a `runners` row that says its slot is bound. */
  function seedExportingOnDeadSlot(guid = GUID, slotId = "slot-1"): void {
    seedRunners(1);
    db.run(`UPDATE runners SET status = 'active', session_guid = ? WHERE id = ?`, guid, slotId);
    seedSession(guid, {
      state: "exporting",
      runner_id: slotId,
      export_state: RUNNING,
    });
  }

  const rowFor = (slotId: string) =>
    db.get<{ status: string; session_guid: string | null }>(
      `SELECT status, session_guid FROM runners WHERE id = ?`,
      slotId,
    );

  // (a) The whole repair, in one tick.
  //
  // The `runner_id` assertion is the regression this branch exists for: `releaseRunner`
  // frees the `runners` row and does **not** null `sessions.runner_id`, so a repair
  // that released the slot without clearing the session's binding would leave it
  // pointing at a slot the orchestrator has already given back — claimable by someone
  // else, and believed by this session until the cap.
  it("releases the slot, clears the binding and ends the export in one tick", async () => {
    seedExportingOnDeadSlot();
    const frames = watch(sse, GUID);

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      deadSlots: ["slot-1"],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    // Named, once. "A release happened" and "a release happened for that slot" are
    // different assertions.
    expect(released).toEqual(["slot-1"]);
    expect(report.exportsRunnerDied).toBe(1);

    const session = db.getSession(GUID)!;
    // **The regression assertion.** `markExportStranded` requires `runner_id IS NULL`,
    // so without this the repair is a no-op on the row that matters.
    expect(session.runner_id).toBeNull();
    expect(session.state).toBe("authenticated");
    expect(session.idle_expires_at).toBe(now + TTL.authenticatedIdle);

    const parsed = JSON.parse(session.export_state!);
    expect(parsed.state).toBe("failed");
    // Not the default string: this runner was not released, it disappeared, and the
    // two are different failures told to a user staring at a frozen card.
    expect(parsed.error).toBe("the runner disappeared before this export finished");
    expect(parsed.id).toBe("art1");

    // And the slot is claimable again. A `runners` row left `active` is invisible to
    // `claimRunner`'s `WHERE status = 'idle' AND session_guid IS NULL`, so ending the
    // wedged export that way would wedge the slot instead.
    expect(rowFor("slot-1")).toEqual({ status: "idle", session_guid: null });

    // The browser is told, because the one writer that would have ended the progress
    // card is the thing that died.
    const events = frames();
    expect(events.length).toBe(1);
    expect(events[0].type).toBe("session-status");
    expect(events[0].data).toEqual({ state: "authenticated" });
  });

  // (b) The false-positive guard, and the reason the list is narrow evidence rather
  // than "the slot looks busy". Everything is the same except that the runner is alive.
  //
  // **And "alive" has to be said on the wire.** `bound: 1` is the whole difference
  // between this and (a) once `byState` is read: the stub's derived default is
  // `{ idle: 1 }` with no `bound` key — the D6 body — so the identical fixture without
  // this line would now measure the *repair* rather than the hold. A pool reporting that
  // nothing is bound anywhere is precisely what branch C exists for, and it would be
  // right to act on it.
  it("holds a live runner, and releases nothing", async () => {
    seedExportingOnDeadSlot();

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      deadSlots: [],
      byState: { bound: 1 },
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(released).toEqual([]);
    expect(report.exportsRunnerDied).toBe(0);
    // Held, as it must be: an export in flight is not an idle session.
    expect(report.exportsHeld).toBe(1);
    expect(report.exportsStranded).toBe(0);
    expect(db.getSession(GUID)?.state).toBe("exporting");
    expect(db.getSession(GUID)?.runner_id).toBe("slot-1");
    expect(rowFor("slot-1")?.session_guid).toBe(GUID);
  });

  // (c) A release that fails for any reason other than a conflict.
  //
  // **The row is retained, whole.** Clearing it here would orphan the slot: not
  // released on the orchestrator's side, not bound on this one, and the next session
  // to claim something takes a container that is still running. The cost of being
  // wrong in this direction is that the session stays wedged for one more sweep
  // interval; the cost of the other direction is somebody else's runner.
  it("retains the row when the release fails for a reason other than a conflict", async () => {
    seedExportingOnDeadSlot();
    const frames = watch(sse, GUID);

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      deadSlots: ["slot-1"],
      release: "unreachable",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(released).toEqual(["slot-1"]);
    expect(report.exportsRunnerDied).toBe(0);
    // Untouched, not merely unreleased: state, binding and the in-flight export are
    // all still what they were, so the next sweep tries again.
    const session = db.getSession(GUID)!;
    expect(session.state).toBe("exporting");
    expect(session.runner_id).toBe("slot-1");
    expect(JSON.parse(session.export_state!).state).toBe("running");
    expect(rowFor("slot-1")?.session_guid).toBe(GUID);
    // Nothing announced, because nothing changed that a browser could see.
    expect(frames().length).toBe(0);
  });

  // A 409 is not a failure: it means the slot is already gone or already unbound,
  // which is exactly the state this branch wanted. The same tolerance
  // `releaseForIdle` ships, so the two cannot disagree about what a 409 means.
  it("treats a conflict from /release as the slot already being gone", async () => {
    seedExportingOnDeadSlot();

    const { client } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      deadSlots: ["slot-1"],
      release: "conflict",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(report.exportsRunnerDied).toBe(1);
    expect(db.getSession(GUID)?.runner_id).toBeNull();
    expect(db.getSession(GUID)?.state).toBe("authenticated");
  });

  // (d) The rolling deploy, and the reason the field is optional.
  //
  // **Paired with the same fixture carrying the field**, because a test that only
  // asserts "nothing happened" passes just as happily against code that does nothing
  // at all — which is the standing rule this repo keeps re-learning. The two halves
  // differ by exactly the field, so deleting the branch turns the first red and
  // firing it unconditionally turns the second.
  it("does nothing for an orchestrator that reports no deadSlots at all", async () => {
    seedExportingOnDeadSlot();
    const runWith = async (opts: Parameters<typeof orchestratorStub>[0]) => {
      const { client, released } = orchestratorStub(opts);
      const report = await sweep(options(client), new PoolBinder(options(client)));
      return { report, released };
    };

    const withField = await runWith({
      stats: "filled",
      slotIds: ["slot-1"],
      deadSlots: ["slot-1"],
      // Live runner, on both fixtures: the slot is `bound`, so branch C stands down and
      // the half-pinned question stays the only one this test asks. See (b) above for why
      // it cannot be left to the stub's default.
      byState: { bound: 1 },
      release: "ok",
    });
    // Same pool, same dead runner, one field missing. A fresh session, because the
    // first run repaired the only one.
    seedExportingOnDeadSlot(OTHER, "slot-1");
    const withoutField = await runWith({
      stats: "filled",
      slotIds: ["slot-1"],
      byState: { bound: 1 },
      release: "ok",
    });

    expect(withField.report.exportsRunnerDied).toBe(1);
    expect(withoutField.released).toEqual([]);
    expect(withoutField.report.exportsRunnerDied).toBe(0);
    expect(db.getSession(OTHER)?.runner_id).toBe("slot-1");
    expect(db.getSession(OTHER)?.state).toBe("exporting");
  });

  // (f) "Cannot ask" is not "there is none". This process cannot tell a dead runner
  // from an unreachable orchestrator, and while it cannot ask it acts on nothing at
  // all — the guard is the same line the orphan pass uses, for the same reason.
  it("acts on nothing at all when the orchestrator cannot be asked", async () => {
    seedExportingOnDeadSlot();

    const { client, released } = orchestratorStub({ stats: "unreachable", release: "ok" });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(released).toEqual([]);
    expect(report.exportsRunnerDied).toBe(0);
    expect(db.getSession(GUID)?.state).toBe("exporting");
    expect(db.getSession(GUID)?.runner_id).toBe("slot-1");
  });

  // A finished export is not a dead one. `markExportStranded`'s `ELSE` arm is the
  // data-loss guard — session `80837b89` is `partial` with a real `artifact_id`, a
  // working download whose state was wrongly `exporting` — and this is the caller
  // that must not be able to defeat it.
  it("keeps a finished partial export byte-for-byte through this caller too", async () => {
    const partialState = JSON.stringify({
      state: "partial",
      partialReason: "quota",
      id: "artifact123",
      notebook: "NB",
      progress: null,
      startedAt: 1234567890,
      finishedAt: 1234567900,
    });
    // An exporting session on the dead slot, whose walk turned out to have produced a
    // downloadable partial before the container went.
    seedExportingOnDeadSlot();
    db.run(
      `UPDATE sessions SET export_state = ?, artifact_id = 'artifact123' WHERE guid = ?`,
      partialState,
      GUID,
    );

    const { client } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      deadSlots: ["slot-1"],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(report.exportsRunnerDied).toBe(1);
    expect(db.getSession(GUID)?.state).toBe("authenticated");
    expect(db.getSession(GUID)?.export_state).toBe(partialState);
    expect(db.getSession(GUID)?.artifact_id).toBe("artifact123");
  });
});
/**
 * A session left `exporting` on a slot the orchestrator reclaimed to **idle**.
 *
 * ## The gap
 *
 * A boot TTL-replace (or any orchestrator restart) drops a bound slot's
 * orchestrator-side `SessionGUID`, so the slot reports `idle`. The api's own records
 * are then all consistent and all wrong: `state='exporting'`, `runner_id` set,
 * `runners` row `active` — naming a slot nobody is bound to. The sweeper skips
 * `exporting` sessions to protect live ones, so the idle deadline never applies and
 * `POST /api/export` answers `409 an export is already running` for every future
 * notebook, until the 12-hour absolute cap erases the row.
 *
 * Neither existing branch reaches it: `exportsStranded` needs `runner_id IS NULL`,
 * and `exportsRunnerDied` needs the slot in `deadSlots` — which is bound-only, and an
 * idle slot is not dead.
 *
 * ## The signal, and its two production shapes
 *
 * `/stats.boundSessions` names **every slot the orchestrator currently binds**, so a
 * session's slot being *absent as a key* is positive evidence it is unbound: idle,
 * vacant, being recreated, or gone. The primary shape is `boundSessions` **present**
 * with this slot absent — the pool's one idle slot of two, the other slot bound to a
 * live session — which is what test (a) builds.
 *
 * The other shape is an **absent field**, and it has two causes that are not the same
 * thing. A rolling deploy pairs this api with an orchestrator predating `boundSessions`.
 * An all-idle pool does not send it either: `Stats()` leaves the map nil and `omitempty`
 * drops the key — which is what makes it the *ordinary* state of a pool nobody is using,
 * and what D6 was: that pool could not be repaired at all, and a session stuck
 * `exporting` on it was 409ing every future export until the 12-hour cap.
 *
 * So the absent field is now a **fallback, not a dead end**: `byState` answers the same
 * question from the same response by counting instead of naming, and no `bound` key in it
 * means no slot in the pool is bound to anybody. Tests (c')–(c'''') are that one absent
 * field with four `byState` bodies under it — repaired, repaired, refused, and stood
 * down — because a fallback whose only pin is the happy path is not a fallback, it is a
 * guess.
 */
describe("sweep exportsDispossessed", () => {
  /** Read off a real host row rather than invented, so the shape is the real one. */
  const REAL_EXPORT_STATE =
    '{"state":"running","partialReason":null,"id":"zLshdOnjRmN6jkYPcu7SnXzsZvKg9YifTAbRM7aZy5E",' +
    '"notebook":"MS is great","progress":{"pages":0,"sections":0,"assets":0},' +
    '"startedAt":1791536187840,"finishedAt":null}';

  /** A third session, for the two-slot pool's other slot. */
  const THIRD = "22222222-2222-4222-8222-222222222222";

  /**
   * The exported session, plus a `runners` row that says its slot is bound.
   *
   * `slots` creates the pool this test's `slotIds` names — asking for two and seeding
   * one would leave `syncPool` to invent the second row, so the binding under test
   * would be partly the thing under test.
   */
  function seedExportingOnSlot(guid = GUID, slotId = "slot-1", slots = 1): void {
    seedRunners(slots);
    db.run(`UPDATE runners SET status = 'active', session_guid = ? WHERE id = ?`, guid, slotId);
    seedSession(guid, {
      state: "exporting",
      runner_id: slotId,
      export_state: REAL_EXPORT_STATE,
    });
  }

  /**
   * The pool's second slot, held by a **live** session.
   *
   * A real `sessions` row, because the post-loop orphan reconciler asks
   * `sessionOwnsSlot(guid)` and releases anything bound to a session it cannot find.
   * Seeding only the `runners` row would make every "nothing else is released"
   * assertion here pass or fail on the *reconciler*, not on this branch — the test
   * would measure the wrong writer.
   */
  function seedSecondSlotBound(sessionGuid = OTHER, slotId = "slot-2"): void {
    seedSession(sessionGuid, { state: "authenticated", runner_id: slotId });
    db.run(`UPDATE runners SET status = 'active', session_guid = ? WHERE id = ?`, sessionGuid, slotId);
  }

  /**
   * The pool's second slot, held by a second session that is **also** exporting.
   *
   * A real `sessions` row for the same reason `seedSecondSlotBound` above gives one, and
   * the same trap this whole block keeps re-learning: with a two-slot pool and only one
   * seeded session, the post-loop orphan reconciler is a second candidate to have done
   * the repair, and it does it by calling `/release`. So "both slots are unbound now"
   * would be true whichever writer ran, and `released === []` would be the assertion that
   * distinguishes them — which only means something if branch C is the one that ran.
   */
  function seedSecondSlotExporting(sessionGuid = THIRD, slotId = "slot-2"): void {
    seedSession(sessionGuid, {
      state: "exporting",
      runner_id: slotId,
      export_state: REAL_EXPORT_STATE,
    });
    db.run(`UPDATE runners SET status = 'active', session_guid = ? WHERE id = ?`, sessionGuid, slotId);
  }

  const rowFor = (slotId: string) =>
    db.get<{ status: string; session_guid: string | null }>(
      `SELECT status, session_guid FROM runners WHERE id = ?`,
      slotId,
    );

  // (a) whole repair on the PRODUCTION signal — one idle slot of two.
  it("releases the slot and ends the export in one tick (one idle slot of two)", async () => {
    seedExportingOnSlot(GUID, "slot-1", 2);
    seedSecondSlotBound();

    const frames = watch(sse, GUID);

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      boundSessions: { "slot-2": OTHER },
      deadSlots: [],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    // **Nothing goes through `/release`.** Branch C repairs the api's row only: the
    // orchestrator side is already idle, so a `/release` would destroy a healthy
    // container to fix nothing. And the orphan reconciler is quiet because slot-2's
    // holder is a real session — so this array is branch C's assertion, not the
    // reconciler's.
    expect(released).toEqual([]);
    expect(report.exportsDispossessed).toBe(1);

    const session = db.getSession(GUID)!;
    expect(session.runner_id).toBeNull();
    expect(session.state).toBe("authenticated");
    expect(session.idle_expires_at).toBe(now + TTL.authenticatedIdle);

    const parsed = JSON.parse(session.export_state!);
    expect(parsed.state).toBe("failed");
    expect(parsed.error).toBe("the runner's slot was reclaimed before this export finished");
    expect(parsed.id).toBe("zLshdOnjRmN6jkYPcu7SnXzsZvKg9YifTAbRM7aZy5E");
    expect(parsed.notebook).toBe("MS is great");

    expect(rowFor("slot-1")).toEqual({
      status: "idle",
      session_guid: null,
    });

    const events = frames();
    expect(events.length).toBe(1);
    expect(events[0].type).toBe("session-status");
    expect(events[0].data).toEqual({ state: "authenticated" });
  });

  // (b) false-positive guard — a live export is held, untouched.
  it("does not reset when the slot is bound to a live session", async () => {
    seedExportingOnSlot(GUID, "slot-1", 2);
    seedSecondSlotBound(THIRD);

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      boundSessions: { "slot-1": GUID, "slot-2": THIRD },
      deadSlots: [],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(released).toEqual([]);
    expect(report.exportsDispossessed).toBe(0);
    // Held by the export-hold below, which is the correct answer for a live export.
    expect(report.exportsHeld).toBe(1);

    const session = db.getSession(GUID)!;
    expect(session.runner_id).toBe("slot-1");
    expect(session.state).toBe("exporting");
  });

  // (c') **D6, closed.** An absent `boundSessions` is no longer a dead end: the same
  // response's `byState` answers the same question by counting.
  //
  // This test used to pin the *limitation* — `exportsDispossessed === 0`, and its
  // comment recorded why a positive orchestrator signal was deferred. It is the same
  // fixture with the assertions inverted, which is the shape this repo asks for: the
  // body it runs against is the one the deployed host actually sends on a pool nobody is
  // using (`{"size":1,"byState":{"idle":1},…}` — no `boundSessions`, no `bound` key), and
  // the thing it used to demonstrate was that the strand survived.
  //
  // **Before this fix the row below stayed `exporting` for the whole 12-hour cap**, and
  // `POST /api/export` answered `409 an export is already running` for every notebook the
  // user had not tried yet. The stub's derived `byState` — `{ idle: 1 }` with no `bound`
  // key — is that body, and it is the *default* every other test in this file has been
  // running against all along, which is why the fixture needed no new option to
  // reproduce D6.
  it("repairs the strand on an all-idle pool, which marshals no boundSessions", async () => {
    seedExportingOnSlot();

    const frames = watch(sse, GUID);

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      deadSlots: [],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    // **Still no `/release`** — the point branch C shares with test (a), and why this is
    // asserted first. The orchestrator side is already unbound, so a release would
    // destroy a healthy idle container to fix a row only this process can see. And
    // because `/stats` carries no `boundSessions` at all, the post-loop orphan
    // reconciler has nothing to iterate: `[]` here is branch C's assertion, not the
    // reconciler's.
    expect(released).toEqual([]);
    expect(report.exportsDispossessed).toBe(1);

    const session = db.getSession(GUID)!;
    expect(session.state).toBe("authenticated");
    expect(session.runner_id).toBeNull();
    expect(rowFor("slot-1")).toEqual({ status: "idle", session_guid: null });

    // The user's own cause — branch C's message, not branch B's "the runner disappeared".
    const parsed = JSON.parse(session.export_state!);
    expect(parsed.error).toBe("the runner's slot was reclaimed before this export finished");
    expect(parsed.id).toBe("zLshdOnjRmN6jkYPcu7SnXzsZvKg9YifTAbRM7aZy5E");

    // One frame, because the frontend is SSE-only: the walk is gone, and nothing else
    // will ever end this progress card.
    const events = frames();
    expect(events.length).toBe(1);
    expect(events[0].type).toBe("session-status");
    expect(events[0].data).toEqual({ state: "authenticated" });
  });

  // (c'') the body the deployed host actually sends, on the pool size it actually has.
  //
  // Two slots, `{"byState":{"idle":2}}`, and **two sessions stranded on them** — the
  // shape a whole pool going quiet leaves behind. Both halves are load-bearing:
  //
  //   - **Two real `sessions` rows.** With only one, the post-loop orphan reconciler is
  //     also a candidate to "fix" a row, and it fixes it by calling `/release` for real.
  //     A test that asserted only "both slots ended up unbound" would pass whichever
  //     writer ran — the trap the PR that added branch C fell into. `released === []`
  //     beside the counter is what tells the two apart.
  //   - **No `bound` key.** Asserted by the stub's own default rather than by a comment,
  //     because a `bound: 0` would make this the (a) shape and the test would measure
  //     nothing new.
  it("repairs both strands on the real two-slot all-idle body", async () => {
    seedExportingOnSlot(GUID, "slot-1", 2);
    seedSecondSlotExporting();

    const runWith = async (opts: Parameters<typeof orchestratorStub>[0]) => {
      const { client, released } = orchestratorStub(opts);
      const report = await sweep(options(client), new PoolBinder(options(client)));
      return { report, released };
    };

    // The capture from the deployed host, byte for byte in the part under test: two
    // slots, both idle, nothing bound, and no `boundSessions` key to ask about.
    const idle = await runWith({
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      byState: { idle: 2 },
      release: "ok",
    });
    expect(idle.released).toEqual([]);
    expect(idle.report.exportsDispossessed).toBe(2);

    for (const guid of [GUID, THIRD]) {
      expect(db.getSession(guid)?.state).toBe("authenticated");
      expect(db.getSession(guid)?.runner_id).toBeNull();
      expect(JSON.parse(db.getSession(guid)!.export_state!).error).toBe(
        "the runner's slot was reclaimed before this export finished",
      );
    }
  });

  // (c''-b) **The companion body: what a `/release` actually leaves behind.**
  //
  // One idle slot and one `vacant` — no container, one wanted — which is the state
  // `Pool.Release` puts a slot in. The same repair has to happen, and it has to happen
  // *because `vacant` reads as not-bound* rather than in spite of the vocabulary check:
  // `POOL_STATE_NAMES` covers both words, so the answer is the same one (c'') got from
  // `idle`. Without this half, the refusal in (c''') would read as being about unknown
  // names rather than about names, and a future state added to the pool could break the
  // repair with a green suite.
  it("still repairs when the released slot reports vacant rather than idle", async () => {
    seedExportingOnSlot(GUID, "slot-1", 2);
    seedSecondSlotExporting();

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      byState: { idle: 1, vacant: 1 },
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    // Still branch C's: no `/release`, even though this body is the aftermath of one.
    expect(released).toEqual([]);
    expect(report.exportsDispossessed).toBe(2);
  });

  // (c''') the refusal, which is what makes the `?? 0` this does *not* write safe.
  //
  // `byState: { idle: 1, warming: 1 }` is a pool from an orchestrator whose vocabulary
  // this api has never heard of. `bound` is absent from it — for a reason that means "I do
  // not use that word", not "nothing is bound" — and a `byState.bound ?? 0` would read it
  // as the second thing and dispossess a live export mid-walk. So the helper answers
  // "cannot ask" and the strand survives this tick.
  //
  // **That is the safe direction and it is deliberate**: one more tick of a 409 beats
  // cancelling somebody's running export. Deleting the `POOL_STATE_NAMES` loop turns this
  // red, which is the entire reason the loop exists.
  it("refuses to answer when byState names a state this api does not know", async () => {
    seedExportingOnSlot();

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      byState: { idle: 1, warming: 1 },
      deadSlots: [],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(released).toEqual([]);
    expect(report.exportsDispossessed).toBe(0);
    // Held, not stranded by us: the export-hold below is the right answer for a session
    // we cannot prove is unbound.
    expect(report.exportsHeld).toBe(1);

    const session = db.getSession(GUID)!;
    expect(session.state).toBe("exporting");
    expect(session.runner_id).toBe("slot-1");
  });

  // (c'''') the fallback's other no-answer: `boundSessions` missing for a reason that is
  // NOT an all-idle pool.
  //
  // `boundSessions` is `omitempty` over a nil map, and a bound slot whose GUID is blank
  // contributes nothing to it by design: `Stats` requires `StateBound` **and** a non-empty
  // `SessionGUID`. So an orchestrator can bind a slot and still publish no
  // `boundSessions` at all, and then `byState` is the only evidence there is. It says a
  // slot *is* bound, which means something is holding one, so this branch stands down
  // rather than assuming it is this session's.
  //
  // This is what forbids hard-coding the fallback to `true`: the strand in (c') is
  // detected because the pool is quiet, not because anybody released anything.
  it("stands down when boundSessions is absent but some slot is bound", async () => {
    seedExportingOnSlot();

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      byState: { idle: 1, bound: 1 },
      deadSlots: [],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(released).toEqual([]);
    expect(report.exportsDispossessed).toBe(0);
    expect(report.exportsHeld).toBe(1);

    const session = db.getSession(GUID)!;
    expect(session.state).toBe("exporting");
    expect(session.runner_id).toBe("slot-1");
  });

  // (d) data-loss guard — a terminal `partial` export keeps its bytes.
  it("preserves a partial export_state and its artifact_id through this repair", async () => {
    seedExportingOnSlot(GUID, "slot-1", 2);
    seedSecondSlotBound();

    const partialState = JSON.stringify({
      state: "partial",
      partialReason: "quota",
      id: "artifact123",
      notebook: "MS is great",
      progress: { pages: 1, sections: 1, assets: 1 },
      startedAt: 1791536187840,
      finishedAt: 1791536200000,
    });
    db.run(
      `UPDATE sessions SET export_state = ?, artifact_id = 'artifact123' WHERE guid = ?`,
      partialState,
      GUID,
    );

    const { client } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      boundSessions: { "slot-2": OTHER },
      deadSlots: [],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    // The repair runs — the session is freed either way...
    expect(report.exportsDispossessed).toBe(1);
    expect(db.getSession(GUID)?.state).toBe("authenticated");
    // ...but `markExportStranded`'s `ELSE export_state` arm is the data-loss guard: a
    // terminal export is not `queued`/`running`, so it is left byte-for-byte alone and
    // the artifact it names is still downloadable.
    expect(db.getSession(GUID)?.export_state).toBe(partialState);
    expect(db.getSession(GUID)?.artifact_id).toBe("artifact123");
  });

  // (e) malformed `export_state` — the row is still repaired.
  it("resets to authenticated even with malformed export_state", async () => {
    seedExportingOnSlot(GUID, "slot-1", 2);
    seedSecondSlotBound();
    db.run(`UPDATE sessions SET export_state = 'not-json' WHERE guid = ?`, GUID);

    const { client } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      boundSessions: { "slot-2": OTHER },
      deadSlots: [],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(report.exportsDispossessed).toBe(1);
    expect(db.getSession(GUID)?.state).toBe("authenticated");
    expect(db.getSession(GUID)?.runner_id).toBeNull();
    // `json_valid` fails, so the export blob is left as found rather than half-written.
    expect(db.getSession(GUID)?.export_state).toBe("not-json");
  });

  // (f) bound to a *different* session is pool drift, not dispossession.
  //
  // This is the guard that pins D5's direction. `slot-1` **is** a key in
  // `boundSessions`, so `!(runner_id in boundSessions)` is false and branch C stands
  // down — the post-loop orphan reconciler owns that shape. A `!== guid` test would
  // have fired here and dispossessed a live session.
  it("does not reset when the slot is bound to a different session", async () => {
    seedExportingOnSlot(GUID, "slot-1", 2);
    seedSecondSlotBound(OTHER, "slot-1");
    seedSession(THIRD, { state: "authenticated", runner_id: "slot-2" });

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1", "slot-2"],
      boundSessions: { "slot-1": OTHER, "slot-2": THIRD },
      deadSlots: [],
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(released).toEqual([]);
    expect(report.exportsDispossessed).toBe(0);
    expect(report.exportsHeld).toBe(1);

    const session = db.getSession(GUID)!;
    expect(session.runner_id).toBe("slot-1");
    expect(session.state).toBe("exporting");
  });

  // (g) an unreachable orchestrator is "cannot ask", not "nothing is bound".
  it("does nothing when the orchestrator is unreachable", async () => {
    seedExportingOnSlot();

    const { client, released } = orchestratorStub({ stats: "unreachable", release: "ok" });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    expect(released).toEqual([]);
    expect(report.exportsDispossessed).toBe(0);
    expect(report.exportsHeld).toBe(1);

    const session = db.getSession(GUID)!;
    expect(session.runner_id).toBe("slot-1");
    expect(session.state).toBe("exporting");
  });

  // (h) a slot that is **both** dead and unbound belongs to branch B, exactly once.
  //
  // This is the overlap the two predicates could both match, and the reason it matters
  // is not the double-count but the *message and the teardown*: branch C would end the
  // export with "the slot was reclaimed" and skip the `/release`, when in fact the
  // container died and needs tearing down. So B must win, and only B.
  it("gives a dead-and-unbound slot to branch B, counted once", async () => {
    seedExportingOnSlot();
    seedSession(OTHER, { state: "authenticated" });

    const { client, released } = orchestratorStub({
      stats: "filled",
      slotIds: ["slot-1"],
      // `boundSessions` is present and empty: the orchestrator binds nothing, which is
      // true of a slot whose container died and was never rebound.
      boundSessions: {},
      deadSlots: ["slot-1"],
      // **`byState` is consistent, and deliberately so**: nothing is bound anything, so
      // the fallback arm would also say `true`. The test therefore cannot tell the two
      // arms apart — `boundSessions` is present and empty, so the untouched arm decides
      // — and what it pins is the property that must hold either way: a slot that is
      // both dead and unbound belongs to B, once, with its `/release` and its own
      // message. If branch order ever let the fallback act first, the message and the
      // missing teardown below would say so.
      byState: { idle: 1, dead: 1 },
      release: "ok",
    });
    const report = await sweep(options(client), new PoolBinder(options(client)));

    // B acted — with its release, which C would not have made.
    expect(released).toEqual(["slot-1"]);
    expect(report.exportsRunnerDied).toBe(1);
    // And C did not also act on the same slot.
    expect(report.exportsDispossessed).toBe(0);

    const session = db.getSession(GUID)!;
    expect(session.state).toBe("authenticated");
    expect(JSON.parse(session.export_state!).error).toBe(
      "the runner disappeared before this export finished",
    );
  });
});

/**
 * The session's vault directory, removed when the session is gone.
 *
 * The orchestrator creates `/opt/msout/data/vault/<guid>/` at claim time and
 * nothing else removes it, so the api — which has no mount of the vault at all —
 * asks the orchestrator when the session's **row** is deleted. The row's
 * deletion is the signal that the session is gone; a release is not, because a
 * released session can come back and re-use its directory.
 */
describe("sweep removes the session's vault directory", () => {
  const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

  /** A sweep whose orchestrator records the directory removals it was asked for. */
  const runWith = async (opts: Parameters<typeof orchestratorStub>[0] = {}) => {
    const stub = orchestratorStub(opts);
    const binder = new PoolBinder(options(stub.client));
    const report = await sweep(options(stub.client), binder);
    return { report, deleted: stub.deletedSessionDirs };
  };

  it("asks the orchestrator to remove it when the row is deleted at the absolute cap", async () => {
    seedSession(GUID, {
      state: "authenticated",
      auth_state: "valid",
      expires_at: now - 1,
    });

    const { report, deleted } = await runWith();

    expect(report.absoluteExpired).toBe(1);
    expect(db.getSession(GUID)).toBeUndefined();
    expect(deleted).toEqual([GUID]);
  });

  it("asks the orchestrator to remove it when the row is deleted unclaimed", async () => {
    seedSession(GUID, { state: "created", created_at: now - TTL.unclaimedSession - 1 });

    const { report, deleted } = await runWith();

    expect(report.unclaimedExpired).toBe(1);
    expect(deleted).toEqual([GUID]);
  });

  it("does NOT remove it when the session is merely released and can come back", async () => {
    // The idle branch releases the runner and **keeps the row**: the user may
    // return within the session's remaining life and re-use their vault. The
    // directory has to survive that, or the session comes back to nothing.
    // A runner to release: the counter only increments when the release
    // succeeds, so without one the branch would be vacuous.
    seedRunners(1);
    seedSession(GUID, {
      state: "authenticated",
      auth_state: "valid",
      runner_id: "slot-1",
      idle_expires_at: now - 1,
      expires_at: now + 3_600_000,
    });

    const { report, deleted } = await runWith({ release: "ok" });

    expect(report.idleReleased).toBe(1);
    // The row is still there — the session is not gone.
    expect(db.getSession(GUID)).toBeDefined();
    // And so is its directory.
    expect(deleted).toEqual([]);
  });
});
