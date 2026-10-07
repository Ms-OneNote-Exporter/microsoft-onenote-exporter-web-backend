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
  stats?: "ok" | "unreachable";
}) {
  const calls: string[] = [];
  const client = new OrchestratorClient({
    baseUrl: "http://127.0.0.1:1",
    secret: "B".repeat(43),
    fetchImpl: (async (url: string) => {
      // Parsed rather than string-replaced, so the stub works whatever baseUrl the
      // client was built with.
      const path = new URL(String(url)).pathname;
      calls.push(path);
      if (path === "/claim") {
        if (opts.claim === "ok") {
          return new Response(JSON.stringify({ slotId: "slot-9", containerId: "ctr9" }));
        }
        if (opts.claim === "conflict") return new Response("{}", { status: 409 });
        if (opts.claim === "pool-empty") return new Response("{}", { status: 503 });
        throw new Error("ECONNREFUSED");
      }
      if (path === "/release") {
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
  return { client, calls };
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

  it("releases the slot on a conflict too", async () => {
    seedRunners(1);
    seedSession(GUID);
    const { client } = orchestratorStub({ claim: "conflict" });
    const binder = new PoolBinder(options(client));

    await binder.claimForLogin(db.getSession(GUID)!);

    expect(db.get<{ status: string }>(`SELECT status FROM runners WHERE id = 'slot-1'`)?.status).toBe(
      "idle",
    );
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
  it("leaves an exporting session alone however long it runs", async () => {
    seedRunners(1);
    seedSession(GUID, {
      state: "exporting",
      runner_id: "slot-1",
      idle_expires_at: now - TTL.authenticatedIdle - 1,
    });
    const report = await run();
    expect(report.idleReleased).toBe(0);
    expect(db.getSession(GUID)).toBeDefined();
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

// ---- reconcile ------------------------------------------------------------

describe("reconcile", () => {
  it("reports success and logs a size disagreement", async () => {
    seedRunners(2);
    const { client } = orchestratorStub({ stats: "ok" });

    const result = await reconcile(options(client));

    expect(result.reconciled).toBe(true);
    expect(result.runnerCount).toBe(2);
  });

  it("reconciles when the counts agree", async () => {
    seedRunners(2);
    const { client } = orchestratorStub({ stats: "ok" });
    await reconcile(options(client));
    // Nothing was destroyed on the orchestrator's say-so alone.
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