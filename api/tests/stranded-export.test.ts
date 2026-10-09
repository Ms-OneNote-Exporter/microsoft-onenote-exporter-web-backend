/**
 * Regression tests for the fix that resets stranded exports.
 *
 * This file was originally `stranded-export-proof.test.ts` and proved that a
 * stranded export (**state='exporting' AND runner_id IS NULL**) refuses every
 * future export with 409 `"an export is already running"`. That is the BUG.
 *
 * After the fix, a sweep tick resets the session to `state='authenticated'` and
 * marks `export_state` as `'failed'`, so the export route no longer refuses.
 * The harness has no pool binder, so the rebind path answers 409
 * `"no runner bound to this session"` — which distinguishes the two refusals.
 *
 * ## Why this test exists
 *
 * Sessions in `exporting` state with `runner_id NULL` are stuck until the
 * 12-hour absolute cap. Two such rows existed on the deployed host. The fix
 * runs from `sweep.ts` when it finds `state === 'exporting' && runner_id === null`.
 */
import { beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";

import { buildServer, type ServerDeps } from "../src/server.js";
import type { ApiConfig } from "../src/config.js";
import { Db } from "../src/db.js";
import { OrchestratorClient } from "../src/orchestrator-client.js";
import { SseHub } from "../src/sse.js";
import { RateLimiter } from "../src/rate-limit.js";
import { SESSION_COOKIE } from "../src/csrf.js";
import { deriveCsrfToken, generateCsrfKey, hashSecret } from "../src/session.js";
import { derive } from "./helpers.js";
import { TTL } from "../src/sweep.js";
import { sweep, PoolBinder } from "../src/sweep.js";

const ALLOWED = "https://app.example.com";
const SECRET = "A".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

/** Read verbatim off the live row, session `cc915fdf`, 2026-10-09. */
const REAL_STRANDED_EXPORT_STATE =
  '{"state":"running","partialReason":null,"id":"zLshdOnjRmN6jkYPcu7SnXzsZvKg9YifTAbRM7aZy5E",' +
  '"notebook":"MS is great","progress":{"pages":0,"sections":0,"assets":0},' +
  '"startedAt":1791536187840,"finishedAt":null}';

const config: ApiConfig = {
  allowedOrigins: new Set([ALLOWED]),
  csrfKey: "C".repeat(43),
  sessionTtlHours: 12,
  minFreeDiskMb: 2048,
  publicOrigin: "https://one-backend.example.com",
  orchestratorUrl: "http://orchestrator:9100",
  orchestratorSecret: "B".repeat(43),
  orchestratorReplayWindowSeconds: 60,
  logLevel: "info",
  listen: "127.0.0.1:0",
  databasePath: ":memory:",
  sseBufferEvents: 500,
  sseKeepaliveMs: 15_000,
  sessionsPerHour: 3,
};

let db: Db;
let sse: SseHub;
let limiter: RateLimiter;
let csrfKey: string;

function deps(): ServerDeps {
  return {
    db,
    sse,
    limiter,
    orchestrator: new OrchestratorClient({
      baseUrl: "http://127.0.0.1:1",
      secret: config.orchestratorSecret,
    }),
  };
}

async function newApp(): Promise<FastifyInstance> {
  const app = buildServer(config, deps());
  await app.ready();
  return app;
}

/**
 * A session in the stranded state: `auth_state` valid, no runner, and
 * an `export_state` that claims an export is running.
 */
function seedStranded(exportState: string | null = REAL_STRANDED_EXPORT_STATE): void {
  csrfKey = generateCsrfKey();
  db.createSession({
    guid: GUID,
    secretHash: hashSecret(SECRET),
    csrfKey,
    now: Date.now(),
    expiresAt: Date.now() + TTL.absolute,
  });
  db.run(
    `UPDATE sessions
        SET state = 'exporting', auth_state = 'valid', runner_id = NULL, export_state = ?
      WHERE guid = ?`,
    exportState,
    GUID,
  );
}

function exportRequest(app: FastifyInstance, notebook: string) {
  return app.inject({
    method: "POST",
    url: "/api/export",
    headers: {
      "content-type": "application/json",
      cookie: `${SESSION_COOKIE}=${GUID}:${SECRET}`,
      origin: ALLOWED,
      "x-csrf-token": derive(csrfKey, GUID),
    },
    payload: JSON.stringify({ notebook }),
  });
}

function runSweep(): Promise<void> {
  const binder = new PoolBinder({ db, orchestrator: deps().orchestrator, sse, now: () => Date.now() });
  return sweep(options(), binder);
}

function options() {
  return { db, orchestrator: deps().orchestrator, sse, now: () => Date.now() };
}

beforeEach(() => {
  db = new Db(":memory:");
  sse = new SseHub();
  limiter = new RateLimiter({ logSalt: "test" });
});

describe("stranded export fix", () => {
  it("reset by sweep tick, export route no longer refuses with 'an export is already running'", async () => {
    // Seed a session in the stranded state
    seedStranded();
    
    // The export route should refuse
    const app1 = await newApp();
    try {
      const res1 = await exportRequest(app1, "MS is great");
      expect(res1.statusCode).toBe(409);
      expect(res1.json()).toMatchObject({ error: "an export is already running" });
    } finally {
      await app1.close();
    }
    
    // Run a sweep tick to fix the stranded session
    await runSweep();
    
    // After the sweep, the session state should be 'authenticated'
    const rowAfterSweep = db.getSession(GUID);
    expect(rowAfterSweep?.state).toBe("authenticated");
    expect(rowAfterSweep?.runner_id).toBeNull();
    expect(rowAfterSweep?.last_activity_at).toBeGreaterThanOrEqual(Date.now() - 1000);
    expect(rowAfterSweep?.idle_expires_at).toBeGreaterThanOrEqual(Date.now());
    
    // The export_state should be 'failed' with the correct error message
    const parsedExportState = JSON.parse(rowAfterSweep!.export_state!);
    expect(parsedExportState.state).toBe("failed");
    expect(parsedExportState.error).toBe("the runner was released before this export finished");
    expect(parsedExportState.id).toBe("zLshdOnjRmN6jkYPcu7SnXzsZvKg9YifTAbRM7aZy5E");
    expect(parsedExportState.notebook).toBe("MS is great");
    
    // Now the export route should pass the export-state guard and fail for a different reason
    // (no pool binder, so rebind fails)
    const app2 = await newApp();
    try {
      const res2 = await exportRequest(app2, "MS is great");
      
      // Should NOT be 'an export is already running'
      expect(res2.statusCode).toBe(409);
      expect(res2.json()).not.toMatchObject({ error: "an export is already running" });
      
      // Should be 'no runner bound to this session' from the rebind path
      expect(res2.json()).toMatchObject({ error: "no runner bound to this session" });
    } finally {
      await app2.close();
    }
  });

  it("keeps the session if export_state is terminal (partial) and doesn't touch artifact_id", async () => {
    // A session with export_state.state='partial' has a real artifact_id - it's a finished export
    const partialExportState = JSON.stringify({
      state: "partial",
      partialReason: "quota",
      id: "realArtifactId123",
      notebook: "MS is great",
      progress: null,
      startedAt: 1234567890,
      finishedAt: 1234567900,
    });

    db.createSession({
      guid: GUID,
      secretHash: hashSecret(SECRET),
      csrfKey,
      now: Date.now(),
      expiresAt: Date.now() + TTL.absolute,
    });
    db.run(
      `UPDATE sessions
          SET state = 'exporting', auth_state = 'valid', runner_id = NULL,
              export_state = ?, artifact_id = 'realArtifactId123'
        WHERE guid = ?`,
      partialExportState,
      GUID,
    );

    const beforeRow = db.getSession(GUID)!;
    expect(beforeRow.state).toBe("exporting");
    expect(beforeRow.runner_id).toBeNull();

    // Run sweep - should NOT change the export_state because it's not 'queued' or 'running'
    await runSweep();

    const afterRow = db.getSession(GUID)!;
    
    // The session state should still be fixed to authenticated
    expect(afterRow.state).toBe("authenticated");
    
    // But export_state should be UNTOUCHED (the data-loss guard)
    expect(afterRow.export_state).toBe(partialExportState);
    expect(afterRow.artifact_id).toBe("realArtifactId123");
  });

  it("two refusals are distinguishable by their error bodies", async () => {
    // The stranded export (running) refusal and the "no runner" refusal
    // are both 409 but have different error messages.

    // First, the stranded refusal
    seedStranded();
    const app1 = await newApp();
    try {
      const res = await exportRequest(app1, "MS is great");
      expect(res.statusCode).toBe(409);
      expect(res.json()).toMatchObject({ error: "an export is already running" });
    } finally {
      await app1.close();
    }

    // Fix it with sweep
    await runSweep();

    // Then, the "no runner" refusal (after the fix, no export-state guard)
    const app2 = await newApp();
    try {
      const res = await exportRequest(app2, "MS is great");
      expect(res.statusCode).toBe(409);
      expect(res.json()).toMatchObject({ error: "no runner bound to this session" });
    } finally {
      await app2.close();
    }
  });

  it("malformed export_state is never touched", async () => {
    db.createSession({
      guid: GUID,
      secretHash: hashSecret(SECRET),
      csrfKey,
      now: Date.now(),
      expiresAt: Date.now() + TTL.absolute,
    });
    // Malformed JSON
    db.run(
      `UPDATE sessions
          SET state = 'exporting', auth_state = 'valid', runner_id = NULL, export_state = ?
        WHERE guid = ?`,
      "not valid json {",
      GUID,
    );

    const beforeRow = db.getSession(GUID)!;
    expect(beforeRow.export_state).toBe("not valid json {");
    expect(beforeRow.state).toBe("exporting");
    expect(beforeRow.runner_id).toBeNull();
    console.log("Before row:", JSON.stringify(beforeRow, null, 2));

    // Should not throw during sweep
    await runSweep();

    // DEBUG: read from db multiple times to check for consistency
    console.log("Test: about to read after row, GUID=", GUID);
    const afterRow1 = db.getSession(GUID)!;
    console.log("After row 1 state:", afterRow1!.state, "row1:", JSON.stringify(afterRow1, null, 2));
    const afterRow2 = db.getSession(GUID)!;
    console.log("After row 2 state:", afterRow2!.state, "row2:", JSON.stringify(afterRow2, null, 2));
    // export_state unchanged (data-loss guard)
    expect(afterRow1.export_state).toBe("not valid json {");
    expect(afterRow2.export_state).toBe("not valid json {");
    // But state should still be fixed because the WHERE clause condition is satisfied
    expect(afterRow1.state).toBe("authenticated");
    expect(afterRow2.state).toBe("authenticated");
  });

  it("NULL export_state is never touched", async () => {
    db.createSession({
      guid: GUID,
      secretHash: hashSecret(SECRET),
      csrfKey,
      now: Date.now(),
      expiresAt: Date.now() + TTL.absolute,
    });
    db.run(
      `UPDATE sessions
          SET state = 'exporting', auth_state = 'valid', runner_id = NULL, export_state = NULL
        WHERE guid = ?`,
      GUID,
    );

    const beforeRow = db.getSession(GUID)!;
    expect(beforeRow.export_state).toBeNull();

    await runSweep();

    const afterRow = db.getSession(GUID)!;
    console.log("After row NULL:", JSON.stringify(afterRow, null, 2));
    expect(afterRow.export_state).toBeNull();
    expect(afterRow.state).toBe("authenticated");
  });

  it("re-running on an already failed row is a no-op", async () => {
    seedStranded();
    
    // Run sweep once
    await runSweep();
    
    const row1 = db.getSession(GUID)!;
    expect(row1.state).toBe("authenticated");
    expect(JSON.parse(row1.export_state!).state).toBe("failed");

    // Run sweep again
    await runSweep();

    const row2 = db.getSession(GUID)!;
    // Nothing changed
    expect(row2.state).toBe("authenticated");
    expect(JSON.parse(row2.export_state!).state).toBe("failed");
    expect(row2.last_activity_at).toBe(row1.last_activity_at);
  });

  it("a session with a live runner (runner_id non-null) is never touched", async () => {
    seedStranded();
    // Give it a runner_id
    db.run(`UPDATE sessions SET runner_id = 'slot-1' WHERE guid = ?`, GUID);

    expect(() => runSweep()).not.toThrow();

    const afterRow = db.getSession(GUID)!;
    // The slot is untouched
    expect(afterRow.runner_id).toBe("slot-1");
    // State unchanged
    expect(afterRow.state).toBe("exporting");
  });

  it("a session not in exporting state is never touched", async () => {
    // Create a session in a different state
    db.createSession({
      guid: GUID,
      secretHash: hashSecret(SECRET),
      csrfKey,
      now: Date.now(),
      expiresAt: Date.now() + TTL.absolute,
    });
    db.run(
      `UPDATE sessions
          SET state = 'authenticated', auth_state = 'valid', runner_id = NULL, export_state = ?
        WHERE guid = ?`,
      REAL_STRANDED_EXPORT_STATE,
      GUID,
    );

    expect(() => runSweep()).not.toThrow();

    const afterRow = db.getSession(GUID)!;
    expect(afterRow.state).toBe("authenticated");
    expect(afterRow.runner_id).toBeNull();
    // export_state unchanged
    expect(afterRow.export_state).toBe(REAL_STRANDED_EXPORT_STATE);
  });
});

describe("PROOF (original): a stranded export refuses every future export", () => {
  /**
   * This test was written BEFORE the fix to prove the bug existed.
   * After the fix, it now proves the bug is fixed: the export-state guard
   * is bypassed after a sweep tick.
   *
   * The premise behind the Tier 1 plan was inferred from reading code: `POST /api/export`
   * refuses when `export_state` is `queued` or `running` (`routes.ts:860`), and two
   * sessions on the deployed host are in exactly that state with no runner. That is a
   * sound reading and it is **not** an observation. Nobody had watched it happen, and
   * when the user — who had a working session — said "I am not sure you are correct",
   * the honest next step was to produce the evidence rather than restate the inference.
   *
   * So this was the evidence: drive the **real** route handler over HTTP, seeded with
   * the **real** `export_state` value read off the live row. No predicate is
   * reimplemented here: the assertion was on the response the shipped code produces.
   *
   * After the fix, this test now proves the bug is fixed: a sweep tick resets the
   * session so the export-state guard no longer fires.
   */
  it("PROOF: a stranded export used to refuse every future export with 409", async () => {
    // Seed the stranded session
    seedStranded();
    const app = await newApp();
    try {
      const res = await exportRequest(app, "MS is great");

      // This assertion proved the bug existed
      expect(res.statusCode).toBe(409);
      expect(res.json()).toMatchObject({ error: "an export is already running" });
    } finally {
      await app.close();
    }

    // Now verify the fix: after a sweep tick, the export state is reset
    await runSweep();

    const row = db.getSession(GUID)!;
    expect(row.state).toBe("authenticated");
    expect(JSON.parse(row.export_state!).state).toBe("failed");
  });

  it("PROOF: a stranded export kept refusing until the fix", async () => {
    seedStranded();
    const app = await newApp();
    try {
      // Three different notebooks - all refused the same way
      const replies = [];
      for (const notebook of ["MS is great", "MyFirstNotebook", "The Complete Notebook"]) {
        replies.push(await exportRequest(app, notebook));
      }
      for (const res of replies) {
        expect(res.statusCode).toBe(409);
        expect(res.json()).toMatchObject({ error: "an export is already running" });
      }
    } finally {
      await app.close();
    }

    // After the fix
    await runSweep();

    const row = db.getSession(GUID)!;
    expect(row.state).toBe("authenticated");
    expect(JSON.parse(row.export_state!).state).toBe("failed");
  });

  it("does NOT blame the export once it is terminal — the one-line difference", async () => {
    // The same session with `export_state` rewritten to a terminal value.
    // After the fix, this still passes the export-state guard (no change to that logic),
    // and the request then fails for a *different* reason — there is no runner.
    seedStranded(
      '{"state":"done","partialReason":null,"id":"x","notebook":"MS is great",' +
        '"progress":null,"startedAt":1,"finishedAt":2}',
    );
    const app = await newApp();
    try {
      const res = await exportRequest(app, "MS is great");

      // The export-state refusal is gone...
      expect(res.json()).not.toMatchObject({ error: "an export is already running" });
      // ...and it is now a *different* 409, from the rebind path.
      expect(res.json()).toMatchObject({ error: "no runner bound to this session" });
    } finally {
      await app.close();
    }
  });
});
