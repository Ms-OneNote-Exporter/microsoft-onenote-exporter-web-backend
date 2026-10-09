/**
 * `Db.completeExport` — the write that did not exist.
 *
 * ## Why this is tested against a real database and not a stub
 *
 * The bug this file guards was a **missing writer**, not a wrong one. A test that
 * calls `completeExport` against a mock `Db` and asserts the mock was called would
 * have passed before the method existed — it would have been asserting the shape of
 * its own double. The only thing that can catch a missing write is reading the row
 * back out of a real SQLite database and checking the columns the api's own
 * `GET /api/session/status` reads.
 *
 * So: in-memory SQLite, a seeded session in `exporting`, the real `completeExport`,
 * then `SELECT` — and the assertions name the columns the snapshot reads.
 *
 * ## The two claims worth stating
 *
 * 1. `artifact_id` is set. It is what `findByArtifact` matches, what
 *    `authorize-download` compares, and what `artifact.available` reports. Before
 *    this method, nothing in `src/` ever wrote it, so every download was refused.
 * 2. `state` leaves `exporting`. `sweep()` skips any session in that state, so a
 *    session that completed an export and stayed there held its slot until the
 *    twelve-hour absolute TTL. On the deployed two-slot pool that is two exports to
 *    a permanent lockout, and it was introduced by the fix for #44.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Db, type SessionRow } from "../src/db.js";
import { NOTEBOOK_NOT_FOUND } from "../src/export-completion.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";

let db: Db;
const NOW = 1_700_000_000_000;
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const ARTIFACT = "A".repeat(43);

/** seed inserts a session in the state an export leaves it in. */
function seed(guid: string, overrides: Partial<SessionRow> = {}): void {
  db.run(
    `INSERT INTO sessions
       (guid, secret_hash, csrf_key, runner_id, state, auth_state,
        created_at, expires_at, idle_expires_at, last_activity_at,
        notebook, export_state, artifact_id, artifact_partial)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0)`,
    guid,
    hashSecret("A".repeat(43)),
    generateCsrfKey(),
    overrides.runner_id ?? null,
    overrides.state ?? "created",
    overrides.auth_state ?? "none",
    overrides.created_at ?? NOW,
    overrides.expires_at ?? NOW + 43_200_000,
    overrides.idle_expires_at ?? null,
    overrides.last_activity_at ?? NOW,
    overrides.notebook ?? null,
    overrides.export_state ?? null,
  );
}

function row(guid: string = GUID): SessionRow {
  return db.get<SessionRow>(`SELECT * FROM sessions WHERE guid = ?`, guid)!;
}

beforeEach(() => {
  // No session seeded here: each test seeds the row in exactly the state it is
  // about, because "a session in `exporting`" is the precondition for every case
  // and seeding a default row first would mean most tests silently relied on a
  // second `seed` call to reach it.
  db = new Db(":memory:");
});

afterEach(() => {
  db.close();
});

describe("completeExport", () => {
  it("writes the artifact id, which is the only thing a download needs", () => {
    seed(GUID, { state: "exporting" });

    db.completeExport({
      guid: GUID,
      artifactId: ARTIFACT,
      partial: false,
      partialReason: null,
      notebook: "Notebook",
      progress: { pages: 12, sections: 3, assets: 40 },
      startedAt: NOW,
      finishedAt: NOW + 5_000,
    });

    // Read back rather than trusting the return value: the return says a row
    // changed, this says the column the download authoriser matches now holds the
    // id. Those are different claims and only the second one is the bug.
    expect(row().artifact_id).toBe(ARTIFACT);
    expect(row().artifact_partial).toBe(0);
    // `findByArtifact` is literally this query. If it does not find the row the
    // api just wrote, every download is refused and nothing else would say so.
    expect(db.findByArtifact(ARTIFACT)?.guid).toBe(GUID);
  });

  it("leaves the session out of 'exporting', which is what pins a slot", () => {
    seed(GUID, { state: "exporting" });
    expect(row().state).toBe("exporting");

    db.completeExport({
      guid: GUID,
      artifactId: ARTIFACT,
      partial: false,
      partialReason: null,
      notebook: "Notebook",
      progress: null,
      startedAt: NOW,
      finishedAt: NOW + 5_000,
    });

    // `authenticated`, not a new state and not `exporting`. The session is still
    // signed in and still holds its runner; a second export must reuse them. And
    // `sweep()`'s guard is `state === "exporting"`, so leaving it would mean this
    // session's runner is never released for idle.
    expect(row().state).toBe("authenticated");
    expect(row().state).not.toBe("exporting");
  });

  it("records a terminal export_state with a finishedAt", () => {
    seed(GUID, {
      state: "exporting",
      export_state: JSON.stringify({ state: "running", id: ARTIFACT, finishedAt: null }),
    });

    db.completeExport({
      guid: GUID,
      artifactId: ARTIFACT,
      partial: false,
      partialReason: null,
      notebook: "Notebook",
      progress: { pages: 12, sections: 3, assets: 40 },
      startedAt: NOW,
      finishedAt: NOW + 5_000,
    });

    const parsed = JSON.parse(row().export_state!) as Record<string, unknown>;
    expect(parsed.state).toBe("done");
    // The specific field the previous session watched stay null for ever.
    expect(parsed.finishedAt).toBe(NOW + 5_000);
    expect(parsed.id).toBe(ARTIFACT);
    expect(parsed.notebook).toBe("Notebook");
    expect(parsed.progress).toEqual({ pages: 12, sections: 3, assets: 40 });
  });

  it("labels a partial vault as partial on both the row and the export state", () => {
    // Two places, because two readers. `artifact_partial` is what the api's
    // download authoriser reads; `export_state.partialReason` is what the client
    // renders. Writing one and not the other gives a user either a download that
    // silently truncates or a message with no way to act on it.
    seed(GUID, { state: "exporting" });
    db.completeExport({
      guid: GUID,
      artifactId: ARTIFACT,
      partial: true,
      partialReason: "aborted",
      notebook: "Notebook",
      progress: null,
      startedAt: NOW,
      finishedAt: NOW + 1_000,
    });

    const parsed = JSON.parse(row().export_state!) as Record<string, unknown>;
    expect(row().artifact_partial).toBe(1);
    expect(parsed.state).toBe("partial");
    expect(parsed.partialReason).toBe("aborted");
  });

  it("reports no row changed for a session that is gone", () => {
    // A late `export-done` for an erased session is expected traffic, and the
    // caller logs on this boolean to tell "recorded" from "ignored". Returning true
    // would make every erased session log an export as published.
    const recorded = db.completeExport({
      guid: "no-such-guid",
      artifactId: ARTIFACT,
      partial: false,
      partialReason: null,
      notebook: "Notebook",
      progress: null,
      startedAt: NOW,
      finishedAt: NOW,
    });

    expect(recorded).toBe(false);
  });
});

describe("markExportUnpublishable", () => {
  it("frees the session without inventing an artifact", () => {
    seed(GUID, { state: "exporting" });

    db.markExportUnpublishable({
      guid: GUID,
      error: "The export finished, but the file could not be prepared for download.",
      artifactId: ARTIFACT,
      notebook: "Notebook",
      partialReason: null,
      finishedAt: NOW + 5_000,
    });

    // The slot is freed — the sweep skips `exporting` — …
    expect(row().state).toBe("authenticated");
    // … and `artifact_id` stays NULL, because an id here would make
    // `artifact.available` true and let Caddy authorise a download of an archive
    // that was never published.
    expect(row().artifact_id).toBeNull();
    expect(db.findByArtifact(ARTIFACT)).toBeUndefined();
  });

  it("records the failure with a finishedAt, so the client stops showing 'running'", () => {
    seed(GUID, {
      state: "exporting",
      export_state: JSON.stringify({ state: "running", id: ARTIFACT, finishedAt: null }),
    });

    db.markExportUnpublishable({
      guid: GUID,
      error: "could not prepare",
      artifactId: ARTIFACT,
      notebook: "Notebook",
      partialReason: null,
      finishedAt: NOW + 5_000,
    });

    const parsed = JSON.parse(row().export_state!) as Record<string, unknown>;
    expect(parsed.state).toBe("failed");
    expect(parsed.finishedAt).toBe(NOW + 5_000);
    expect(parsed.error).toBe("could not prepare");
  });
});

describe("markExportUnpublishable for notebook not found", () => {
  it("records the failure with the notebook not found message", () => {
    seed(GUID, { state: "exporting" });

    db.markExportUnpublishable({
      guid: GUID,
      error: NOTEBOOK_NOT_FOUND,
      artifactId: ARTIFACT,
      notebook: "Notebook",
      partialReason: null,
      finishedAt: NOW + 5_000,
    });

    const parsed = JSON.parse(row().export_state!) as Record<string, unknown>;
    expect(parsed.state).toBe("failed");
    expect(parsed.error).toBe(NOTEBOOK_NOT_FOUND);
    expect(parsed.finishedAt).toBe(NOW + 5_000);
  });
});