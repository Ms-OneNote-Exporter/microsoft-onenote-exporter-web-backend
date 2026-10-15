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
      // Zeros, because these cases are clean exports. Passed rather than omitted
      // because that is what `export-completion.ts` does with the real counts,
      // and a terminal is the one moment where "nothing failed" is *measured*
      // rather than merely absent.
      failedSections: 0,
      failedPages: 0,
      failedGroups: 0,
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
      failedSections: 0,
      failedPages: 0,
      failedGroups: 0,
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
      // Zeros, because these cases are clean exports. Passed rather than omitted
      // because that is what `export-completion.ts` does with the real counts,
      // and a terminal is the one moment where "nothing failed" is *measured*
      // rather than merely absent.
      failedSections: 0,
      failedPages: 0,
      failedGroups: 0,
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
      failedSections: 0,
      failedPages: 0,
      failedGroups: 0,
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
      failedSections: 0,
      failedPages: 0,
      failedGroups: 0,
    });

    expect(recorded).toBe(false);
  });

  it("keeps the start the row already held instead of overwriting it with the finish", () => {
    // **The bug, and the reason this method is patched rather than overwritten.**
    //
    // `export-completion.ts` passed `startedAt: input.finishedAt` — a copy-paste —
    // and the old implementation rebuilt the whole object from its arguments, so
    // every completed export recorded `"startedAt":<finish>,"finishedAt":<finish>`.
    // The row claimed the walk took zero time. Observed live twice on the host.
    //
    // The start was never missing: `routes.ts` writes it into `export_state` at
    // queue and again at run start, which is what this row carries.
    //
    // The seed is deliberately **valid JSON that contains `startedAt`**. That is
    // the only shape that can catch this: `export_state: null` takes the ELSE arm,
    // which writes `startedAt` from the arguments by design and so would pass
    // either way; and valid JSON *without* `startedAt` has no start to preserve,
    // so a row claiming `startedAt === finishedAt` would look identical.
    const START = NOW;
    const FINISH = NOW + 229_000; // 3m49s. The real export: 29 pages, 8 assets.
    seed(GUID, {
      state: "exporting",
      export_state: JSON.stringify({
        state: "running",
        id: ARTIFACT,
        notebook: "Notebook",
        progress: { pages: 29, sections: 1, assets: 8 },
        startedAt: START,
        finishedAt: null,
      }),
    });

    db.completeExport({
      guid: GUID,
      artifactId: ARTIFACT,
      partial: false,
      partialReason: null,
      notebook: "Notebook",
      progress: { pages: 29, sections: 1, assets: 8 },
      // A mischief value, not the start: even if this method *did* read the
      // argument, the assertion below would fail. So the test cannot be satisfied
      // by any implementation that prefers the caller's number.
      startedAt: FINISH,
      finishedAt: FINISH,
      failedSections: 0,
      failedPages: 0,
      failedGroups: 0,
    });

    const parsed = JSON.parse(row().export_state!) as Record<string, unknown>;
    // The pair, asserted together because the bug is a *relationship* between
    // them: equal timestamps are the symptom, and one assertion on either field
    // alone would not catch a writer that simply dropped `startedAt`.
    expect(parsed.startedAt).toBe(START);
    expect(parsed.finishedAt).toBe(FINISH);
    // The regression this most directly guards, stated so a future reader knows
    // which line to break: restoring `'$.startedAt', ?` to the json_set argument
    // list turns the row back into "startedAt: 1792000690626, finishedAt:
    // 1792000690626".
    expect(parsed.startedAt).not.toBe(parsed.finishedAt);
    // The terminal fields are still written — preserving the start must not cost
    // the completion itself.
    expect(parsed.state).toBe("done");
    expect(parsed.progress).toEqual({ pages: 29, sections: 1, assets: 8 });
    // `$.failed` still has to arrive as an object, not as the string
    // '{"pages":0,...}'. Without `json(?)` this assertion fails, which is why the
    // patch cannot be spelled with bare parameters.
    expect(parsed.failed).toEqual({ pages: 0, sections: 0, groups: 0 });
  });

  it("preserves the row's start on a partial terminal too", () => {
    // The same patch on the other branch, because `state` and `startedAt` are set
    // in one `json_set` and a fix applied to only one of them would be invisible
    // on the half of exports that are partial — the ones where the duration is
    // most likely to be quoted back to a user afterwards.
    seed(GUID, {
      state: "exporting",
      export_state: JSON.stringify({
        state: "running",
        id: ARTIFACT,
        startedAt: NOW,
        finishedAt: null,
      }),
    });

    db.completeExport({
      guid: GUID,
      artifactId: ARTIFACT,
      partial: true,
      partialReason: "disk",
      notebook: "Notebook",
      progress: { pages: 29, sections: 1, assets: 8 },
      finishedAt: NOW + 60_000,
      failedSections: 0,
      failedPages: 1,
      failedGroups: 0,
    });

    const parsed = JSON.parse(row().export_state!) as Record<string, unknown>;
    expect(parsed.state).toBe("partial");
    expect(parsed.partialReason).toBe("disk");
    expect(parsed.startedAt).toBe(NOW);
    expect(parsed.finishedAt).toBe(NOW + 60_000);
    expect(parsed.failed).toEqual({ pages: 1, sections: 0, groups: 0 });
  });

  it("still records a complete terminal object when export_state is not valid JSON", () => {
    // The ELSE arm, and the reason the patch is guarded rather than unconditional:
    // `json_set` **throws** on malformed JSON, and this runs in the completion path,
    // where a throw reaches the outer catch in `index.ts` and abandons every
    // remaining session for that tick. Mirrors the malformed-JSON cases pinned for
    // `markExportStranded` in tests/stranded-export.test.ts.
    //
    // What it pins: a row too corrupt to patch is still *completed* — the slot is
    // freed, the artifact is recorded, the user sees a terminal state — and only
    // `startedAt` has to be invented, because a row that cannot be parsed has no
    // start in it to preserve.
    seed(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET state = 'exporting', export_state = ? WHERE guid = ?`,
      "not valid json {",
      GUID,
    );

    let recorded = false;
    // The assertion that matters: no throw. Everything after it is about what the
    // fallback wrote once the guard let it through.
    expect(() => {
      recorded = db.completeExport({
        guid: GUID,
        artifactId: ARTIFACT,
        partial: false,
        partialReason: null,
        notebook: "Notebook",
        progress: { pages: 12, sections: 3, assets: 40 },
        // No start was passed and none could be recovered, so it falls back to the
        // finish — which is the old bug's value and is *correct* here: with no
        // start in the row, "unknown" is the only honest thing to record, and the
        // alternative is dropping the field and leaving a reader to guess.
        finishedAt: NOW + 5_000,
        failedSections: 0,
        failedPages: 0,
        failedGroups: 0,
      });
    }).not.toThrow();

    expect(recorded).toBe(true);
    // The completion itself is whole: this is what a user with a corrupt row still
    // has to get, and it is the part a throw would have cost them.
    expect(row().state).toBe("authenticated");
    expect(row().artifact_id).toBe(ARTIFACT);
    const parsed = JSON.parse(row().export_state!) as Record<string, unknown>;
    expect(parsed.state).toBe("done");
    expect(parsed.finishedAt).toBe(NOW + 5_000);
    expect(parsed.startedAt).toBe(NOW + 5_000);
    expect(parsed.progress).toEqual({ pages: 12, sections: 3, assets: 40 });
    expect(parsed.failed).toEqual({ pages: 0, sections: 0, groups: 0 });
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

  it("keeps the start the row already held instead of nulling it", () => {
    // The same defect as `completeExport`, one line over — and the worse of the
    // two, because this is the path where the *walk succeeded*: only the archiving
    // failed. The elapsed time is real and known, and writing `startedAt: null`
    // over it does not leave a gap, it makes a statement.
    //
    // This method has no `startedAt` argument at all, which is deliberate: an
    // argument the caller would have to invent is what produced the original bug.
    // So the only correct reading is "preserve whatever the row has".
    seed(GUID, {
      state: "exporting",
      export_state: JSON.stringify({
        state: "running",
        id: ARTIFACT,
        startedAt: NOW,
        finishedAt: null,
      }),
    });

    db.markExportUnpublishable({
      guid: GUID,
      error: "could not prepare",
      artifactId: ARTIFACT,
      notebook: "Notebook",
      partialReason: null,
      finishedAt: NOW + 229_000,
    });

    const parsed = JSON.parse(row().export_state!) as Record<string, unknown>;
    expect(parsed.startedAt).toBe(NOW);
    expect(parsed.startedAt).not.toBeNull();
    expect(parsed.finishedAt).toBe(NOW + 229_000);
    // The failure still has to reach the user — preserving the start must not cost
    // the terminal the path exists to write.
    expect(parsed.state).toBe("failed");
    expect(parsed.error).toBe("could not prepare");
    expect(parsed.notebook).toBe("Notebook");
    // `progress` is null on purpose here (the walk's counts are not what failed),
    // and it must arrive as JSON null rather than the string "null".
    expect(parsed.progress).toBeNull();
  });

  it("still records the failure when export_state is not valid JSON", () => {
    // The ELSE arm, for the same reason as `completeExport`: `json_set` throws on
    // malformed JSON and this runs in the completion path. The user has to get a
    // terminal state either way, and only `startedAt` is lost.
    seed(GUID, { state: "exporting" });
    db.run(
      `UPDATE sessions SET state = 'exporting', export_state = ? WHERE guid = ?`,
      "not valid json {",
      GUID,
    );

    expect(() =>
      db.markExportUnpublishable({
        guid: GUID,
        error: "could not prepare",
        artifactId: ARTIFACT,
        notebook: "Notebook",
        partialReason: null,
        finishedAt: NOW + 5_000,
      }),
    ).not.toThrow();

    expect(row().state).toBe("authenticated");
    const parsed = JSON.parse(row().export_state!) as Record<string, unknown>;
    expect(parsed.state).toBe("failed");
    expect(parsed.error).toBe("could not prepare");
    expect(parsed.finishedAt).toBe(NOW + 5_000);
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