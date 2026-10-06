import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  API_BUILD,
  PROTOCOL_VERSION,
  authenticate,
  authErrorBody,
  authStatus,
  buildSnapshot,
  iso,
  parseExportState,
  sanitiseExportError,
  GENERIC_EXPORT_ERROR,
  MAX_EXPORT_ERROR_CHARS,
  type SessionSnapshot,
} from "../src/auth.js";
import { Db, type SessionRow } from "../src/db.js";
import { generateCsrfKey, hashSecret } from "../src/session.js";

/**
 * PLAN-v3 §4. The properties under test are the ones that are properties rather
 * than behaviour: that a caller cannot learn whether a GUID exists, that a
 * constant-time comparison is actually used, and that an expired session is
 * unreachable before its secret is even checked.
 */

const NOW = 1_700_000_000_000;
const TTL = 43_200_000;
const SECRET = "A".repeat(43);
const OTHER_SECRET = "B".repeat(43);
const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
/** The configured public origin, as loadConfig would supply it. */
const PUBLIC_ORIGIN = "https://one-backend.example.com";
const OTHER_GUID = "00000000-0000-0000-0000-000000000000";

let db: Db;

function seed(guid: string, overrides: Partial<SessionRow> = {}): SessionRow {
  const csrfKey = generateCsrfKey();
  db.createSession({
    guid,
    secretHash: hashSecret(SECRET),
    csrfKey,
    now: overrides.created_at ?? NOW,
    expiresAt: overrides.expires_at ?? NOW + TTL,
  });
  const changes: Record<string, unknown> = {
    auth_state: overrides.auth_state ?? "none",
    state: overrides.state ?? "created",
    notebook: overrides.notebook ?? null,
    export_state: overrides.export_state ?? null,
    artifact_id: overrides.artifact_id ?? null,
    artifact_partial: overrides.artifact_partial ?? 0,
    idle_expires_at: overrides.idle_expires_at ?? null,
    last_activity_at: overrides.last_activity_at ?? NOW,
  };
  const columns = Object.keys(changes);
  db.run(
    `UPDATE sessions SET ${columns.map((c) => `${c} = ?`).join(", ")} WHERE guid = ?`,
    ...columns.map((c) => changes[c]),
    guid,
  );
  return db.getSession(guid)!;
}

beforeEach(() => {
  db = new Db(":memory:");
});

afterEach(() => {
  db.close();
});

describe("authenticate", () => {
  it("accepts a correct guid and secret", () => {
    seed(GUID);
    const result = authenticate(db, { guid: GUID, secret: SECRET, now: NOW });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.session.guid).toBe(GUID);
      expect(result.csrfToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(result.sessionValue).toContain(GUID);
    }
  });

  it("rejects a wrong secret", () => {
    seed(GUID);
    const result = authenticate(db, { guid: GUID, secret: OTHER_SECRET, now: NOW });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("wrong-secret");
  });

  it("rejects an unknown guid", () => {
    seed(GUID);
    const result = authenticate(db, { guid: OTHER_GUID, secret: SECRET, now: NOW });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("unknown-session");
  });

  // An enumeration oracle: if these two produced different statuses, a caller
  // could test GUIDs against the endpoint.
  it("answers an unknown session and a wrong secret identically", () => {
    seed(GUID);
    const unknown = authenticate(db, { guid: OTHER_GUID, secret: SECRET, now: NOW });
    const wrong = authenticate(db, { guid: GUID, secret: OTHER_SECRET, now: NOW });

    expect(unknown.ok).toBe(wrong.ok);
    if (!unknown.ok && !wrong.ok) {
      expect(authStatus(unknown.failure)).toBe(authStatus(wrong.failure));
      expect(authStatus(unknown.failure)).toBe(401);
    }
  });

  it("uses one body for every 401", () => {
    expect(authErrorBody()).toEqual({ error: "unauthorised" });
  });

  it("rejects an expired session", () => {
    seed(GUID, { expires_at: NOW - 1 });
    const result = authenticate(db, { guid: GUID, secret: SECRET, now: NOW });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("expired");
  });

  it("accepts a session one millisecond before expiry and refuses one after", () => {
    seed(GUID, { expires_at: NOW + 1 });
    expect(authenticate(db, { guid: GUID, secret: SECRET, now: NOW }).ok).toBe(true);
    expect(authenticate(db, { guid: GUID, secret: SECRET, now: NOW + 1 }).ok).toBe(false);
  });

  // The subtle ordering property: an expired row's secret must not be checkable.
  it("refuses an expired session without consulting its secret", () => {
    seed(GUID, { expires_at: NOW - 1 });
    const result = authenticate(db, { guid: GUID, secret: OTHER_SECRET, now: NOW });
    // "expired", not "wrong-secret" — the reverse order would let a caller
    // holding a stale GUID learn whether a guessed secret was ever right.
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("expired");
  });

  it("rejects a malformed guid as a client error, not an auth failure", () => {
    const result = authenticate(db, { guid: "nope", secret: SECRET, now: NOW });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe("malformed-guid");
      // 400, so a frontend bug does not look like a session problem.
      expect(authStatus(result.failure)).toBe(400);
    }
  });

  it("rejects a malformed secret as a client error", () => {
    seed(GUID);
    const result = authenticate(db, { guid: GUID, secret: "short", now: NOW });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure).toBe("malformed-secret");
      expect(authStatus(result.failure)).toBe(400);
    }
  });

  it("rejects a missing cookie pair", () => {
    for (const input of [
      { guid: undefined, secret: SECRET },
      { guid: GUID, secret: undefined },
      { guid: "", secret: "" },
    ]) {
      const result = authenticate(db, { ...input, now: NOW });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.failure).toBe("no-session-cookie");
    }
  });

  it("refuses a row with no secret hash rather than authenticating it", () => {
    // A partially-created row must not become an open door.
    seed(GUID);
    db.run(`UPDATE sessions SET secret_hash = NULL WHERE guid = ?`, GUID);
    const result = authenticate(db, { guid: GUID, secret: SECRET, now: NOW });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure).toBe("unknown-session");
  });

  it("refuses a row with no csrf key", () => {
    seed(GUID);
    db.run(`UPDATE sessions SET csrf_key = NULL WHERE guid = ?`, GUID);
    const result = authenticate(db, { guid: GUID, secret: SECRET, now: NOW });
    expect(result.ok).toBe(false);
  });

  it("derives a stable csrf token for an authenticated session", () => {
    seed(GUID);
    const first = authenticate(db, { guid: GUID, secret: SECRET, now: NOW });
    const second = authenticate(db, { guid: GUID, secret: SECRET, now: NOW });
    expect(first.ok && second.ok).toBe(true);
    if (first.ok && second.ok) {
      expect(first.csrfToken).toBe(second.csrfToken);
      expect(first.csrfToken).not.toBe(first.csrfKey);
    }
  });

  it("never returns the secret in the result", () => {
    seed(GUID);
    const result = authenticate(db, { guid: GUID, secret: SECRET, now: NOW });
    if (result.ok) {
      // sessionValue echoes it because the cookie must round-trip, but nothing
      // else does, and the session row holds only a hash.
      expect(JSON.stringify(result.session)).not.toContain(SECRET);
      expect(result.session.secret_hash).toBe(hashSecret(SECRET));
    }
  });
});

describe("buildSnapshot", () => {
  const notebooks: SessionSnapshot["notebooks"] = { state: "idle", items: [] };

  it("always includes every top-level key", () => {
    const snapshot = buildSnapshot(seed(GUID), NOW, notebooks);
    for (const key of ["protocol", "serverTime", "session", "auth", "notebooks", "export", "artifact"]) {
      expect(snapshot).toHaveProperty(key);
    }
  });

  it("renders ISO-8601 UTC with milliseconds", () => {
    const snapshot = buildSnapshot(seed(GUID), NOW, notebooks);
    expect(snapshot.serverTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(snapshot.session.expiresAt).toMatch(/\.\d{3}Z$/);
  });

  it("reports the protocol version the frontend pins", () => {
    // §7.2: a skew should render a "reload" prompt, not a confusing failure.
    expect(buildSnapshot(seed(GUID), NOW, notebooks).protocol).toBe(PROTOCOL_VERSION);
    expect(PROTOCOL_VERSION).toBe(3);
  });

  it("uses null rather than omitting an optional leaf", () => {
    const snapshot = buildSnapshot(seed(GUID), NOW, notebooks);
    expect(snapshot.session.idleExpiresAt).toBeNull();
    expect(snapshot.auth.lastCheckedAt).toBeNull();
    expect(snapshot.export.id).toBeNull();
    expect(snapshot.export.progress).toBeNull();
    expect(snapshot.artifact.downloadUrl).toBeNull();
    // Present, not absent.
    expect(Object.keys(snapshot.export)).toContain("finishedAt");
  });

  it("reports idleExpiresAt when a login is in flight", () => {
    const snapshot = buildSnapshot(
      seed(GUID, { idle_expires_at: NOW + 900_000 }),
      NOW,
      notebooks,
      PUBLIC_ORIGIN,
    );
    expect(snapshot.session.idleExpiresAt).toBe(iso(NOW + 900_000));
  });

  it("reports no artifact before one exists", () => {
    const snapshot = buildSnapshot(seed(GUID), NOW, notebooks);
    expect(snapshot.artifact).toEqual({
      available: false,
      partial: false,
      downloadUrl: null,
      fileName: null,
    });
  });

  it("builds a download url from the opaque artifact id only", () => {
    // §5 and invariant 8: no GUID and no notebook name in the URL.
    const snapshot = buildSnapshot(
      seed(GUID, {
        artifact_id: "A".repeat(43),
        notebook: "Personal Notebook",
        artifact_partial: 1,
      }),
      NOW,
      notebooks,
      PUBLIC_ORIGIN,
    );
    expect(snapshot.artifact.available).toBe(true);
    expect(snapshot.artifact.partial).toBe(true);
    expect(snapshot.artifact.downloadUrl).toBe(
      `${PUBLIC_ORIGIN}/files/${"A".repeat(43)}`,
    );
    expect(snapshot.artifact.downloadUrl).not.toContain(GUID);
    expect(snapshot.artifact.downloadUrl).not.toContain("Personal");
    // The name comes from Content-Disposition at download time, not from here.
    expect(snapshot.artifact.fileName).toBeNull();
  });

  it("restores a running export so a refresh can reattach", () => {
    const snapshot = buildSnapshot(
      seed(GUID, {
        state: "exporting",
        export_state: JSON.stringify({
          state: "running",
          id: "export-123",
          notebook: "Work",
          progress: { pages: 120, sections: 8, assets: 340 },
          startedAt: NOW - 5000,
          finishedAt: null,
        }),
      }),
      NOW,
      notebooks,
    );
    expect(snapshot.export.state).toBe("running");
    expect(snapshot.export.id).toBe("export-123");
    expect(snapshot.export.progress).toEqual({ pages: 120, sections: 8, assets: 340 });
    expect(snapshot.export.startedAt).toBe(iso(NOW - 5000));
    expect(snapshot.export.finishedAt).toBeNull();
  });

  it("passes the notebook list through", () => {
    const snapshot = buildSnapshot(seed(GUID), NOW, {
      state: "loaded",
      items: ["Personal", "Work"],
    });
    expect(snapshot.notebooks).toEqual({ state: "loaded", items: ["Personal", "Work"] });
  });

  it("keeps an empty notebook list as an empty array, not null", () => {
    // An empty array while loaded is a real answer meaning no notebooks.
    const snapshot = buildSnapshot(seed(GUID), NOW, { state: "loaded", items: [] });
    expect(snapshot.notebooks.items).toEqual([]);
  });

  it("tolerates a corrupt export column rather than failing the session", () => {
    // The session may still hold a valid auth.json; refusing the whole snapshot
    // would log the user out over one bad column.
    const snapshot = buildSnapshot(
      seed(GUID, { export_state: "{not json" }),
      NOW,
      notebooks,
      PUBLIC_ORIGIN,
    );
    expect(snapshot.export.state).toBe("none");
    expect(snapshot.export.id).toBeNull();
  });

  it("treats a stored state with no recognised value as 'none'", () => {
    const snapshot = buildSnapshot(
      seed(GUID, { export_state: JSON.stringify({ id: "x" }) }),
      NOW,
      notebooks,
      PUBLIC_ORIGIN,
    );
    expect(snapshot.export.state).toBe("none");
  });

  it("never reports an erased state, since the row is gone by then", () => {
    const snapshot = buildSnapshot(seed(GUID, { state: "erasing" }), NOW, notebooks);
    expect(snapshot.session.state).toBe("erasing");
  });
});

describe("parseExportState", () => {
  it("returns null for absent or empty input", () => {
    expect(parseExportState(null)).toBeNull();
    expect(parseExportState("")).toBeNull();
  });

  it("fills every field of a partial object", () => {
    const parsed = parseExportState(JSON.stringify({ state: "queued" }));
    expect(parsed).toEqual({
      state: "queued",
      partialReason: null,
      error: null,
      id: null,
      notebook: null,
      progress: null,
      startedAt: null,
      finishedAt: null,
    });
  });

  // mac's pushback: "you stopped this export" is factually false when the disk
  // or the quota is what stopped it, and it sends the user hunting for something
  // they did not do.
  it("keeps a recognised partialReason", () => {
    for (const reason of ["aborted", "quota", "disk"] as const) {
      const parsed = parseExportState(
        JSON.stringify({ state: "partial", partialReason: reason }),
      );
      expect(parsed?.partialReason).toBe(reason);
    }
  });

  it("drops an unrecognised partialReason rather than passing it through", () => {
    // A stored value outside the union would put the client in a state it has no
    // rendering for, and `partial` with an unknown reason is the one case where
    // guessing a message would be wrong.
    for (const bad of ["cancelled", "", 42, null, "unknown"]) {
      const parsed = parseExportState(
        JSON.stringify({ state: "partial", partialReason: bad }),
      );
      expect(parsed?.partialReason).toBeNull();
    }
  });

  it("returns null when the state key is absent or not a string", () => {
    expect(parseExportState(JSON.stringify({ id: "x" }))).toBeNull();
    expect(parseExportState(JSON.stringify({ state: 42 }))).toBeNull();
  });
});

describe("version", () => {
  it("exposes a build id", () => {
    expect(API_BUILD.length).toBeGreaterThan(0);
  });
});

// ---- export errors: mac's finding ----------------------------------------

describe("sanitiseExportError", () => {
  it("maps a known classification to display text", () => {
    expect(sanitiseExportError("quota")).toMatch(/limit/i);
    expect(sanitiseExportError("disk")).toMatch(/disk/i);
    expect(sanitiseExportError("auth")).toMatch(/sign-in/i);
    // Case and surrounding whitespace, because the classification arrives from a
    // runner and a stray capital would otherwise silently produce null.
    expect(sanitiseExportError("  DISK  ")).toMatch(/disk/i);
  });

  it("returns null for anything it does not recognise, rather than echoing it", () => {
    // The important one. This value is rendered on a page, and the raw failure
    // text from a third-party CLI contains absolute paths and the notebook name.
    // An unknown classification must therefore produce nothing at all, so the
    // caller substitutes a generic message.
    for (const hostile of [
      "ENOENT: no such file or directory, open '/srv/msout/sessions/abc/Personal Notebook'",
      "../../etc/passwd",
      "<script>alert(1)</script>",
      "failed for user alice@example.com",
      "",
      "   ",
      null,
      undefined,
      42,
    ]) {
      expect(sanitiseExportError(hostile as string | null)).toBeNull();
    }
  });

  it("never returns text containing a path or a notebook name", () => {
    // Belt and braces on the closed-set design: whatever the input, the output is
    // one of six fixed strings.
    const outputs = ["quota", "disk", "auth", "network", "aborted", "cli"].map((r) =>
      sanitiseExportError(r),
    );
    for (const out of outputs) {
      expect(out).not.toBeNull();
      expect(out).not.toMatch(/[/\\]/);
      expect(out).not.toMatch(/@/);
      expect(out!.length).toBeLessThanOrEqual(MAX_EXPORT_ERROR_CHARS);
    }
  });

  it("offers a generic message for the unclassifiable case", () => {
    // The caller always has something to show, so a failed export is never a
    // dead end.
    expect(GENERIC_EXPORT_ERROR.length).toBeGreaterThan(0);
    expect(GENERIC_EXPORT_ERROR).not.toMatch(/[/\\]/);
  });
});

describe("export error in the snapshot", () => {
  it("carries the reason for a failed export", () => {
    // The bug this fixes: with no error field, the only place a reason could live
    // was export-log frames — which a refresh discards, because status returns no
    // logs, and which the ring buffer can evict on a long export.
    const session = seed(GUID, {
      state: "exporting",
      export_state: JSON.stringify({
        state: "failed",
        partialReason: null,
        error: sanitiseExportError("disk"),
        id: "x".repeat(43),
        notebook: "Work",
        progress: null,
        startedAt: NOW - 1000,
        finishedAt: NOW,
      }),
    });
    const snapshot = buildSnapshot(
      session,
      NOW,
      { state: "loaded", items: ["Work"] },
      PUBLIC_ORIGIN,
    );
    expect(snapshot.export.state).toBe("failed");
    expect(snapshot.export.error).toMatch(/disk/i);
  });

  it("is null on a successful export, so the key is always present", () => {
    const session = seed(GUID, {
      state: "authenticated",
      export_state: JSON.stringify({ state: "done", partialReason: null, id: "x".repeat(43) }),
    });
    const snapshot = buildSnapshot(
      session,
      NOW,
      { state: "loaded", items: ["Work"] },
      PUBLIC_ORIGIN,
    );
    // Always present, so a client never branches on a missing key.
    expect(snapshot.export.error).toBeNull();
  });

  it("caps a stored error that is far too long", () => {
    // Defence in depth: parseExportState truncates, so even a row written by
    // something else cannot flood the snapshot.
    const session = seed(GUID, {
      state: "exporting",
      export_state: JSON.stringify({
        state: "failed",
        partialReason: null,
        error: "x".repeat(10_000),
        id: "x".repeat(43),
      }),
    });
    const snapshot = buildSnapshot(
      session,
      NOW,
      { state: "loaded", items: ["Work"] },
      PUBLIC_ORIGIN,
    );
    expect(snapshot.export.error).toHaveLength(MAX_EXPORT_ERROR_CHARS);
  });

  it("drops a non-string error rather than rendering it", () => {
    const session = seed(GUID, {
      state: "exporting",
      export_state: JSON.stringify({
        state: "failed",
        partialReason: null,
        error: { message: "an object, not a string" },
        id: "x".repeat(43),
      }),
    });
    const snapshot = buildSnapshot(
      session,
      NOW,
      { state: "loaded", items: ["Work"] },
      PUBLIC_ORIGIN,
    );
    expect(snapshot.export.error).toBeNull();
  });
});
