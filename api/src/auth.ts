/**
 * Session authentication.
 *
 * PLAN-v3 §4. Three things make this the load-bearing part of the api under the
 * two-component split, where v2 had deferred it:
 *
 *   1. The secret is verified from a hash in constant time, so neither the stored
 *      value nor a comparison reveals anything to a caller who can measure.
 *   2. A rejected credential and an unknown session are deliberately
 *      indistinguishable to the caller — the same status, the same body — so the
 *      endpoint is not an oracle for which GUIDs exist.
 *   3. An expired session is a 401 and not a readable state, which is why
 *      `GET /api/session/status` can assume its 200 means the session exists.
 */

import type { AuthState, Db, SessionRow, SessionState } from "./db.js";
import {
  deriveCsrfToken,
  isValidGuid,
  isValidSecret,
  secretsMatch,
} from "./session.js";

/** Why authentication failed. Never surfaced to the caller — see the note above. */
export type AuthFailure =
  | "no-session-cookie"
  | "malformed-guid"
  | "malformed-secret"
  | "unknown-session"
  | "wrong-secret"
  | "expired";

/** The outcome of authenticating a request. */
export type AuthResult =
  | {
      readonly ok: true;
      readonly session: SessionRow;
      readonly csrfKey: string;
      readonly csrfToken: string;
      /** The value to put in the `__Host-msout` cookie. */
      readonly sessionValue: string;
    }
  | { readonly ok: false; readonly failure: AuthFailure };

/** The status an auth failure maps to. */
export function authStatus(failure: AuthFailure): number {
  switch (failure) {
    case "no-session-cookie":
    case "unknown-session":
    case "wrong-secret":
    case "expired":
      // One status for every credential-shaped failure. Distinguishing them would
      // tell a caller whether a GUID exists, which is an enumeration oracle.
      return 401;
    case "malformed-guid":
    case "malformed-secret":
      return 400;
  }
}

/** Body for an auth failure. Identical for every 401, by design. */
export function authErrorBody(): { error: string } {
  return { error: "unauthorised" };
}

/** Inputs to an authentication attempt. */
export interface AuthenticateInput {
  /** The GUID presented in the session cookie. */
  readonly guid: string | undefined;
  /** The 43-character secret presented in the session cookie. */
  readonly secret: string | undefined;
  /** Milliseconds since the epoch, injected so tests are not clock-dependent. */
  readonly now: number;
}

/**
 * authenticate verifies a session cookie pair against the database.
 *
 * The order of the checks is deliberate and each step short-circuits:
 *
 *   1. shape — a malformed GUID or secret is a client bug (400), not an
 *      authentication failure, and conflating them would make a frontend bug
 *      look like a session problem.
 *   2. existence — an unknown GUID gets the same answer as a wrong secret.
 *   3. expiry — checked before the secret, so an expired session cannot be probed
 *      with a candidate secret to see whether it was ever valid.
 *   4. secret — constant-time comparison against sha256(secret).
 *
 * Step 3 before step 4 is the subtle one: the reverse order would let an attacker
 * holding an expired session's GUID learn whether their guessed secret was right,
 * for as long as the row survives.
 */
export function authenticate(db: Db, input: AuthenticateInput): AuthResult {
  const { guid, secret, now } = input;

  if (guid === undefined || guid === "") {
    return { ok: false, failure: "no-session-cookie" };
  }
  if (!isValidGuid(guid)) {
    return { ok: false, failure: "malformed-guid" };
  }
  if (secret === undefined || secret === "") {
    return { ok: false, failure: "no-session-cookie" };
  }
  if (!isValidSecret(secret)) {
    return { ok: false, failure: "malformed-secret" };
  }

  const session = db.getSession(guid);
  if (session === undefined) {
    return { ok: false, failure: "unknown-session" };
  }

  // Expiry before the secret comparison, deliberately. See the note above.
  if (session.expires_at <= now) {
    return { ok: false, failure: "expired" };
  }

  if (session.secret_hash === null) {
    // A row with no secret cannot authenticate anyone. Treated as unknown rather
    // than as a bug, so a partially-created row cannot be exploited.
    return { ok: false, failure: "unknown-session" };
  }
  if (!secretsMatch(secret, session.secret_hash)) {
    return { ok: false, failure: "wrong-secret" };
  }

  if (session.csrf_key === null) {
    return { ok: false, failure: "unknown-session" };
  }

  return {
    ok: true,
    session,
    csrfKey: session.csrf_key,
    csrfToken: deriveCsrfToken(session.csrf_key, guid),
    // The cookie echoes back the same GUID+secret pair the client was given. The
    // secret is not looked up by value anywhere, so this is a verbatim echo rather
    // than a lookup, and the row is found by GUID.
    sessionValue: `${guid}:${secret}`,
  };
}

/* Cookie construction lives in cookies.ts; this module decides whether a
 * credential is acceptable, not how it is transported. */

/** The snapshot a client sees. Shaped to match what the frontend renders against. */
export interface SessionSnapshot {
  readonly protocol: number;
  readonly serverTime: string;
  readonly session: {
    readonly state: Exclude<SessionState, "erased">;
    readonly createdAt: string;
    readonly expiresAt: string;
    readonly idleExpiresAt: string | null;
  };
  readonly auth: {
    readonly state: AuthState;
    readonly lastCheckedAt: string | null;
  };
  readonly notebooks: {
    readonly state: "idle" | "listing" | "loaded" | "failed";
    readonly items: string[];
  };
  readonly export: {
    readonly state: "none" | "queued" | "running" | "done" | "partial" | "failed";
    /**
     * Why a partial export stopped, or null when it did not.
     *
     * `partial` alone is not enough to render honestly. mac's point: telling a
     * user "you stopped this export" is factually false when the quota or the
     * disk filled up, and it sends them hunting for something they did not do.
     * This separates the two so the message can match the cause — and the
     * difference between "try again" and "free some space and try again" is the
     * whole point of telling them.
     */
    readonly partialReason: "aborted" | "quota" | "disk" | null;
    readonly id: string | null;
    readonly notebook: string | null;
    readonly progress: { pages: number; sections: number; assets: number } | null;
    readonly startedAt: string | null;
    readonly finishedAt: string | null;
  };
  readonly artifact: {
    readonly available: boolean;
    readonly partial: boolean;
    readonly downloadUrl: string | null;
    readonly fileName: string | null;
  };
}

/** Stored export state, as JSON in the session row. */
export interface StoredExportState {
  state: SessionSnapshot["export"]["state"];
  /** See SessionSnapshot.export.partialReason. */
  partialReason: "aborted" | "quota" | "disk" | null;
  id: string | null;
  notebook: string | null;
  progress: { pages: number; sections: number; assets: number } | null;
  startedAt: number | null;
  finishedAt: number | null;
}

/**
 * buildSnapshot renders the restore payload.
 *
 * Everything is always present so a client never branches on a missing key; only
 * leaves are optional, and an absent leaf is `null` rather than missing. That
 * shape is the cross-component contract with the frontend, so it is defined here
 * in one place rather than assembled per handler.
 */
export function buildSnapshot(
  session: SessionRow,
  now: number,
  notebooks: { state: SessionSnapshot["notebooks"]["state"]; items: string[] },
): SessionSnapshot {
  const exportState = parseExportState(session.export_state);

  return {
    protocol: PROTOCOL_VERSION,
    serverTime: iso(now),
    session: {
      // `erased` never reaches a snapshot: the erase machine deletes the row, so
      // a snapshot for an erased session cannot be produced. The type excludes it
      // rather than the runtime guessing.
      state: session.state === "erased" ? "erasing" : session.state,
      createdAt: iso(session.created_at),
      expiresAt: iso(session.expires_at),
      idleExpiresAt: session.idle_expires_at === null ? null : iso(session.idle_expires_at),
    },
    auth: {
      state: session.auth_state,
      // Null until the first successful login, and then the login time — not a
      // health-probe timestamp, because §13.2 has no checkAuth() preflight.
      lastCheckedAt:
        session.auth_state === "valid" && session.last_activity_at > 0
          ? iso(session.last_activity_at)
          : null,
    },
    notebooks: {
      state: notebooks.state,
      items: notebooks.items,
    },
    export: {
      state: exportState?.state ?? "none",
      partialReason: exportState?.partialReason ?? null,
      id: exportState?.id ?? null,
      notebook: exportState?.notebook ?? null,
      progress: exportState?.progress ?? null,
      startedAt: exportState?.startedAt === null || exportState?.startedAt === undefined
        ? null
        : iso(exportState.startedAt),
      finishedAt:
        exportState?.finishedAt === null || exportState?.finishedAt === undefined
          ? null
          : iso(exportState.finishedAt),
    },
    artifact: {
      available: session.artifact_id !== null,
      partial: session.artifact_partial === 1,
      // The download URL carries the opaque artifact id and nothing else — no
      // GUID, no notebook name (PLAN-v3 §5, invariant 8).
      downloadUrl: session.artifact_id === null ? null : `/files/${session.artifact_id}`,
      // The notebook name comes from Content-Disposition at download time, not
      // from here, because putting it in the URL would leak it into Referer and
      // access logs.
      fileName: null,
    },
  };
}

/**
 * The api protocol version.
 *
 * PLAN-v3 §7.2. The frontend pins this as a literal and a mismatch renders a
 * "reload" prompt instead of a confusing failure — a v3 frontend against a v2 api
 * produces a 404 or a silently missing SSE field, and the natural reaction is to
 * debug the wrong component.
 */
export const PROTOCOL_VERSION = 3;

/** The api build identifier, surfaced on /api/public/version. */
export const API_BUILD = process.env.BUILD_ID ?? "dev";

/** iso renders a millisecond timestamp as ISO-8601 UTC with milliseconds. */
export function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/**
 * parseExportState reads the stored export JSON, tolerating absence and garbage.
 *
 * A row whose export_state is unreadable is a row that must still produce a
 * snapshot — the session is valid and its auth.json may be intact, so refusing
 * the whole response would log the user out over a corrupt column.
 */
export function parseExportState(raw: string | null): StoredExportState | null {
  if (raw === null || raw === "") return null;
  try {
    const parsed = JSON.parse(raw) as Partial<StoredExportState>;
    if (typeof parsed.state !== "string") return null;
    return {
      state: parsed.state,
      // Validated rather than trusted. A stored value outside the union would put
      // the client in a state it has no rendering for, and `partial` with an
      // unknown reason is the one case where guessing a message would be wrong.
      partialReason:
        parsed.partialReason === "aborted" ||
        parsed.partialReason === "quota" ||
        parsed.partialReason === "disk"
          ? parsed.partialReason
          : null,
      id: parsed.id ?? null,
      notebook: parsed.notebook ?? null,
      progress: parsed.progress ?? null,
      startedAt: parsed.startedAt ?? null,
      finishedAt: parsed.finishedAt ?? null,
    };
  } catch {
    return null;
  }
}