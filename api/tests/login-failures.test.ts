/**
 * The login failure mapping, and the test that keeps it honest.
 *
 * This file is where the two repositories meet. Nothing here can see the other
 * side's code except through the published package, and that is the point: two
 * implementations sharing one contract is where every serious bug in this project
 * has come from. So the assertions here are made against the **real exported
 * union**, not against a copy of it that would drift silently.
 */
import { describe, it, expect } from "vitest";
import {
  LOGIN_REASONS,
  LOGIN_FAILURE_KINDS,
  LOGIN_FAILURE_MESSAGES,
  loginFailureKind,
  loginFailureMessage,
  readLoginReason,
} from "../src/login-failures.js";

/**
 * The vocabulary, read from the package rather than transcribed here.
 *
 * A dev dependency on purpose. `@msout/microsoft-webauth` drags Playwright in,
 * and the api must not depend on it — but a *test* may, and it must, because the
 * alternative is two hand-maintained lists that agree until they do not.
 */
import {
  LOGIN_REASONS as UPSTREAM_REASONS,
  LOGIN_EVENT_TYPES as UPSTREAM_EVENT_TYPES,
  CHALLENGE_KINDS as UPSTREAM_CHALLENGE_KINDS,
} from "@msout/microsoft-webauth";

describe("the reason vocabulary has not drifted from the package", () => {
  it("declares exactly the reasons @msout/microsoft-webauth reports", () => {
    // The enforcement for the transcription in src/login-failures.ts. A reason
    // added upstream turns this red; it does not reach production as a generic
    // "something went wrong" that nobody can act on.
    expect([...LOGIN_REASONS].sort()).toEqual([...UPSTREAM_REASONS].sort());
  });

  it("has no duplicates, which would make a reason ambiguous", () => {
    expect(new Set(LOGIN_REASONS).size).toBe(LOGIN_REASONS.length);
  });
});

describe("the classification table", () => {
  it("covers every reason — no reason falls through to generic by accident", () => {
    expect(Object.keys(LOGIN_FAILURE_KINDS).sort()).toEqual([...LOGIN_REASONS].sort());
  });

  it("gives every reason a real classification", () => {
    for (const reason of LOGIN_REASONS) {
      const kind = LOGIN_FAILURE_KINDS[reason];
      expect(kind).toBeDefined();
      expect(["credentials", "challenge", "generic"]).toContain(kind);
    }
  });

  it("calls a refused password the only thing that is actually a credentials problem", () => {
    // The whole reason this module exists: a wrong password and a Microsoft outage
    // both resolve to `false` from login(), and telling someone their correct
    // password is wrong sends them to reset it.
    expect(loginFailureKind("credentials_rejected")).toBe("credentials");
  });

  it("does not call a challenge a credentials problem", () => {
    // These accounts are fine. The flow is waiting on the user, or on a decision
    // only the user can make, and a password reset fixes none of it.
    for (const reason of ["code_prompt", "approver_prompt", "no_password_route"]) {
      expect(loginFailureKind(reason)).toBe("challenge");
      expect(loginFailureKind(reason)).not.toBe("credentials");
    }
  });

  it("does not call an unusable artefact a credentials problem", () => {
    // Reached the app, then saved nothing usable. Retrying the password achieves
    // exactly nothing, so it must not be advice about the password.
    expect(loginFailureKind("auth_state_unusable")).not.toBe("credentials");
  });

  it("names exactly one reason as a credentials problem", () => {
    // A total assertion rather than a spot check, because the spot checks above
    // all pass on a table where four reasons are wrong: they only assert that
    // *these* reasons are not `credentials`, and say nothing about the rest.
    //
    // Verified by deliberately misclassifying `password_field` as `credentials`
    // while this test existed and every other test in the file still passed — the
    // module would then tell a user to check their password for a run that never
    // got as far as one. This is the assertion that catches that.
    const asCredentials = LOGIN_REASONS.filter((r) => LOGIN_FAILURE_KINDS[r] === "credentials");
    expect(asCredentials).toEqual(["credentials_rejected"]);
  });

  it("classifies a successful-looking reason as generic, not as credentials", () => {
    // `password_field` is the happy path's intermediate state; the package emits
    // `reason: null` on success, so it should never arrive as a terminal reason.
    // If it ever does — a future refactor — it must not produce password advice.
    expect(LOGIN_FAILURE_KINDS.password_field).toBe("generic");
  });

  it("treats network, timeout and unknown identically, because a user can act on none of them", () => {
    // Upstream keeps them apart because the runner can tell them apart. The user
    // cannot: the advice is the same for all three.
    expect(loginFailureKind("network")).toBe("generic");
    expect(loginFailureKind("timed_out")).toBe("generic");
    expect(loginFailureKind("unknown")).toBe("generic");
  });
});

describe("loginFailureKind", () => {
  it("falls back to generic for anything unrecognised", () => {
    // A reason arriving over a socket from a container is untrusted input. A login
    // that fails to report is worse than one that reports vaguely.
    for (const value of ["", "not_a_reason", "CREDENTIALS_REJECTED_", "../etc/passwd"]) {
      expect(loginFailureKind(value)).toBe("generic");
    }
    expect(loginFailureKind(null)).toBe("generic");
    expect(loginFailureKind(undefined)).toBe("generic");
    expect(loginFailureKind(42 as unknown as string)).toBe("generic");
  });

  it("tolerates casing and surrounding space", () => {
    // The value crosses a container boundary and may be re-cased in transit.
    expect(loginFailureKind("  credentials_rejected  ")).toBe("credentials");
    expect(loginFailureKind("CREDENTIALS_REJECTED")).toBe("credentials");
  });
});

describe("the messages", () => {
  it("exist for every classification", () => {
    for (const kind of ["credentials", "challenge", "generic"]) {
      expect(typeof LOGIN_FAILURE_MESSAGES[kind as keyof typeof LOGIN_FAILURE_MESSAGES]).toBe("string");
    }
  });

  it("never mention the reason code, a path, or a notebook", () => {
    // These strings cross to a browser and are rendered. A reason code in user-facing
    // text is leaked vocabulary; a path is a filesystem disclosure.
    for (const [kind, message] of Object.entries(LOGIN_FAILURE_MESSAGES)) {
      expect(message).not.toMatch(/credentials_rejected|_prompt|interstitial|timed_out/);
      expect(message).not.toMatch(/\//);
      expect(message).not.toMatch(/[A-Za-z]:\\\\|\\\\home|\/tmp|\/srv/i);
      expect(message.length).toBeGreaterThan(10);
      expect(message.length).toBeLessThan(200);
      void kind;
    }
  });

  it("tell the user to check their password only in the credentials case", () => {
    // Asserted as text, because the *advice* is the contract. A generic message
    // that says "check your password" is the bug this module prevents, and it
    // would pass every other test in this file.
    expect(LOGIN_FAILURE_MESSAGES.credentials).toMatch(/password/i);
    expect(LOGIN_FAILURE_MESSAGES.generic).not.toMatch(/password/i);
    expect(LOGIN_FAILURE_MESSAGES.challenge).not.toMatch(/password/i);
  });

  it("always return a string, so no call site needs a null check", () => {
    expect(typeof loginFailureMessage("credentials_rejected")).toBe("string");
    expect(typeof loginFailureMessage(null)).toBe("string");
    expect(typeof loginFailureMessage("nonsense")).toBe("string");
    expect(loginFailureMessage(null)).toBe(LOGIN_FAILURE_MESSAGES.generic);
  });
});

describe("readLoginReason", () => {
  it("reads `reason`, the current contract", () => {
    expect(readLoginReason({ ok: false, reason: "credentials_rejected" })).toBe("credentials_rejected");
  });

  it("reads `code` too, so the mock stays an honest test double", () => {
    // The api's mock predates the `reason` vocabulary and still emits `code`. A
    // mock that emitted a key the real adapter never sends would be testing a
    // shape that cannot occur.
    expect(readLoginReason({ ok: false, code: "bad_credentials" })).toBe("bad_credentials");
  });

  it("prefers `reason` when both are present", () => {
    expect(readLoginReason({ reason: "network", code: "bad_credentials" })).toBe("network");
  });

  it("returns null for anything without a usable string", () => {
    expect(readLoginReason({})).toBeNull();
    expect(readLoginReason({ reason: 42 })).toBeNull();
    expect(readLoginReason(null)).toBeNull();
    expect(readLoginReason("credentials_rejected")).toBeNull();
    expect(readLoginReason(undefined)).toBeNull();
  });

  it("feeds straight into the classifier, so an old `code` still classifies", () => {
    // The end-to-end shape: what a runner sends, through the reader, to advice.
    const reason = readLoginReason({ code: "bad_credentials" });
    // Not a member of the union, so it is generic — which is the right answer for
    // a legacy code, and is asserted rather than assumed.
    expect(loginFailureKind(reason)).toBe("generic");

    const current = readLoginReason({ reason: "credentials_rejected" });
    expect(loginFailureKind(current)).toBe("credentials");
  });
});

describe("the challenge vocabulary, for the same reason", () => {
  it("matches the package's challenge kinds", () => {
    // The api does not own the challenge vocabulary — the runner observes it — but
    // it renders it, so it has to know what can arrive. The frontend's parser is
    // the other consumer.
    expect([...UPSTREAM_CHALLENGE_KINDS].sort()).toEqual(["code", "phone-approval"]);
  });

  it("leaves session vocabulary to the api, which owns it", () => {
    // `login-started`, `login-success`, `login-failed` and `auth-state` are the
    // api's. The package deliberately does not emit them, and a regression that
    // added one would mean two components claiming the same statement.
    for (const type of ["login-started", "login-success", "login-failed", "auth-state"]) {
      expect(UPSTREAM_EVENT_TYPES).not.toContain(type);
    }
  });
});
