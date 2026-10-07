/**
 * Login failure reasons, and what the user is told.
 *
 * `@msout/microsoft-webauth` reports *what it saw on screen*. This module decides
 * what that means for a session, and it is the only place in the api that does.
 * The split is deliberate: the runner cannot see a session, and the api cannot see
 * a Microsoft login screen, so neither can own both vocabularies.
 *
 * ## Why the vocabulary is re-declared rather than imported
 *
 * `LOGIN_REASONS` is exported by the package, and its docblock says a caller
 * should assert its mapping table against the real union. That is exactly what
 * {@link LOGIN_REASONS} below is for — it is a **transcription**, and
 * `tests/login-failures.test.ts` asserts it equals the package's exported array
 * by value.
 *
 * It is a transcription rather than an import because this api's `dependencies`
 * is `{ fastify }` and nothing else — the api never runs a browser and never loads
 * Playwright. Adding `@msout/microsoft-webauth` as a dependency to obtain an
 * array of thirteen strings would pull a Playwright-sized tree into a service that
 * does not need it, and the runner is the component that owns that dependency.
 *
 * So: the union is declared here, and a test fails when the two drift. The test
 * is the enforcement; the declaration is what keeps the api buildable on its own.
 */

/**
 * Every reason `@msout/microsoft-webauth` can report.
 *
 * Transcribed from `LOGIN_REASONS` in that package. Verified by
 * `tests/login-failures.test.ts`, which imports the package and compares — so a
 * reason added there turns this test red instead of silently falling through to
 * the generic message below.
 */
export const LOGIN_REASONS = [
  "password_field",
  "unreadable",
  "unchanged",
  "max_steps",
  "code_prompt",
  "approver_prompt",
  "no_password_route",
  "credentials_rejected",
  "auth_state_unusable",
  "network",
  "timed_out",
  "interstitial",
  "unknown",
] as const;

/** One of {@link LOGIN_REASONS}. */
export type LoginReason = (typeof LOGIN_REASONS)[number];

/**
 * How a reason is classified for the session.
 *
 * Three outcomes, not two, because the middle one is the case this whole module
 * exists for: telling someone their correct password is wrong sends them to
 * reset it.
 */
export type LoginFailureKind =
  /** The credential was refused. Only now is "check your password" honest. */
  | "credentials"
  /** Microsoft is waiting on the user, or on a decision only the user can make. */
  | "challenge"
  /** Nothing actionable was learned. Say so plainly. */
  | "generic";

/**
 * The classification for each reason.
 *
 * A closed set, and a **total** one — every reason has an entry. A missing key
 * would fall through to `generic`, which is safe but silent, and silent is how a
 * new cause gets folded into a generic message forever. The test asserts that
 * this table's keys are exactly `LOGIN_REASONS`, so adding a reason upstream
 * fails here rather than degrading.
 */
export const LOGIN_FAILURE_KINDS: Readonly<Record<LoginReason, LoginFailureKind>> = {
  // Microsoft itself refused the account or the password. This is the only
  // reason that licenses telling a user to check what they typed.
  credentials_rejected: "credentials",

  // Microsoft is asking the user to do something. Not a failed credential, and a
  // password reset does not fix it — the account is fine, the flow is waiting.
  code_prompt: "challenge",
  approver_prompt: "challenge",
  no_password_route: "challenge",

  // Reached the password field on the way to failing somewhere else. Never seen as
  // a terminal reason by the package (it emits `reason: null` on success), and
  // listed so the table stays exhaustive if that ever changes.
  password_field: "generic",

  // Reached the app, then could not save anything usable. The sign-in worked; the
  // artefact did not. Retrying the password would achieve exactly nothing.
  auth_state_unusable: "generic",

  // A screen this tool does not recognise, a screen it could not read, and a walk
  // that gave up. All three are "not the password's fault", and all three are
  // equally uninformative to a user.
  interstitial: "generic",
  unreadable: "generic",
  unchanged: "generic",
  max_steps: "generic",

  // The network, and the deadline. Distinct upstream because the runner can tell
  // them apart, and identical here because a user can act on neither — retry.
  network: "generic",
  timed_out: "generic",

  // Upstream's deliberate escape hatch for a failure it could not classify. It
  // declines to guess rather than naming the closest reason, and so do we.
  unknown: "generic",
};

/**
 * The message shown for each classification.
 *
 * **User-facing text, and deliberately uninformative for the generic case.** It
 * crosses to a browser and is rendered. It carries no path, no notebook name, no
 * Microsoft error string, and no reason code — the reason vocabulary is for logs
 * and for this api's own decisions, not for display. `routes.ts` never passes a
 * raw `error.message` through for the same reason.
 */
export const LOGIN_FAILURE_MESSAGES: Readonly<Record<LoginFailureKind, string>> = {
  credentials: "Microsoft did not accept that password. Check it and try again.",
  challenge:
    "Microsoft is asking for an extra sign-in step on your account, which this service cannot complete.",
  generic: "The sign-in could not be completed. Please try again in a moment.",
};

/**
 * The classification for a reported reason.
 *
 * Unknown strings become `generic` rather than throwing. A reason arriving from a
 * container over a socket is untrusted input by definition, and a login that
 * fails to report is worse than one that reports vaguely — so the default has to
 * be safe, not loud.
 *
 * @param reason - A `LoginReason`, or anything a runner sent.
 */
export function loginFailureKind(reason: string | null | undefined): LoginFailureKind {
  if (typeof reason !== "string") return "generic";
  const match = LOGIN_FAILURE_KINDS[reason.trim().toLowerCase() as LoginReason];
  return match ?? "generic";
}

/**
 * The message for a reported reason.
 *
 * Always returns a string. There is no "no message" path, because the caller
 * needs one and a nullable return is a null check at every call site.
 */
export function loginFailureMessage(reason: string | null | undefined): string {
  return LOGIN_FAILURE_MESSAGES[loginFailureKind(reason)];
}

/**
 * Reads the reason off a runner's failure payload.
 *
 * Accepts both spellings, deliberately. `login-result` from the package carries
 * `reason`; the api's own mock, written before that vocabulary existed, still
 * emits `code`. Honouring both keeps the mock honest as a test double — a mock
 * that emitted a key the real adapter never sends would be testing a shape that
 * cannot occur, which is the mock's failure mode in every project that has one.
 *
 * `reason` wins when both are present, because that is the current contract.
 */
export function readLoginReason(payload: unknown): string | null {
  if (payload === null || typeof payload !== "object") return null;
  const record = payload as Record<string, unknown>;
  if (typeof record.reason === "string") return record.reason;
  if (typeof record.code === "string") return record.code;
  return null;
}
