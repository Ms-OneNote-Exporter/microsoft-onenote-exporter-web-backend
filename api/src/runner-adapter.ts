/**
 * The seam between `api` and a runner.
 *
 * PLAN-v3 §2.1's capability table says the api holds no Docker socket, no vault
 * mount and no egress — so every route that needs a running container has to ask
 * something that does. This interface is that "something", named once.
 *
 * It exists for two reasons.
 *
 * **It is the real architecture.** When the runner sidecar lands (§12 steps 1–2),
 * a real adapter implements this and the routes stop returning 501. The alternative
 * — each route reaching for a runner address directly — would scatter that
 * knowledge across four handlers and make the contract with the runner implicit.
 *
 * **It is what makes the mock possible.** Every method here is event-driven: it
 * takes an input and reports progress over SSE rather than returning a result,
 * because that is genuinely how the real flow works — a login does not finish
 * inside the request, it finishes minutes later. A mock that returned a result
 * would be testing a shape the real adapter cannot have.
 *
 * Absent adapter → the routes return 501, which is the current behaviour. That is
 * why the contract mac is building against does not change when this lands.
 */

import type { Readable } from "node:stream";

/** An MFA challenge, as PLAN-v2 §6.1 models it. */
export type Challenge =
  | { readonly kind: "code"; readonly label: string; readonly timeoutMs: number }
  | { readonly kind: "number-match"; readonly code: string; readonly timeoutMs: number };

/** Input for a credential submission. */
export interface SubmitCredentialInput {
  readonly sessionId: string;
  /**
   * The Microsoft account the password belongs to.
   *
   * An email address or a username — Microsoft accepts either, and telling a user
   * to "enter your email" when their account is a username is a dead end.
   *
   * **It is a header, not part of the body**, which is the whole point: the
   * credential stream stays byte-identical from the browser to the runner. Putting
   * both in one body would need a delimiter, and a delimiter is another place for
   * the truncation bug this pair has shipped twice from opposite ends.
   *
   * Not a secret, but still an identifier: never log it.
   */
  readonly account: string;
  /**
   * The raw credential stream.
   *
   * Already framed and capped by the route — `checkFraming` against a ~4 KB limit
   * in `onRequest`, and `capStream` in the handler. An adapter reads this; it
   * must not buffer it into a string, because the api's whole credential-path
   * guarantee is that the bytes are never accumulated anywhere.
   */
  readonly stream: Readable;
  /** The CSRF-derived session identity, for logging correlation. Not a secret. */
  readonly correlationId: string;
}

/** Input for an export. */
export interface StartExportInput {
  readonly sessionId: string;
  /** The opaque artifact id, also the export's client-visible handle. */
  readonly exportId: string;
  readonly notebook: string;
  /** Aborts the run if signalled. Required, not optional — §6.3 is explicit. */
  readonly signal: AbortSignal;
  /**
   * The notebook's URL, when the listing gave one.
   *
   * Preferred over the name where both are available, because a name is not a
   * stable identifier: two notebooks can share a name, and a rename between
   * listing and exporting would send the exporter at the wrong one. The runner
   * accepts exactly one of the two rather than both, because it has to pick and
   * a caller that supplied both would be relying on which one it picked.
   */
  readonly notebookUrl?: string;
}

/** Input for an abort. */
export interface AbortExportInput {
  readonly sessionId: string;
  readonly exportId: string;
}

/** Input for publishing a finished export's vault. */
export interface PublishArtifactInput {
  readonly sessionId: string;
  /**
   * The api's opaque id — the same one `startExport` was given as `exportId`.
   *
   * The runner does **not** generate one, and must not: it knows the session GUID,
   * and a runner-derived id would put that GUID into every download path, Caddy
   * access log and `Referer`. PLAN-v3 §5 makes the id opaque for exactly that
   * reason, so the id is minted by the api and carried through unchanged.
   */
  readonly artifactId: string;
}

/**
 * RunnerAdapter is everything the api needs from a container it cannot reach.
 *
 * Note what is absent: no method takes an image, a command, a flag, a mount, a
 * network or a path. The api has no way to ask for any of those, which is the
 * same property the orchestrator's verb set has and for the same reason.
 */
export interface RunnerAdapter {
  /**
   * Accept a credential and drive the login to completion over SSE.
   *
   * Returns as soon as the credential has been handed over; the outcome arrives
   * as `challenge` / `challenge-expired` / `login-success` / `login-failed`
   * events on the session's stream. A returned promise resolving means "accepted",
   * not "succeeded".
   */
  submitCredential(input: SubmitCredentialInput): Promise<void>;

  /**
   * List notebooks, reporting the result as a `notebooks-listed` event.
   *
   * Also asynchronous for the same reason: it runs a CLI in a container.
   */
  listNotebooks(sessionId: string): Promise<void>;

  /** Start an export, reporting progress as `export-*` events. */
  startExport(input: StartExportInput): Promise<void>;

  /**
   * Stream the finished vault into the artifact staging directory.
   *
   * This is the second half of publishing, and it is **not** called automatically
   * by `startExport`: an export finishes inside the runner while `startExport` has
   * long since returned 202. Something has to ask, after the work is done.
   *
   * It exists here rather than being folded into `startExport` because the two
   * answer different questions and have different failure modes. `startExport` is
   * fast and failing means the export never began; this is slow (it zips a vault
   * that may be gigabytes) and failing means the export succeeded and produced an
   * archive nobody can download. Collapsing them would make the second failure
   * look like the first, and the user's remedy for each is opposite.
   *
   * PLAN-v3 §2.2: the runner writes to `<ArtifactRoot>/.staging/<artifactId>/` and
   * the orchestrator renames it into place. Neither half is self-publishing — a
   * zip written directly into its final name is readable while it is being
   * written, which is the truncated-archive-with-a-200 failure staging exists to
   * prevent.
   */
  publishArtifact(input: PublishArtifactInput): Promise<void>;

  // ---------------------------------------------------------------------
  // Not in this interface, deliberately, and worth stating because its
  // absence is a real product gap rather than an oversight:
  //
  //   answerChallenge(sessionId, challengeId, code)
  //
  // The runner can be asked for a typed MFA code (`kind: "code"`) and then waits
  // 120 seconds and fails — `login()` has no way to be handed a code mid-flow, and
  // the runner has no route to receive one. The number-match path needs nothing
  // from the user, so it works. A code path needs a runner route, this method, an
  // api route and a frontend screen, and none of those exist.
  //
  // Until they do, `HttpRunnerAdapter` refuses that challenge with a named reason
  // rather than letting it expire silently. See `unsupportedChallenge`.

  /**
   * Abort a running export.
   *
   * §8.2: preserves what is on disk and marks the artifact partial. Must not
   * delete anything.
   */
  abortExport(input: AbortExportInput): Promise<void>;
}

/** The methods the erase machine needs, kept separate because erase is optional. */
export interface RunnerEraseControl {
  abort(sessionId: string): Promise<void>;
  freeze(sessionId: string): Promise<void>;
  shredDirectory(sessionId: string): Promise<void>;
}