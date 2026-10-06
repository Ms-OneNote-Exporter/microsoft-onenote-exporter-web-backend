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
}

/** Input for an abort. */
export interface AbortExportInput {
  readonly sessionId: string;
  readonly exportId: string;
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