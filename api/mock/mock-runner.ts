/**
 * A scripted runner, for local development and the frontend's mock server.
 *
 * It emits the same SSE events the real runner would, in the same order, with
 * plausible delays — so a frontend can be built and exercised end to end without a
 * Docker socket, a Chromium download, or a Microsoft account.
 *
 * What this is *for*: letting a client be written and reviewed against a backend
 * that behaves like the real one. What this is **not**: evidence that the
 * credential path works. It does not read the credential bytes (deliberately — see
 * below), it does not run any of the `@msout/*` packages, and it cannot tell you
 * anything about whether a real login would succeed.
 *
 * ## The credential bytes
 *
 * This drains and discards the stream rather than inspecting it. That is not an
 * oversight and it is not laziness — it is the property the whole credential path
 * is built to have. A development tool that logged, parsed, asserted on, or
 * length-checked the password would be a second place where a credential is
 * handled, and the api's guarantee is that the bytes are forwarded without being
 * accumulated. So the mock proves the *framing* works (the route caps at 4 KB and
 * rejects before reading) and does nothing at all with the content.
 *
 * The one thing it does report is the byte count, because a client that sends a
 * truncated password should get a login failure rather than silence — and that is
 * a statement about the transport, not about the value.
 */

import type { RunnerAdapter, RunnerEraseControl, StartExportInput, SubmitCredentialInput } from "../src/runner-adapter.js";
import type { Db } from "../src/db.js";
import type { SseHub } from "../src/sse.js";

/** How the scripted login should behave. Set per-session by the mock server. */
export type LoginScript = "success" | "mfa-code" | "mfa-number" | "bad-password" | "timeout";

/** Knobs, so a UI can be developed without waiting minutes for a fake. */
export interface MockRunnerOptions {
  readonly db: Db;
  readonly sse: SseHub;
  /** Multiplier on every scripted delay. 0 makes everything instant. */
  readonly speed?: number;
  /** Notebook names the scripted listing returns. */
  readonly notebooks?: readonly string[];
  /** How the next login behaves. Consumed once, then reset to "success". */
  readonly nextLogin?: LoginScript;
}

const DEFAULT_NOTEBOOKS = ["Personal", "Work", "Projects 2026"] as const;

export class MockRunner implements RunnerAdapter, RunnerEraseControl {
  readonly #db: Db;
  readonly #sse: SseHub;
  readonly #speed: number;
  readonly #notebooks: readonly string[];
  #nextLogin: LoginScript;

  /** Live export abort controllers, so abort can actually cancel a run. */
  readonly #running = new Map<string, AbortController>();

  constructor(options: MockRunnerOptions) {
    this.#db = options.db;
    this.#sse = options.sse;
    this.#speed = options.speed ?? 1;
    this.#notebooks = options.notebooks ?? DEFAULT_NOTEBOOKS;
    this.#nextLogin = options.nextLogin ?? "success";
  }

  /** Sets the behaviour of the next login. Used by the mock server's controls. */
  setNextLogin(script: LoginScript): void {
    this.#nextLogin = script;
  }

  /** The behaviour the next login will use, without consuming it. */
  peekNextLogin(): LoginScript {
    return this.#nextLogin;
  }

  #delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms * this.#speed));
  }

  // ---- login ------------------------------------------------------------

  async submitCredential(input: SubmitCredentialInput): Promise<void> {
    const { sessionId, stream } = input;
    const script = this.#nextLogin;
    this.#nextLogin = "success";

    // Drain and discard. Never buffer, never decode, never log. See the file
    // header: a tool that inspected the password would be a second handler for it.
    let bytes = 0;
    for await (const chunk of stream) {
      bytes += (chunk as Buffer).length;
    }

    // Deliberately NOT re-emitting `login-started`: the route already emitted it
    // before handing the stream over, and a mock that emitted it twice would teach
    // a client to tolerate a duplicate the real runner never sends.
    this.#db.run(
      `UPDATE sessions SET state = 'authenticating', auth_state = 'authenticating' WHERE guid = ?`,
      sessionId,
    );

    await this.#delay(400);
    this.#sse.emit(sessionId, "auth-state", { state: "authenticating" });

    if (script === "bad-password") {
      await this.#delay(300);
      this.#db.run(
        `UPDATE sessions SET auth_state = 'failed', state = 'authenticated' WHERE guid = ?`,
        sessionId,
      );
      this.#sse.emit(sessionId, "login-failed", {
        code: "bad_credentials",
        message: "That email and password combination was not recognised.",
      });
      return;
    }

    if (script === "timeout") {
      // The case §6.1 is most concerned about: a swallowed challenge is a hang,
      // not an error. The mock makes the hang visible and then times it out.
      await this.#delay(15_000);
      this.#db.run(`UPDATE sessions SET auth_state = 'expired' WHERE guid = ?`, sessionId);
      this.#sse.emit(sessionId, "challenge-expired", {});
      this.#sse.emit(sessionId, "auth-state", { state: "expired" });
      return;
    }

    if (script === "mfa-code") {
      this.#sse.emit(sessionId, "challenge", {
        kind: "code",
        label: "Enter the code we sent to your phone",
        timeoutMs: 120_000,
      });
      return;
    }

    if (script === "mfa-number") {
      // §6.1: number matching shows ONE number, the user approves in
      // Authenticator, and the page waits passively. No Approve button.
      this.#sse.emit(sessionId, "challenge", {
        kind: "number-match",
        code: String(42 + Math.floor(Math.random() * 8)),
        timeoutMs: 120_000,
      });
      return;
    }

    await this.#delay(600);
    this.finishLoginSuccess(sessionId);
  }

  /** Marks a session logged in. Shared by the success path and the mock controls. */
  finishLoginSuccess(sessionId: string): void {
    this.#db.run(
      `UPDATE sessions SET auth_state = 'valid', state = 'authenticated', last_activity_at = ?
        WHERE guid = ?`,
      Date.now(),
      sessionId,
    );
    this.#sse.emit(sessionId, "login-success", {});
    this.#sse.emit(sessionId, "auth-state", { state: "valid" });
  }

  // ---- notebooks --------------------------------------------------------

  async listNotebooks(sessionId: string): Promise<void> {
    await this.#delay(500);
    const items = [...this.#notebooks];
    this.#sse.emit(sessionId, "notebooks-listed", { items });
  }

  // ---- export -----------------------------------------------------------

  async startExport(input: StartExportInput): Promise<void> {
    const { sessionId, exportId, notebook, signal } = input;
    const controller = new AbortController();
    this.#running.set(exportId, controller);

    // A caller-supplied signal must actually cancel, or abort would be a lie.
    if (signal.aborted) return;
    signal.addEventListener("abort", () => controller.abort(), { once: true });

    await this.#delay(200);
    if (controller.signal.aborted) return;

    this.#sse.emit(sessionId, "export-started", { id: exportId, notebook });

    const pages = 24 + Math.floor(Math.random() * 40);
    const sections = 6 + Math.floor(Math.random() * 5);
    const assets = 120 + Math.floor(Math.random() * 400);

    for (let page = 1; page <= pages; page++) {
      if (controller.signal.aborted) return;
      await this.#delay(120);

      this.#sse.emit(sessionId, "export-progress", {
        id: exportId,
        progress: {
          pages: page,
          sections: Math.min(sections, Math.ceil((page / pages) * sections)),
          assets: Math.min(assets, Math.round((page / pages) * assets)),
        },
      });

      if (page % 4 === 0) {
        this.#sse.emit(sessionId, "export-log", {
          id: exportId,
          line: `exported page ${page}/${pages}`,
        });
      }
    }

    if (controller.signal.aborted) return;

    // A real run writes an artifact under an id and records it in SQLite; the
    // snapshot's `artifact.available` is what a client uses to show a download
    // link, so it is populated here rather than left permanently false.
    const artifactId = "mock".padEnd(43, "0");
    this.#db.run(
      `UPDATE sessions SET artifact_id = ?, artifact_partial = 0 WHERE guid = ?`,
      artifactId,
      sessionId,
    );
    this.#db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({
        state: "done",
        partialReason: null,
        id: exportId,
        notebook,
        progress: { pages, sections, assets },
        startedAt: Date.now(),
        finishedAt: Date.now(),
      }),
      sessionId,
    );
    this.#sse.emit(sessionId, "export-done", { id: exportId, notebook, pages, sections, assets });
  }

  async abortExport(input: { sessionId: string; exportId: string }): Promise<void> {
    const controller = this.#running.get(input.exportId);
    // The route has already recorded the partial state; this only cancels the
    // run. §8.2: abort preserves what is on disk.
    if (controller === undefined) return;
    controller.abort();
    this.#running.delete(input.exportId);
  }

  /** Marks a session's export partial for a given reason. Used by the controls. */
  markPartial(sessionId: string, exportId: string, reason: "aborted" | "quota" | "disk"): void {
    this.#db.run(
      `UPDATE sessions SET export_state = ? WHERE guid = ?`,
      JSON.stringify({
        state: "partial",
        partialReason: reason,
        id: exportId,
        notebook: null,
        progress: null,
        startedAt: null,
        finishedAt: Date.now(),
      }),
      sessionId,
    );
    this.#sse.emit(sessionId, "export-partial", { id: exportId, reason });
  }

  // ---- erase ------------------------------------------------------------

  async abort(sessionId: string): Promise<void> {
    for (const [exportId, controller] of this.#running) {
      controller.abort();
      this.#running.delete(exportId);
    }
    void sessionId;
  }

  async freeze(sessionId: string): Promise<void> {
    this.#sse.emit(sessionId, "session-status", { state: "erasing" });
  }

  async shredDirectory(sessionId: string): Promise<void> {
    // There is no directory in a mock, and pretending to shred one would be a lie
    // about the property that matters. The api's erase machine is what this
    // exercises, and it is real code.
    void sessionId;
  }
}