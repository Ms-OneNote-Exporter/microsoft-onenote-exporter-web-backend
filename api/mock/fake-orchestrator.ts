/**
 * A fake orchestrator for local development and for the frontend's mock server.
 *
 * It implements the same surface as `OrchestratorClient`, so `api` cannot tell the
 * difference — which is the entire point. Swapping this in does not change a
 * single route, a single status code, or a single header the browser sees.
 *
 * What this fakes and why it is honest about it:
 *
 *   - **The Docker socket.** The real client speaks the Engine API over a unix
 *     socket. There is no socket on a development machine that should be granting
 *     container-creation rights to a test suite, so this is a scripted pool.
 *   - **Slot identity.** The real orchestrator returns its own slot and container
 *     ids. This returns plausible ones, and they are stable per session so a
 *     re-read of the same session returns the same container — which is the
 *     property a client could actually depend on.
 *
 * What this does NOT fake, and is worth stating plainly: it does not make the
 * capability assertions true. `T-X1`, `T-N1`, `T-X2` and `T-N4` are about what a
 * *running* container can see, and nothing in this file changes that. They can
 * only be asserted against a real stack, which is what step 6 is for.
 */

import type {
  FinalizeInput,
  FinalizeResponse,
  OrchestratorResult,
  OrchestratorStats,
  StatResponse,
} from "../src/orchestrator-client.js";

/** Timing the fake applies, overridable so tests run instantly. */
export interface FakeOrchestratorOptions {
  /** How long `claim` takes to "create a container". */
  readonly claimDelayMs?: number;
  /**
   * How many slots the pool has.
   *
   * The fake mirrors the real orchestrator's shape rather than growing on demand:
   * the pool is a fixed set of named slots, and claiming takes one of them. A fake
   * that invents a slot per request could not demonstrate pool exhaustion, which is
   * one of the states worth being able to see.
   */
  readonly size?: number;
  /** Fixed clock, so snapshots are reproducible in tests. */
  readonly now?: () => number;
}

/** One slot in the fake pool. */
interface FakeSlot {
  readonly slotId: string;
  containerId: string;
  sessionGuid: string | null;
}

/**
 * FakeOrchestrator is an in-memory stand-in for the real control plane.
 *
 * Deliberately not a class extending `OrchestratorClient` — that class is
 * constructed with a `fetchImpl` and holds real signing code, and a fake that
 * inherited it would carry signing logic it never needs. It satisfies the same
 * structural interface, which is all `api` requires.
 */
export class FakeOrchestrator {
  readonly #slots = new Map<string, FakeSlot>();
  /** Artifacts `finalize` published, keyed by id. What `stat` reports on. */
  readonly #finalised = new Map<string, { bytes: number; partial: boolean }>();
  readonly #claimDelayMs: number;
  readonly #now: () => number;
  #seq = 0;

  constructor(options: FakeOrchestratorOptions = {}) {
    this.#claimDelayMs = options.claimDelayMs ?? 0;
    this.#now = options.now ?? (() => Date.now());
    for (let i = 1; i <= (options.size ?? 2); i++) {
      const slotId = `slot-${i}`;
      this.#slots.set(slotId, { slotId, containerId: "", sessionGuid: null });
    }
  }

  /** Total slots, claimed or not. Mirrors the real `/stats` `size`. */
  get poolSize(): number {
    return this.#slots.size;
  }

  /** Slots with no session attached — what `/stats` reports as `byState.idle`. */
  get freeSlots(): number {
    let n = 0;
    for (const slot of this.#slots.values()) if (slot.sessionGuid === null) n++;
    return n;
  }

  /**
   * The slot ids, in order.
   *
   * This is the thing the real orchestrator does not expose. The api has to seed
   * its `runners` table with these exact strings, because `sessions.runner_id`
   * holds one and `release`/`recycle` take it back as a `slotId` — and the real
   * `/stats` returns counts only. See `syncPool`'s comment.
   */
  slotIds(): string[] {
    return [...this.#slots.keys()];
  }

  async claim(
    sessionGuid: string,
    _sessionExpiresAt: Date,
  ): Promise<OrchestratorResult<{ slotId: string; containerId: string }>> {
    if (this.#claimDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.#claimDelayMs));
    }
    // Re-claiming an already-bound session returns its existing slot, because the
    // real orchestrator's claim is idempotent per slot and a client may retry
    // after a network blip.
    const existing = [...this.#slots.values()].find((s) => s.sessionGuid === sessionGuid);
    if (existing !== undefined) {
      return {
        ok: true,
        value: { slotId: existing.slotId, containerId: existing.containerId },
      };
    }

    // Any free slot, and a new container id — which is what claiming one means.
    const free = [...this.#slots.values()].find((s) => s.sessionGuid === null);
    if (free === undefined) {
      // Exhaustion. The real one answers 409 for a full pool.
      return { ok: false, error: { kind: "conflict", status: 409 } };
    }
    this.#seq++;
    free.sessionGuid = sessionGuid;
    free.containerId = `mock${String(this.#seq).padStart(6, "0")}`;
    return { ok: true, value: { slotId: free.slotId, containerId: free.containerId } };
  }

  async release(slotId: string): Promise<OrchestratorResult<{ released: boolean }>> {
    const slot = this.#slots.get(slotId);
    if (slot === undefined) {
      // Matches the real orchestrator, which answers 409 for an unknown slot.
      return { ok: false, error: { kind: "conflict", status: 409 } };
    }
    // The container goes away but the slot stays: that is the distinction between
    // release and remove, and a fake that conflated them would hide it.
    slot.sessionGuid = null;
    slot.containerId = "";
    return { ok: true, value: { released: true } };
  }

  async recycle(
    slotId: string,
    _reason: string,
  ): Promise<OrchestratorResult<{ recycled: boolean }>> {
    const slot = this.#slots.get(slotId);
    if (slot === undefined) {
      return { ok: false, error: { kind: "conflict", status: 409 } };
    }
    // A new container id for the same slot, which is what recycle means. The
    // binding survives.
    this.#seq++;
    slot.containerId = `mock${String(this.#seq).padStart(6, "0")}`;
    return { ok: true, value: { recycled: true } };
  }

  async remove(slotId: string): Promise<OrchestratorResult<{ removed: boolean }>> {
    if (!this.#slots.has(slotId)) {
      return { ok: false, error: { kind: "conflict", status: 409 } };
    }
    // remove is only meaningful for a slot nobody is bound to; the real one
    // refuses to remove a live slot, and pretending otherwise would let a test
    // exercise a path a deployment cannot take.
    const slot = this.#slots.get(slotId)!;
    if (slot.sessionGuid !== null) {
      return { ok: false, error: { kind: "conflict", status: 409 } };
    }
    this.#slots.delete(slotId);
    return { ok: true, value: { removed: true } };
  }

  /**
   * stat reports on artifacts that were actually finalised.
   *
   * Driven by `#finalised`, which only `finalize` populates — so a client cannot
   * build a download link for an artifact the pipeline never published. This used
   * to answer `exists: false` unconditionally, deliberately, so the missing publish
   * step stayed visible while no code called it. Now that `finalize` exists, a
   * constant `false` would be a second false claim: it would hide a publish that
   * silently stopped happening.
   */
  async stat(artifactId: string): Promise<OrchestratorResult<StatResponse>> {
    const found = this.#finalised.get(artifactId);
    return {
      ok: true,
      value: found === undefined ? { exists: false, size: 0 } : { exists: true, size: found.bytes },
    };
  }

  /**
   * finalize publishes a staged archive under its artifact id.
   *
   * Records what a real `os.Rename` would have moved into place, including the
   * partial naming, so the mock's `stat` and the mock's archive name agree with the
   * production shapes rather than with whatever is convenient here.
   *
   * A `409` for an id nothing was staged under is kept, because the api's handling
   * of it is the interesting part: it means "the export produced no archive", not
   * "try again".
   */
  async finalize(input: FinalizeInput): Promise<OrchestratorResult<FinalizeResponse>> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(input.artifactId)) {
      return { ok: false, error: { kind: "conflict", status: 409 } };
    }
    const bytes = 1024;
    this.#finalised.set(input.artifactId, { bytes, partial: input.partial });
    return {
      ok: true,
      value: {
        artifactId: input.artifactId,
        archiveName: input.partial ? "vault.partial.zip" : "vault.zip",
        bytes,
        partial: input.partial,
      },
    };
  }

  async stats(): Promise<OrchestratorResult<OrchestratorStats>> {
    const byState: Record<string, number> = { idle: 0, bound: 0 };
    for (const slot of this.#slots.values()) {
      byState[slot.sessionGuid === null ? "idle" : "bound"] =
        (byState[slot.sessionGuid === null ? "idle" : "bound"] ?? 0) + 1;
    }
    // The same shape the real one sends, derived from this file's own slot model
    // rather than computed on demand from the caller's interest in it.
    //
    // It matters that the mock reports the field at all: `mock-runner.ts` came to
    // hide a missing erase step because it implemented the flow itself, and a mock
    // whose `stats` quietly omitted `boundSessions` would let the sweeper's orphan
    // branch go unexercised in exactly the place it is supposed to be exercised.
    // Sorted, to match the real response byte for byte.
    const boundSessions: Record<string, string> = {};
    for (const slot of this.#slots.values()) {
      if (slot.sessionGuid !== null) boundSessions[slot.slotId] = slot.sessionGuid;
    }
    return {
      ok: true,
      value: {
        size: this.#slots.size,
        byState,
        runnerTtlSeconds: 300,
        // The real orchestrator exposes these now, and the api seeds its pool from
        // them. Sorted so the fake matches the real response byte for byte.
        slotIds: this.slotIds().sort(),
        // **Omitted, not empty**, when nothing is bound — the real `Stats` carries
        // `omitempty`, and a fake that always sends the key would teach the api to
        // read an all-idle pool differently from a real one. Conditional spread
        // rather than `{ boundSessions }`, because `exactOptionalPropertyTypes`
        // treats an explicit undefined as a different value from an absent key.
        ...(Object.keys(boundSessions).length === 0 ? {} : { boundSessions }),
      },
    };
  }

  async healthz(): Promise<OrchestratorResult<{ ok: boolean; pool: OrchestratorStats }>> {
    const stats = await this.stats();
    return { ok: true, value: { ok: true, pool: stats.ok ? stats.value : { size: 0, byState: {}, runnerTtlSeconds: 0 } } };
  }

  /** now is exposed so the mock server's snapshot timings agree with this fake. */
  now(): number {
    return this.#now();
  }
}