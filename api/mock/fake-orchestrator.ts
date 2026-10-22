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
  /**
   * When the current container was created, in epoch ms. `null` when the slot has
   * no container — the fake's version of the real `Slot.CreatedAt` being zero until
   * the create finishes, and the reason `/stats` omits the age maps for such a slot.
   *
   * Null rather than 0 so "no container" cannot collide with a test whose clock
   * happens to be the epoch.
   */
  createdAtMs: number | null;
}

/**
 * The runner budget the fake reports, in seconds.
 *
 * One constant because `/stats` now answers `runnerTtlSeconds` and
 * `slotRemainingSec` from the same number, and a fake that reported 300 for one and
 * 600 for the other would hand a caller a self-contradicting pool.
 */
const RUNNER_TTL_SECONDS = 300;

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
      this.#slots.set(slotId, { slotId, containerId: "", sessionGuid: null, createdAtMs: null });
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

  /**
   * claim binds a slot to a session, and starts a container on it.
   *
   * `slotId` names the slot the caller already holds a SQLite claim on, and it is
   * **taken literally** — bound, or a 409, never silently substituted. That is the
   * real contract (`orchestrator/internal/server/server.go`, `handleClaim`: *"When the
   * request names a slot, that slot is taken or the claim conflicts. It is never
   * silently substituted"*), and it is the property `PoolBinder`'s mismatch branch
   * exists to survive an orchestrator that broke it.
   *
   * This fake modelled the *unnamed* contract only, because `claim` grew its third
   * argument after this file was written and the parameter was never added. A fake
   * that quietly picked a different slot could not reproduce the one thing it exists
   * to let a test see — and, worse, it handed back the session's **existing** slot
   * with its **existing** container whenever the api had just re-bound a session, so
   * a test could not tell a fresh container from a reused broken one. That is the
   * same lesson the api's own stub file records: a fixture that only works because the
   * code under test discards half of it is a second implementation of the wrong thing.
   *
   * Omitting `slotId` keeps the original behaviour: any free slot, idempotent for a
   * session that already holds one, which is what a caller retrying after a network
   * blip needs.
   */
  async claim(
    sessionGuid: string,
    _sessionExpiresAt: Date,
    slotId?: string,
  ): Promise<OrchestratorResult<{ slotId: string; containerId: string }>> {
    if (this.#claimDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.#claimDelayMs));
    }

    if (slotId !== undefined) {
      const named = this.#slots.get(slotId);
      if (named === undefined) {
        // Not "try another". An unknown slot is a disagreement about pool
        // membership, which `syncPool` exists to prevent, and `api` reads the 409
        // as `slot-conflict` rather than as exhaustion.
        return { ok: false, error: { kind: "conflict", status: 409 } };
      }
      if (named.sessionGuid === sessionGuid) {
        // A retry of a claim this session already holds. Answering with the slot it
        // has is what stops a retry after a network blip from leaking a second one.
        return { ok: true, value: { slotId: named.slotId, containerId: named.containerId } };
      }
      if (named.sessionGuid !== null) {
        // Held by somebody else. The real one refuses rather than displacing them,
        // so a fake that stole it would let a test exercise a path a deployment
        // cannot take.
        return { ok: false, error: { kind: "conflict", status: 409 } };
      }
      return this.#bind(named, sessionGuid);
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
    return this.#bind(free, sessionGuid);
  }

  /** #bind takes a slot that is known to be free and starts a container on it. */
  #bind(slot: FakeSlot, sessionGuid: string): OrchestratorResult<{
    slotId: string;
    containerId: string;
  }> {
    this.#seq++;
    slot.sessionGuid = sessionGuid;
    slot.containerId = `mock${String(this.#seq).padStart(6, "0")}`;
    slot.createdAtMs = this.#now();
    return { ok: true, value: { slotId: slot.slotId, containerId: slot.containerId } };
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
    // No container, no age — so `/stats` stops reporting one for this slot, exactly
    // as the real pool does for a slot whose `CreatedAt` was reset on release.
    slot.createdAtMs = null;
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
    // A replacement is a new container, so the age restarts from zero. A fake that
    // kept the old `createdAtMs` would report a recycled slot as about to expire and
    // teach a caller to distrust the field it is supposed to be testing.
    slot.createdAtMs = this.#now();
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

  /**
   * deleteArtifact removes a published artifact directory.
   *
   * The map is the fake's stand-in for the artifact volume, so an erase that
   * publishes and then erases leaves the fake reporting `exists: false` for the id
   * — the same observable the api would get back from the real `/stat` after a
   * real `/delete-artifact`.
   *
   * Idempotent, like the real one: an unknown id is `{ deleted: true }`, because
   * "already gone" is the outcome the caller wanted.
   */
  async deleteArtifact(artifactId: string): Promise<OrchestratorResult<{ deleted: boolean }>> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(artifactId)) {
      return { ok: false, error: { kind: "unexpected", status: 400, body: "invalid artifact id" } };
    }
    this.#finalised.delete(artifactId);
    return { ok: true, value: { deleted: true } };
  }

  async stats(): Promise<OrchestratorResult<OrchestratorStats>> {
    // **Counted the way `Stats()` counts.** Only a state that holds at least one slot
    // gets a key, so an all-idle pool answers `{"idle": n}` and carries **no `bound`
    // key** — which is what the real orchestrator sends, read off the deployed host:
    // `{"size":2,"byState":{"idle":2},…}`. This used to seed `{ idle: 0, bound: 0 }`
    // and always emit `bound: 0`, a response no `Stats()` has ever produced. That is
    // worse than a missing field: the api's strand repair reads `byState` when
    // `boundSessions` is absent, and a fake that always sent `bound` made the new
    // path's *input* unreachable in the one place it is supposed to be exercised —
    // while teaching the api a shape the wire does not carry. A mock that disagrees
    // with production is a mock that keeps passing when production is wrong.
    //
    // **Still an approximation, and knowingly so.** This file's slot model has no state
    // machine, so there is no `starting`, `draining` or `dead` here at all; modelling
    // those is a mock-fidelity project, not this fix. Nor is this mock covered by CI —
    // it is a dev harness (`npm run mock`) — which is why the both-ends pins live in
    // `api/tests/orchestrator-client.test.ts` and in `orchestrator/internal/pool`'s
    // `TestStatsByStateKeysAreKnownStateNames` instead of here.
    const byState: Record<string, number> = {};
    for (const slot of this.#slots.values()) {
      // The real `Release` leaves its slot **vacant** — no container, one wanted — and
      // so does a slot `EnsurePool` has registered and not created into yet.
      // `createdAtMs === null` is exactly the container-less case this file models, so
      // it is what tells the two apart from an `idle` container nobody is bound to. The
      // mock has no `fail`, so it cannot produce that one — see the note above. Neither
      // word is `bound`, so this changes no answer the api derives; it is fidelity, and
      // it is what makes a `/stats` body from the dev harness readable as a real one.
      const state =
        slot.createdAtMs === null ? "vacant" : slot.sessionGuid === null ? "idle" : "bound";
      byState[state] = (byState[state] ?? 0) + 1;
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
    // Per-slot age and remaining budget, read off this file's own slot model for the
    // same reason `boundSessions` is: a mock that quietly omitted the field would let
    // a caller's floor check go unexercised in exactly the place it is supposed to be
    // exercised — and would go unexercised *silently*, because every other test would
    // still pass with the field simply absent.
    //
    // A slot with no container is absent from both maps, matching the real `Stats`,
    // which skips a zero `CreatedAt` and carries `omitempty` on both. The arithmetic
    // is the real one: `remaining = max(0, budget - age)`.
    const slotAgeSec: Record<string, number> = {};
    const slotRemainingSec: Record<string, number> = {};
    const nowSec = Math.floor(this.#now() / 1000);
    for (const slot of this.#slots.values()) {
      if (slot.createdAtMs === null) continue;
      const ageSec = Math.max(0, nowSec - Math.floor(slot.createdAtMs / 1000));
      slotAgeSec[slot.slotId] = ageSec;
      slotRemainingSec[slot.slotId] = Math.max(0, RUNNER_TTL_SECONDS - ageSec);
    }
    // The slots the orchestrator would accept for a claim are exactly the idle ones.
    // The real orchestrator uses `Slot.IsIdle()`, which returns true only for
    // `StateIdle`. This mock reports `idle` for slots that have no container but
    // have a timestamp, and `vacant` for slots that have neither (see the comment
    // above where `byState` is built). So the claimable set is exactly the slots
    // with state `idle` in our model.
    const claimableSlotIds: string[] = [];
    for (const slot of this.#slots.values()) {
      // The same logic the real `Stats` uses: a slot with `createdAtMs === null`
      // is vacant (no container), otherwise if `sessionGuid === null` it's idle.
      // Only idle slots are claimable.
      if (slot.createdAtMs !== null && slot.sessionGuid === null) {
        claimableSlotIds.push(slot.slotId);
      }
    }
    // Sort to match the real response byte for byte.
    claimableSlotIds.sort();

    return {
      ok: true,
      value: {
        size: this.#slots.size,
        byState,
        runnerTtlSeconds: RUNNER_TTL_SECONDS,
        // The real orchestrator exposes these now, and the api seeds its pool from
        // them. Sorted so the fake matches the real response byte for byte.
        slotIds: this.slotIds().sort(),
        // The claimable set is exactly the idle slots, as the real orchestrator
        // publishes (see pool.go:428-434). Sorted like `slotIds` above.
        // **Omitted, not empty**, when nothing is claimable — same rule as `slotIds`:
        // `omitempty` drops an absent key, and a fake that always sends the key would
        // teach the api to read an all-idle pool differently from a real one.
        ...(claimableSlotIds.length === 0 ? {} : { claimableSlotIds }),
        // **Omitted, not empty**, when nothing is bound — the real `Stats` carries
        // `omitempty`, and a fake that always sends the key would teach the api to
        // read an all-idle pool differently from a real one. Conditional spread
        // rather than `{ boundSessions }`, because `exactOptionalPropertyTypes`
        // treats an explicit undefined as a different value from an absent key.
        ...(Object.keys(boundSessions).length === 0 ? {} : { boundSessions }),
        // Same rule, same reason, and it is what makes a fresh pool — where no slot
        // has a container yet — report neither key.
        ...(Object.keys(slotAgeSec).length === 0
          ? {}
          : { slotAgeSec, slotRemainingSec }),
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

  async deleteSessionDir(_sessionGuid: string): Promise<OrchestratorResult<{ deleted: boolean }>> {
    // The vault directory is not modelled in the fake — it's a real filesystem
    // concept, and this mock's job is to stand in for the orchestrator's API
    // without actually touching the filesystem. So this always returns success.
    // An erase that calls this will record the step as done.
    return { ok: true, value: { deleted: true } };
  }
}
