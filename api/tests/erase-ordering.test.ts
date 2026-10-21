/**
 * The registry that orders an erase's cookie expiry against a create that
 * presents the erasing session's cookie.
 *
 * The race it closes is in `api/src/erase-ordering.ts`'s header, measured on
 * the deployed host: a create that answers while an erase is still running has
 * its cookie expired by the erase's response, and the new session becomes
 * unreachable.
 *
 * These cases are the module's own contract: what `register` promises, what
 * `settle` waits for, and what it does **not** wait for. The route-level
 * behaviour is in `routes.test.ts`.
 */
import { describe, expect, it, vi } from "vitest";

import {
  createEraseOrdering,
  MAX_ERASE_ORDERING_WAIT_MS,
} from "../src/erase-ordering.js";

const GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const OTHER = "4f2504e0-4f89-11d3-9a0c-0305e82c3301";

describe("createEraseOrdering", () => {
  /**
   * B1: a create that presents the erasing session's cookie is **held** until
   * the erase's response has been flushed.
   */
  it("holds a create that presents the erasing session's cookie until the release", async () => {
    const ordering = createEraseOrdering();
    const release = ordering.register(GUID);

    let settled = false;
    const waiting = ordering.settle(GUID).then(() => {
      settled = true;
    });

    // Let the microtask queue turn: the settle must still be waiting.
    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);

    // The erase's response is flushed.
    release();
    await waiting;
    expect(settled).toBe(true);
  });

  /**
   * B2: a create that presents **no** cookie is not held.
   */
  it("does not hold a create for a session that is not being erased", async () => {
    const ordering = createEraseOrdering();

    let settled = false;
    await ordering.settle(OTHER).then(() => {
      settled = true;
    });

    expect(settled).toBe(true);
  });

  /**
   * B3: a create that presents the cookie of a session that is **not** being
   * erased is not held — the registry is scoped to the guid.
   */
  it("holds only the session that is being erased", async () => {
    const ordering = createEraseOrdering();
    const release = ordering.register(GUID);

    let otherSettled = false;
    await ordering.settle(OTHER).then(() => {
      otherSettled = true;
    });
    expect(otherSettled).toBe(true);

    // And the erased one is still held.
    let settled = false;
    const waiting = ordering.settle(GUID).then(() => {
      settled = true;
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);

    release();
    await waiting;
  });

  /**
   * B4: the wait is **bounded** — an erase that never finishes cannot hang a
   * create.
   */
  it("releases a create when the bound is reached", async () => {
    vi.useFakeTimers();
    try {
      const warnings: string[] = [];
      const ordering = createEraseOrdering({
        log: (message) => warnings.push(message),
      });
      // Registered and never released: the erase is stuck.
      ordering.register(GUID);

      let settled = false;
      const waiting = ordering.settle(GUID).then(() => {
        settled = true;
      });

      await vi.advanceTimersByTimeAsync(MAX_ERASE_ORDERING_WAIT_MS);
      await waiting;

      expect(settled).toBe(true);
      // And it says so, so an operator can see a stuck erase.
      expect(warnings.join(" ")).toMatch(/stuck/i);
    } finally {
      vi.useRealTimers();
    }
  });

  /**
   * The restart-safe half: the registry is per-process, so a row left in
   * `erasing` is the only evidence of an erase that this process did not start.
   */
  it("waits for a session that is still being erased, even with no entry of its own", async () => {
    let erasing = true;
    const ordering = createEraseOrdering({
      isErasing: () => erasing,
    });

    let settled = false;
    const waiting = ordering.settle(GUID).then(() => {
      settled = true;
    });

    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);

    // The erase finished: the row is gone.
    erasing = false;
    await waiting;
    expect(settled).toBe(true);
  });

  it("does not wait for a session that is not being erased, with no entry of its own", async () => {
    const ordering = createEraseOrdering({ isErasing: () => false });
    let settled = false;
    await ordering.settle(GUID).then(() => {
      settled = true;
    });
    expect(settled).toBe(true);
  });

  it("releasing twice does nothing, and a second erase of the same guid is its own entry", async () => {
    const ordering = createEraseOrdering();
    const first = ordering.register(GUID);
    const second = ordering.register(GUID);

    // The first release must not release the second erase's entry.
    first();

    let settled = false;
    const waiting = ordering.settle(GUID).then(() => {
      settled = true;
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);

    second();
    await waiting;
    expect(settled).toBe(true);

    // And releasing again is harmless.
    second();
  });
});
