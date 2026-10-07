/**
 * The reason a failed login reports.
 *
 * ## Why this file exists
 *
 * Found by running the assembled stack, not by reading it. A real login attempt
 * was driven through the whole chain — api container, network alias, runner,
 * Chromium — on a host with no egress, and the terminal event that came back was
 *
 *     login-failed {"reason":"unknown"}
 *
 * which the api maps to its **generic** failure message. The package had said
 * `network`, which maps to "we could not reach Microsoft". Those are different
 * things to tell a user, and the difference was destroyed between two components
 * that both had the information.
 *
 * The cause was in this package: `login()` resolves a boolean, so the return value
 * cannot say why, and the false branch published a literal `"unknown"` while
 * discarding the package's own terminal `login-result` event, which carries the
 * reason.
 *
 * ## Why this is a unit test and not a live login
 *
 * The first version of this file drove a real `login()` and polled for the event.
 * It takes 90 seconds, needs egress to Microsoft, and fails wherever the network is
 * restricted — so it would be slow and flaky in CI and pass or fail for reasons
 * that have nothing to do with the code.
 *
 * What is actually worth pinning is `reasonFromLoginResult`: a pure function over
 * one payload. It is tested exhaustively here, and the live observation that
 * prompted it is recorded above. A test that needs the internet to check a string
 * comparison is a test about the internet.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { reasonFromLoginResult } from "../src/index.js";
import { LOGIN_REASONS } from "@msout/microsoft-webauth";

describe("the reason a failed login reports", () => {
  it("passes through a reason the union contains", () => {
    // Every member, not a sample. The package may emit any of them for any of the
    // screens it reaches, and this process forwards whatever it is given.
    for (const reason of LOGIN_REASONS) {
      const got = reasonFromLoginResult({ ok: false, reason }, LOGIN_REASONS);
      expect(got, `${reason} must survive`).toBe(reason);
    }
  });

  it("returns null for a success, where reason is deliberately null", () => {
    // Every value in the union names something that went wrong, so there is no
    // member to use here. Returning one would force the api to branch on `ok`
    // *and* read the reason.
    expect(reasonFromLoginResult({ ok: true, reason: null }, LOGIN_REASONS)).toBeNull();
    expect(reasonFromLoginResult({ ok: true }, LOGIN_REASONS)).toBeNull();
  });

  it("refuses a reason outside the union rather than forwarding it", () => {
    // The load-bearing case. A JS error name, or a reason from a future package
    // version this runner has not seen, has no mapping in the api and would arrive
    // as the generic message — but would *look* like a specific one in a log.
    for (const bogus of [
      "TypeError",
      "ERR_MODULE_NOT_FOUND",
      "credentials_rejected ", // a trailing space is a different string
      "Credentials_Rejected", // case
      "",
      "network\0",
    ]) {
      expect(reasonFromLoginResult({ ok: false, reason: bogus }, LOGIN_REASONS), bogus).toBe(
        "unknown",
      );
    }
  });

  it("refuses a reason of the wrong type rather than coercing it", () => {
    for (const value of [undefined, null, 42, true, {}, ["network"]]) {
      expect(reasonFromLoginResult({ ok: false, reason: value }, LOGIN_REASONS)).toBe("unknown");
    }
  });

  it("treats anything other than ok:true as a failure", () => {
    // `ok` is checked for `true` and not for truthiness, so a malformed payload
    // cannot be read as a success. A success reported on a payload that did not
    // say so would skip the failure entirely.
    for (const ok of [undefined, null, "true", 1, {}, 0]) {
      expect(reasonFromLoginResult({ ok, reason: "network" }, LOGIN_REASONS)).toBe("network");
    }
  });

  it("every reason the runner can publish has a message in the api", () => {
    // The consumer, asserted from this side. `api/tests/login-failures.test.ts`
    // asserts the same property by value from the api's side; this is the backstop
    // at the seam, because the two components deploy independently and a runner
    // that learned a new reason would otherwise publish something the api renders
    // as a generic failure.
    const source = readFileSync(
      join(import.meta.dirname, "..", "..", "api", "src", "login-failures.ts"),
      "utf8",
    );
    for (const reason of LOGIN_REASONS) {
      expect(source, `no message for ${reason}`).toContain(reason);
    }
  });
});