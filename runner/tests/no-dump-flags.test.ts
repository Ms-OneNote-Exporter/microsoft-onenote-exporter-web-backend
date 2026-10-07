/**
 * No code path in the runner can pass a dump or screenshot flag to a package.
 *
 * ## Why this file exists separately from `debug-surface.test.ts`
 *
 * That file holds the *route table* closed: no endpoint offers a debug flag, and
 * no configuration field exists to carry one. Those are the two halves that can
 * be enumerated.
 *
 * This one holds the third, which cannot: **the call sites**. `dodump` and
 * `screenshot` are properties on the `options` object of all three packages, so
 * any line that spreads a caller's options into a package call could pass them
 * through. A route table cannot catch that — the route takes no flag, and the flag
 * arrives by another road.
 *
 * The attack shape is mundane and therefore worth closing: someone adding a
 * `?debug=1` "for local testing" would most likely do it by spreading a body
 * object into the package options. This asserts that no such spread exists.
 *
 * ## How it is checked
 *
 * Against the source text, which is unusual and deliberate. There is no way to
 * observe "this flag was not passed" from outside the process — a spy on the
 * package would prove what a test made it do, which is the §1 pattern in reverse.
 * The property is a negative about code shape, so the code is read.
 *
 * The checks are narrow on purpose: `--dodump` and `--screenshot` as package
 * *options*, not the words "dump" or "debug" anywhere. A comment explaining why
 * the flag is forbidden contains the word; that must not fail the test.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SRC = join(import.meta.dirname, "..", "src");

/** Every source file, so a new file is checked without editing a list. */
const sourceFiles = (): string[] => {
  const { readdirSync } = require("node:fs") as typeof import("node:fs");
  return readdirSync(SRC)
    .filter((name) => name.endsWith(".ts") && !name.endsWith(".d.ts"))
    .map((name) => join(SRC, name));
};

/** Source with comments and docblocks removed, so prose cannot fail a check. */
function code(file: string): string {
  return readFileSync(file, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
}

describe("no package call can be given a debug flag", () => {
  it("finds no source file that passes dodump or screenshot", () => {
    const offenders: string[] = [];
    for (const file of sourceFiles()) {
      const body = code(file);
      for (const flag of ["dodump", "screenshot"]) {
        // `dodump:` or `dodump =` — i.e. as a property, not in prose.
        const pattern = new RegExp(`(^|[^\\w.])${flag}\\s*[:=]`, "i");
        if (pattern.test(body)) offenders.push(`${file}: ${flag}`);
      }
    }
    expect(offenders, `debug flags must never be set: ${offenders.join(", ")}`).toEqual([]);
  });

  it("spreads no caller-supplied options object into a package call", () => {
    // The specific shape this closes: `runExport({ ...body })`, which would carry
    // any flag a caller put in the body straight into the package options.
    //
    // Matched across the *call site* rather than inside one pair of braces,
    // because the spread in this file is the last property in the object — a
    // `[^}]*` between the paren and the `...` cannot see it, so the check as
    // first written silently inspected nothing and passed. Verified by reading
    // the offender it does report, which is a real one.
    const offenders: string[] = [];
    for (const file of sourceFiles()) {
      const body = code(file);
      const calls = body.matchAll(/\b(runExport|login|listNotebooks|verifyAuth)\s*\(\{/g);
      for (const call of calls) {
        // From the opening brace to the matching close, counting nesting, so a
        // spread nested inside a sub-object is found too.
        let depth = 0;
        for (let i = call.index! + call[0].length - 1; i < body.length; i += 1) {
          const ch = body[i];
          if (ch === "{") depth += 1;
          else if (ch === "}") {
            depth -= 1;
            if (depth === 0) {
              const args = body.slice(call.index! + call[0].length, i);
              if (/\.\.\.[\w.]/.test(args)) offenders.push(`${file}: ${call[1]}({ ... })`);
              break;
            }
          }
        }
      }
    }
    expect(
      offenders,
      `a caller-supplied spread reaches a package call: ${offenders.join(", ")}`,
    ).toEqual([]);
  });

  it("names each package's options field by field, never positionally", () => {
    // Belt and braces on the spread check: every package call must pass named
    // fields, so there is no argument list for a flag to slide into.
    const offenders: string[] = [];
    for (const file of sourceFiles()) {
      const body = code(file);
      const calls = body.match(/\b(?:runExport|login|listNotebooks|verifyAuth)\s*\(/g) ?? [];
      if (calls.length === 0) continue;
      // Positional arguments would appear as `('something'` or `("something"`.
      if (/\b(?:runExport|login|listNotebooks|verifyAuth)\s*\(\s*['"`]/.test(body)) {
        offenders.push(file);
      }
    }
    expect(offenders, `positional package arguments in: ${offenders.join(", ")}`).toEqual([]);
  });

  it("sets no environment variable a package would read as configuration", () => {
    // Allowlist rather than denylist, because the risk is a variable nobody has
    // thought about yet.
    //
    // Scoped to *child* environment construction. The runner reads plenty of
    // SCREAMING_CASE variables of its own — `MSOUT_DATA_ROOT`, the timeouts, the
    // quota — and matching `[A-Z_]+:` across the file finds those too, as it did
    // when this check was first written: it reported `LOGIN_REASONS` three times,
    // which is a destructured import and not an environment variable at all.
    //
    // So the pattern is anchored on an `env:` object, which is the only way a
    // child process is configured in this codebase.
    const allowed = ["ONENOTE_EXPORT_LOG_DIR", "ONENOTE_EXPORT_LOG_LEVEL", "NO_COLOR", "FORCE_COLOR"];
    const offenders: string[] = [];
    for (const file of sourceFiles()) {
      const body = code(file);
      for (const envBlock of body.matchAll(/\benv\s*:\s*\{([\s\S]*?)\n\s*\}/g)) {
        for (const match of envBlock[1]!.matchAll(/\b([A-Z][A-Z0-9_]{3,})\s*:/g)) {
          const name = match[1]!;
          if (!allowed.includes(name)) offenders.push(`${file}: env.${name}`);
        }
      }
    }
    expect(offenders, `unexpected child environment variables: ${offenders.join(", ")}`).toEqual([]);
  });

  it("never names a dump flag in a spawned command line", () => {
    // The predecessor passed `--password` on argv. If anything is ever spawned
    // again, this asserts it is not spawned with a debug flag either.
    const offenders: string[] = [];
    for (const file of sourceFiles()) {
      const body = code(file);
      if (/\bspawn\s*\(/.test(body) && /--dodump|--screenshot/.test(body)) {
        offenders.push(file);
      }
      if (/args\s*:\s*\[[^\]]*--(?:dodump|screenshot)/.test(body)) {
        offenders.push(file);
      }
    }
    expect(offenders, `a debug flag reaches argv in: ${offenders.join(", ")}`).toEqual([]);
  });

  it("does not put the credential on a command line", () => {
    // The defect this whole design exists to avoid. Asserted against the code
    // because the absence of an argv leak is not observable from outside — and
    // because it shipped once, in the runner's own predecessor.
    const offenders: string[] = [];
    for (const file of sourceFiles()) {
      const body = code(file);
      if (/--(?:password|passwd)\b/.test(body)) offenders.push(file);
      if (/args\s*:\s*\[[^\]]*password/i.test(body)) offenders.push(file);
    }
    expect(
      offenders,
      `the password must never be passed as an argument: ${offenders.join(", ")}`,
    ).toEqual([]);
  });
});
