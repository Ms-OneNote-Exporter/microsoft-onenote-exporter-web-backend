/**
 * Exercises the duplicate-key scanner against four workflow shapes.
 *
 * ## Why this file exists
 *
 * The scanner passed a workflow containing **two `run:` keys on one step**, and
 * GitHub rejected the file outright. That was the same signature as the incident the
 * scanner was written for — a run reporting failure with zero jobs — and the
 * scanner was the check meant to prevent exactly it.
 *
 * A check that has only ever been run against the real files cannot be trusted to
 * fail, because nothing has ever asked it to. Four fixtures, two of which must be
 * flagged and two of which must not, and the "must not" pair matters as much as the
 * other: a scanner that flags every `run:` in every workflow is a scanner that gets
 * deleted.
 *
 *   duplicated `run:` on one step   -> must be flagged (the real bug)
 *   duplicated `IMAGE_TAG:`         -> must be flagged (the original incident)
 *   two steps, one `run:` each      -> must be clean (every workflow looks like this)
 *   a shell body containing `key:`  -> must be clean (block bodies are not mappings)
 */

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "no-duplicate-keys.mjs");

/** Runs the scanner over one workflow's text; returns true when it flagged it. */
function flags(source) {
  const dir = mkdtempSync(join(tmpdir(), "dupkeys-"));
  try {
    // The scanner reads `workflows/` **next to itself**, not in the cwd — so the
    // script has to be copied in beside the fixture. Running it from its real
    // location with only the cwd changed scans the real repository's workflows and
    // reports on those instead, which is a test that passes for the wrong reason.
    //
    // That is not hypothetical: the first version of this file did exactly it, and
    // every "must be flagged" case came back clean.
    mkdirSync(join(dir, "workflows"));
    copyFileSync(SCRIPT, join(dir, "no-duplicate-keys.mjs"));
    writeFileSync(join(dir, "workflows", "w.yml"), source);
    try {
      execFileSync("node", [join(dir, "no-duplicate-keys.mjs")], { stdio: "pipe" });
      return false;
    } catch {
      return true;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const HEADER = "name: t\non:\n  push:\njobs:\n  j:\n    runs-on: ubuntu-latest\n";

/** @type {{name: string, source: string, expect: boolean}[]} */
const cases = [
  {
    name: "two `run:` keys on one step",
    // The bug. A step may have `run` **or** `uses`, never both, and a second `run:`
    // after a comment is invisible to a parser that keeps the last value.
    source: `${HEADER}    steps:\n      - name: a step\n        run: |\n          echo first\n        # a comment between them\n        run: |\n          echo second\n`,
    expect: true,
  },
  {
    name: "two `run:` keys with no comment between them",
    source: `${HEADER}    steps:\n      - name: a step\n        run: |\n          echo first\n        run: |\n          echo second\n`,
    expect: true,
  },
  {
    name: "the original incident: `IMAGE_TAG` twice in `env`",
    source: `${HEADER}    env:\n      IMAGE_TAG: a\n      IMAGE_TAG: b\n    steps:\n      - run: echo ok\n`,
    expect: true,
  },
  {
    name: "a duplicated `if` on one step",
    source: `${HEADER}    steps:\n      - run: echo a\n        if: success()\n        if: failure()\n`,
    expect: true,
  },
  {
    name: "two steps, each with one `run:`",
    source: `${HEADER}    steps:\n      - name: one\n        run: |\n          echo a\n      - name: two\n        run: |\n          echo b\n`,
    expect: false,
  },
  {
    name: "a shell body containing a line that looks like a mapping key",
    // The false positive the block-scalar handling exists to avoid, and the reason
    // that handling existed at all.
    source: `${HEADER}    steps:\n      - name: shell\n        run: |\n          if [ -n "$x" ]; then\n            run: something\n            env:\n          fi\n`,
    expect: false,
  },
  {
    name: "a step with both `uses` and `name`",
    source: `${HEADER}    steps:\n      - uses: actions/checkout@v4\n        name: checkout\n      - uses: actions/setup-node@v4\n        name: node\n`,
    expect: false,
  },
];

let failures = 0;
for (const testCase of cases) {
  const got = flags(testCase.source);
  if (got === testCase.expect) {
    console.log(`  ok    ${testCase.name} (${got ? "flagged" : "clean"})`);
  } else {
    failures += 1;
    console.error(
      `  FAIL  ${testCase.name}: expected ${testCase.expect ? "flagged" : "clean"}, got ${got ? "flagged" : "clean"}`,
    );
  }
}

if (failures > 0) {
  console.error(`\n${failures} of ${cases.length} cases failed.`);
  process.exit(1);
}
console.log(`\n${cases.length} cases, all as expected.`);