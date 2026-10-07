#!/usr/bin/env node
/**
 * Rejects duplicate keys in the workflow files.
 *
 * ## Why this exists
 *
 * A duplicate key inside a YAML mapping is a **syntax error for GitHub Actions
 * and invisible to a YAML parser**. PyYAML, `yq`, and every other reader used
 * here keep the *last* value and say nothing, so a duplicated `IMAGE_TAG:` sat in
 * `ci.yml` from PR #21 and was invisible to every local check.
 *
 * The visible effect was not subtle either, once you knew to look for it: the
 * whole workflow stopped being scheduled. Every `ci` run on `main` reported
 * `failure` with **zero jobs** and a duration of 0s — which reads, if you do not
 * know the signature, like an infrastructure outage rather than a file GitHub
 * refused to parse. `capability` kept passing throughout, because it is a
 * different file.
 *
 * So: the check that would have caught it is this one, and it runs in CI on the
 * same commit as the workflows.
 *
 * ## The bug it missed, and why
 *
 * On 2026-10-07 this script passed a workflow containing **two `run:` keys on one
 * step**, and GitHub rejected the file outright — a run that reported failure with
 * zero jobs, the exact signature of the `IMAGE_TAG` incident above.
 *
 * The cause is in the block-scalar handling. `run: |` opens a shell script, and the
 * scanner cleared its map of seen keys when it saw one, so that lines inside a shell
 * body would not be mistaken for mapping keys. The intent was right. The mistake
 * was clearing on the *opening* line: that threw away the key that had just been
 * recorded, so any pair of block scalars on the same step was invisible.
 *
 * `IMAGE_TAG` was caught only because it was a plain scalar. Every `run:` in every
 * workflow — which is nearly all of them — was unchecked.
 *
 * The fix records a block scalar as the key it is and keeps the recorded keys across
 * its body. `tests/` in this directory exercises four shapes: a duplicated `run:`
 * (caught), the historical `IMAGE_TAG` (caught), two steps each with one `run:`
 * (clean), and a shell body containing a line that looks like a key (clean).
 *
 * ## Why a text scanner and not a parser
 *
 * Because the parse is what loses the information. Reading the file with a YAML
 * library gives one value per key and no way to learn there were two, which is
 * the whole question. So the source is scanned as text.
 *
 * That is only safe if the scanner understands the two things in a workflow file
 * that are not YAML mappings:
 *
 *   - **block scalars.** Everything under `run: |` is a shell script, and a shell
 *     script legitimately contains `FOO: bar` twice. Those lines are skipped, and
 *     the scanner tracks the `run:` line's indentation to know where the block
 *     ends.
 *   - **sibling scope.** Only *consecutive* keys at the same indentation are
 *     siblings. A key repeated in a different mapping is not a duplicate, so the
 *     key set resets whenever the indentation changes in either direction. An
 *     earlier version of this file only reset on a *decrease*, which meant it
 *     skipped the very lines it was looking for — the keys under `env:` are
 *     indented deeper than `env:` itself — and passed on a file that still had
 *     the defect.
 */

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKFLOWS = join(HERE, "workflows");

/** `key: value`, or `key:` with the value on a following line. */
const KEY_LINE = /^(\s*)(-\s+)?([^\s#:][^:]*?)\s*:(?:\s+(.*))?$/;

/** A block scalar: `run: |`, `run: >-`, `run: |2`. */
const BLOCK_SCALAR = /^(\s*)(-\s+)?([^:#]*?):\s*[|>][-+0-9]*\s*(?:#.*)?$/;

/**
 * @param {string} source
 * @returns {Array<{key: string, first: number, second: number, block: number}>}
 */
function duplicateKeysInText(source) {
  const problems = [];
  const lines = source.split("\n");

  /** Indent of the `run: |` line whose body we are inside, or null. */
  let blockScalarIndent = null;
  /** Indentation of the previous sibling key we recorded. */
  let keyIndent = null;
  let blockStart = 0;
  /** @type {Map<string, number>} */
  let seen = new Map();

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const raw = lines[i].replace(/\s+$/, "");

    if (blockScalarIndent !== null) {
      // Inside a shell script. It ends at the first non-blank line indented no
      // further than the `run:` that opened it.
      if (raw.trim() === "") continue;
      const indent = raw.length - raw.trimStart().length;
      if (indent > blockScalarIndent) continue;
      blockScalarIndent = null;
    }

    if (raw.trim() === "" || raw.trim().startsWith("#")) continue;

    const scalar = BLOCK_SCALAR.exec(raw);
    if (scalar !== null) {
      // A block scalar is **still a mapping key**. It has to be recorded, and the
      // recorded keys have to survive the block — otherwise two `run:` keys on one
      // step are never compared, which is precisely the bug this script exists to
      // catch and precisely what it missed in `capability.yml` on 2026-10-07.
      //
      // The earlier version cleared `seen` here. The intent was right — a shell
      // body contains lines that look like mapping keys — but clearing on the
      // opening line threw away the key that had just been seen, so every pair of
      // block scalars was invisible to it. `IMAGE_TAG` in `ci.yml` was caught only
      // because it was a plain scalar.
      const scalarIndent = scalar[1].length;
      if (scalar[2] !== undefined) {
        // `- run: |` — a sequence item, so a fresh scope, as below.
        keyIndent = null;
        seen = new Map();
        blockStart = lineNo;
      } else if (keyIndent !== scalarIndent) {
        keyIndent = scalarIndent;
        blockStart = lineNo;
        seen = new Map();
      }
      const scalarKey = scalar[3].trim();
      if (scalarKey !== "" && !scalarKey.startsWith("<<") && !scalarKey.startsWith("? ")) {
        if (seen.has(scalarKey)) {
          problems.push({ key: scalarKey, first: seen.get(scalarKey), second: lineNo, block: blockStart });
        } else {
          seen.set(scalarKey, lineNo);
        }
      }
      // Everything indented further than this line is the scalar's body, and is
      // skipped rather than parsed.
      blockScalarIndent = scalarIndent;
      continue;
    }

    const match = KEY_LINE.exec(raw);
    if (match === null) {
      // Not a mapping line. It does not change scope on its own — a continuation
      // of a multi-line flow scalar, most often.
      continue;
    }

    const indent = match[1].length;

    // A `- ` prefix makes this a **sequence item**, not a mapping key. Two steps
    // in a list both saying `- uses: actions/…` is the normal shape of a workflow,
    // not a duplicate — so the item starts a fresh scope and its own keys are
    // scanned at the deeper indentation that follows.
    if (match[2] !== undefined) {
      keyIndent = null;
      seen = new Map();
      blockStart = lineNo;
      continue;
    }

    if (keyIndent !== indent) {
      keyIndent = indent;
      blockStart = lineNo;
      seen = new Map();
    }

    const key = match[3].trim();
    if (key.startsWith("<<") || key.startsWith("? ")) continue;

    if (seen.has(key)) {
      problems.push({ key, first: seen.get(key), second: lineNo, block: blockStart });
    } else {
      seen.set(key, lineNo);
    }
  }

  return problems;
}

let failures = 0;
for (const name of readdirSync(WORKFLOWS).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))) {
  const problems = duplicateKeysInText(readFileSync(join(WORKFLOWS, name), "utf8"));
  if (problems.length === 0) {
    console.log(`  ok    ${name}: no duplicate keys`);
    continue;
  }
  failures += 1;
  console.log(`  FAIL  ${name}: ${problems.length} duplicate key(s)`);
  for (const p of problems) {
    console.log(
      `        "${p.key}" at line ${p.second}, first seen at line ${p.first} ` +
        `(sibling block starting at line ${p.block})`,
    );
  }
}

if (failures > 0) {
  console.error(
    `\n${failures} workflow file(s) contain duplicate keys. GitHub Actions rejects these ` +
      "outright: the workflow never runs, and every check in it silently stops " +
      "happening. A YAML parser will not tell you, because it keeps the last value.",
  );
  process.exit(1);
}

console.log("no duplicate keys in any workflow");
