#!/usr/bin/env node
/**
 * Tests the assertion script by trying to fool it.
 *
 * `assert-compose.mjs` is a static check over `docker compose config`. A static
 * check that cannot fail is worse than none, because it reads as coverage. This
 * takes the real resolved config, applies one violation at a time, and requires
 * the script to exit non-zero for each.
 *
 *   node .github/assert-compose.test.mjs
 *
 * This file is why the socket check matches a mount's **source** rather than its
 * target: the first version stringified the volume list and looked for
 * "docker.sock", which matched the target, so repointing the source at an
 * unrelated path passed. The "repoints the socket source" case below caught that,
 * and it is kept because the failure it found is invisible by inspection.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const SCRIPT = ".github/assert-compose.mjs";

/** Runs the assertion script against a config object; returns its exit code. */
function run(cfg) {
  try {
    execFileSync("node", [SCRIPT], {
      input: JSON.stringify(cfg),
      stdio: ["pipe", "pipe", "pipe"],
    });
    return 0;
  } catch (error) {
    return error.status ?? 1;
  }
}

/** A deep clone, so each case starts from the real config untouched. */
const clone = (cfg) => structuredClone(cfg);

const base = JSON.parse(
  execFileSync("docker", ["compose", "config", "--format", "json"], {
    encoding: "utf8",
    env: {
      ...process.env,
      COMPOSE_PROJECT_NAME: "msout",
      PUBLIC_HOST: "one-backend.phttp.com",
      ACME_EMAIL: "ops@example.com",
      ALLOWED_ORIGINS: "https://app.example.com",
    },
  }),
);

// ---- the happy path --------------------------------------------------------

if (run(clone(base)) !== 0) {
  console.error("the real config does not pass the assertions — fix that first");
  process.exit(1);
}
console.log("ok    the real compose config passes every assertion");

/** @type {{name: string, mutate: (cfg: any) => void, expectMessage: RegExp}[]} */
const cases = [
  {
    name: "msout-control is not internal",
    mutate: (c) => {
      c.networks["msout-control"].internal = false;
    },
    expectMessage: /internal: true/,
  },
  {
    // The one that matters most, and the one a naive check gets wrong: the mount
    // still *targets* /var/run/docker.sock, so anything matching on the target or
    // on the serialized volume passes.
    name: "repoints the socket source",
    mutate: (c) => {
      for (const v of c.services.orchestrator.volumes) {
        if (String(v.source).endsWith("docker.sock")) v.source = "/tmp/attacker.sock";
      }
    },
    expectMessage: /orchestrator has 0 docker socket/,
  },
  {
    name: "gives the api the docker socket",
    mutate: (c) => {
      c.services.api.volumes.push({
        type: "bind",
        source: "/var/run/docker.sock",
        target: "/var/run/docker.sock",
        bind: {},
      });
    },
    expectMessage: /api mounts a docker socket/,
  },
  {
    name: "gives the api any bind mount at all",
    mutate: (c) => {
      c.services.api.volumes.push({ type: "bind", source: "/", target: "/host", bind: {} });
    },
    expectMessage: /api bind-mounts/,
  },
  {
    name: "publishes the api's port",
    mutate: (c) => {
      c.services.api.ports = [{ target: 3000, published: "3000", protocol: "tcp" }];
    },
    expectMessage: /api publishes 1 port/,
  },
  {
    name: "publishes the orchestrator's port",
    mutate: (c) => {
      c.services.orchestrator.ports = [{ target: 9100, published: "9100", protocol: "tcp" }];
    },
    expectMessage: /orchestrator publishes 1 port/,
  },
  {
    name: "puts the api on the edge network",
    mutate: (c) => {
      c.services.api.networks["msout-edge"] = null;
    },
    expectMessage: /msout-edge holds \[api,caddy\]/,
  },
  {
    name: "hands the orchestrator the CSRF key",
    mutate: (c) => {
      c.services.orchestrator.environment.CSRF_KEY = "leaked";
    },
    expectMessage: /orchestrator environment carries CSRF_KEY/,
  },
  {
    name: "hands the orchestrator the public origin",
    mutate: (c) => {
      c.services.orchestrator.environment.PUBLIC_ORIGIN = "https://one-backend.phttp.com";
    },
    expectMessage: /orchestrator environment carries PUBLIC_ORIGIN/,
  },
  {
    name: "assigns a secret inline instead of by path",
    mutate: (c) => {
      c.services.api.environment.CSRF_KEY = "hunter2";
    },
    expectMessage: /CSRF_KEY is assigned inline/,
  },
  {
    name: "points a secret file outside /run/secrets",
    mutate: (c) => {
      c.services.api.environment.CSRF_KEY_FILE = "/etc/passwd";
    },
    expectMessage: /not a \/run\/secrets path/,
  },
  {
    name: "stops dropping all capabilities on the api",
    mutate: (c) => {
      delete c.services.api.cap_drop;
    },
    expectMessage: /api does not cap_drop ALL/,
  },
  {
    name: "grants the api a new capability",
    mutate: (c) => {
      c.services.api.cap_add = ["SYS_ADMIN"];
    },
    expectMessage: /api adds capabilities it has no use for: SYS_ADMIN/,
  },
  {
    name: "gives caddy an extra capability beyond binding",
    mutate: (c) => {
      c.services.caddy.cap_add = ["NET_BIND_SERVICE", "SYS_PTRACE"];
    },
    expectMessage: /caddy adds unexpected capabilities/,
  },
  {
    name: "gives caddy a host mount beyond its config",
    mutate: (c) => {
      c.services.caddy.volumes.push({
        type: "bind",
        source: "/srv",
        target: "/srv",
        bind: {},
      });
    },
    expectMessage: /caddy bind-mounts something unexpected/,
  },
];

// ---- each violation must be caught ----------------------------------------

let missed = 0;

for (const testCase of cases) {
  const cfg = clone(base);
  testCase.mutate(cfg);

  if (run(cfg) === 0) {
    console.error(`FAIL  not caught: ${testCase.name}`);
    missed++;
    continue;
  }

  // Not just "it failed" — it failed for the right reason. A check that exits
  // non-zero for an unrelated reason is no better than one that passes.
  let output = "";
  try {
    execFileSync("node", [SCRIPT], { input: JSON.stringify(cfg), stdio: ["pipe", "pipe", "pipe"] });
  } catch (error) {
    output = String(error.stderr ?? "");
  }
  if (!testCase.expectMessage.test(output)) {
    console.error(`FAIL  ${testCase.name}`);
    console.error(`      failed for the wrong reason; expected ${testCase.expectMessage}`);
    console.error(
      `      got: ${output.trim().split("\n").find((l) => l.includes("FAIL")) ?? "(no FAIL line)"}`,
    );
    missed++;
    continue;
  }

  console.log(`ok    caught: ${testCase.name}`);
}

if (missed > 0) {
  console.error(`\n${missed} of ${cases.length} violations went undetected.`);
  process.exit(1);
}
console.log(`\n${cases.length} violations, all caught.`);