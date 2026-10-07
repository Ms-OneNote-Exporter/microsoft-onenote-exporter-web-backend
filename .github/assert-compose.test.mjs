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
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCRIPT = ".github/assert-compose.mjs";

/** Runs the assertion script against a config object; returns its exit code. */
function run(cfg) {
  return runScript(SCRIPT, cfg);
}

/**
 * runScript runs the assertion script from *some* directory.
 *
 * Two cases need the script and the Dockerfile to be read from a scratch tree: the
 * assertion reads `../orchestrator/Dockerfile` relative to itself, so a Dockerfile
 * violation can only be staged if the script sits next to a mutated copy of it.
 *
 * Deliberately **not** a `dockerfile` field on the config passed to the script. That
 * would be a test-only backdoor in the assertion — the thing being tested would gain
 * a way to be told what to check, which is exactly the shape of an assertion that
 * cannot be trusted.
 */
function runScript(scriptPath, cfg) {
  try {
    execFileSync("node", [scriptPath], {
      input: JSON.stringify(cfg),
      stdio: ["pipe", "pipe", "pipe"],
    });
    return 0;
  } catch (error) {
    return error.status ?? 1;
  }
}

/**
 * stages a mutated copy of the orchestrator Dockerfile beside a copy of the script,
 * and returns the path to that copy of the script.
 *
 * A temp tree rather than an in-place edit-and-restore: restoring in a `finally`
 * means an interrupt leaves the repository broken, and a broken repository is a
 * worse outcome than a failed harness.
 */
function stageDockerfile(find, replace) {
  const root = mkdtempSync(join(tmpdir(), "assert-compose-"));
  mkdirSync(join(root, ".github"));
  mkdirSync(join(root, "orchestrator"));
  writeFileSync(
    join(root, ".github", "assert-compose.mjs"),
    readFileSync(SCRIPT),
  );
  const original = readFileSync("orchestrator/Dockerfile", "utf8");
  if (!original.includes(find)) {
    throw new Error(`orchestrator/Dockerfile no longer contains ${JSON.stringify(find)}`);
  }
  writeFileSync(join(root, "orchestrator", "Dockerfile"), original.split(find).join(replace));
  return join(root, ".github", "assert-compose.mjs");
}

/** A deep clone, so each case starts from the real config untouched. */
const clone = (cfg) => structuredClone(cfg);

const base = JSON.parse(
  // `--profile runner`, because the runner service sits behind a profile and a
  // plain `config` prunes it out — which would make every runner case below
  // mutate nothing and pass vacuously, against a base with no runner in it. The
  // same trap that made the `infra` job red when ci.yml started running again.
  execFileSync("docker", ["compose", "--profile", "runner", "config", "--format", "json"], {
    encoding: "utf8",
    env: {
      ...process.env,
      COMPOSE_PROJECT_NAME: "msout",
      PUBLIC_HOST: "one-backend.phttp.com",
      ACME_EMAIL: "ops@example.com",
      ALLOWED_ORIGINS: "https://app.example.com",
      IMAGE_TAG: "0000000",
      _DOCKER_GID: "998",
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
    // The bug this assertion exists for, found on the first deploy: the
    // orchestrator was given the api's secret variable name, so the secret never
    // arrived and it refused to start. Docker reported "unhealthy"; the reason was
    // in a log nobody was reading.
    name: "gives the orchestrator the api's secret variable name",
    mutate: (c) => {
      c.services.orchestrator.environment.ORCHESTRATOR_HMAC_SECRET_FILE =
        "/run/secrets/orchestrator_hmac_secret";
      delete c.services.orchestrator.environment.ORCH_HMAC_SECRET_FILE;
    },
    expectMessage: /orchestrator does not set ORCH_HMAC_SECRET_FILE/,
  },
  {
    // Also found on the first deploy: POOL_SIZE was passed unprefixed, so the
    // orchestrator ignored it and came up at its built-in pool size. Silently, and
    // while looking correctly configured.
    name: "gives the orchestrator an unprefixed variable",
    mutate: (c) => {
      c.services.orchestrator.environment.POOL_SIZE = "2";
    },
    expectMessage: /POOL_SIZE, which its config never reads/,
  },
  {
    name: "leaves the api image unstamped",
    mutate: (c) => {
      delete c.services.api.build.args.BUILD_ID;
    },
    expectMessage: /the api image has no BUILD_ID/,
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

  // ---- the runner ---------------------------------------------------------
  //
  // The runner holds the credential bytes, so each of these is the assertion
  // that has to hold before a session password is anywhere near it. Every case
  // below mutates the *real* resolved config, which only contains a runner
  // because the base is resolved with `--profile runner` — without that, all six
  // would mutate `undefined` and pass for the wrong reason.

  {
    name: "removes the runner entirely",
    mutate: (c) => {
      delete c.services.runner;
    },
    // The loudest one. Every other runner check reads `services.runner` and sees
    // an empty object, which is true of no socket, no binds and no ports — so a
    // missing runner must be reported as a missing runner, not as compliance.
    expectMessage: /there is no `runner` service/,
  },
  {
    name: "gives the runner the docker socket",
    mutate: (c) => {
      c.services.runner.volumes.push({
        type: "bind",
        source: "/var/run/docker.sock",
        target: "/var/run/docker.sock",
        bind: {},
      });
    },
    expectMessage: /runner mounts a docker socket/,
  },
  {
    name: "gives the runner a host path beyond its secret",
    mutate: (c) => {
      c.services.runner.volumes.push({
        type: "bind",
        source: "/srv/msout/vault",
        target: "/srv/msout/vault",
        bind: {},
      });
    },
    expectMessage: /runner bind-mounts something unexpected/,
  },
  {
    name: "hands the runner the CSRF key",
    mutate: (c) => {
      c.services.runner.environment.CSRF_KEY = "0123456789abcdef0123456789abcdef";
    },
    expectMessage: /runner environment carries CSRF_KEY/,
  },
  {
    name: "publishes the runner's port",
    mutate: (c) => {
      c.services.runner.ports = [{ target: 3100, published: "3100", protocol: "tcp" }];
    },
    expectMessage: /runner publishes/,
  },
  {
    name: "puts the runner on the control network",
    mutate: (c) => {
      c.services.runner.networks = { "msout-runner": null, "msout-control": null };
    },
    // No space after the comma: the list is built by `Array.prototype.join(",")`,
    // and an expected-message regex that assumed otherwise fails on a *correct*
    // rejection — which is how a check gets "fixed" by being weakened.
    expectMessage: /runner is on \[msout-runner,msout-control\]/,
  },

  // ---- the credential path: the three networks ----------------------------
  //
  // Each of these is the mistake the arrangement exists to prevent, and each
  // deploys cleanly. None of them produces an error, an unhealthy container, or a
  // failing check anywhere else in the stack.
  {
    // The one that is genuinely tempting, because it is the obvious way to let
    // the api reach a runner: one network instead of two. The api then has egress,
    // which is PLAN-v3 §2.1's prohibition, and nothing in the stack notices.
    name: "puts the api on the egress network",
    mutate: (c) => {
      c.services.api.networks["msout-runner"] = null;
    },
    expectMessage: /api is on msout-runner/,
  },
  {
    // The other tempting fix for the same problem: drop the credential-path
    // network and put the runner where the orchestrator is. Now the credential
    // and the Docker socket share a network.
    name: "puts the runner on the control network instead of the api's",
    mutate: (c) => {
      delete c.services.runner.networks["msout-runner-api"];
      c.services.runner.networks["msout-control"] = null;
      c.services.api.networks["msout-runner-api"] = null;
    },
    expectMessage: /runner is on \[/,
  },
  {
    name: "makes the credential-path network routable",
    mutate: (c) => {
      c.networks["msout-runner-api"].internal = false;
    },
    // This is the whole point of `internal: true` on that network: a default
    // route on it hands the api the internet.
    expectMessage: /msout-runner-api/,
  },
  {
    // The failure an allowlist would cause, arrived at from the other side: the
    // runner loses the internet and every login fails. Deliberately not
    // "restricted to Microsoft", which is the tempting wrong fix.
    name: "makes the runner's egress network internal",
    mutate: (c) => {
      c.networks["msout-runner"].internal = true;
    },
    expectMessage: /msout-runner is internal/,
  },
  {
    // The one CI structurally cannot see. In the capability suite the *compose
    // file* creates the runner, so the orchestrator's own create path never runs —
    // which is exactly how a name mismatch between the two survived every job.
    //
    // The fix is `name:` on the network, and this is the assertion for it: without
    // it Compose creates `<project>_msout-runner` while the orchestrator asks for
    // `msout-runner`, and every slot fails on a real host.
    name: "lets Compose prefix the runner networks the orchestrator names",
    mutate: (c) => {
      delete c.networks["msout-runner"].name;
      delete c.networks["msout-runner-api"].name;
    },
    expectMessage: /network not found/,
  },
  {
    name: "removes the api from the credential-path network",
    mutate: (c) => {
      delete c.services.api.networks["msout-runner-api"];
    },
    expectMessage: /api is not on msout-runner-api/,
  },
  {
    name: "adds the orchestrator to the credential path",
    mutate: (c) => {
      c.services.orchestrator.networks["msout-runner-api"] = null;
    },
    expectMessage: /msout-runner-api holds/,
  },
  {
    // The api needs the token to present, and a 401 from the runner reads as "the
    // password was rejected" — pointing an operator at the wrong component.
    name: "takes runner_token away from the api",
    mutate: (c) => {
      c.services.api.secrets = c.services.api.secrets.filter(
        (s) => s.source !== "runner_token",
      );
    },
    expectMessage: /api's secrets are/,
  },
  {
    // The value in an env var is visible in `docker inspect`. The other two
    // secrets this api holds are asserted the same way; the third one is the
    // easiest to get wrong because it is newest.
    name: "puts the runner token in the api's environment",
    mutate: (c) => {
      c.services.api.environment.RUNNER_TOKEN = "hunter2";
    },
    expectMessage: /RUNNER_TOKEN as a value/,
  },
  {
    name: "disables the Chromium sandbox",
    mutate: (c) => {
      c.services.runner.command = ["chromium", "--no-sandbox"];
    },
    expectMessage: /--no-sandbox/,
  },

  // ---- the orchestrator can hand a runner its token ------------------------
  //
  // Dropping either of these is silent: the orchestrator keeps naming
  // /run/secrets/runner_token as a bind source, Docker creates the destination as
  // an empty *directory* when the source does not exist, the runner mounts a
  // directory over its own secret path, reads a path, and exits 1. Every
  // container starts and every orchestrator check still passes.
  {
    name: "takes runner_token away from the orchestrator",
    mutate: (c) => {
      c.services.orchestrator.secrets = c.services.orchestrator.secrets.filter(
        (s) => s.source !== "runner_token",
      );
    },
    expectMessage: /orchestrator's secrets are \[/,
  },
  {
    // The shipped bug: the vault was not a volume at all, so every session's
    // auth.json and exported vault lived in the orchestrator container's writable
    // layer and one `--force-recreate` deleted them. Nothing failed until the data
    // was gone, which is to say nothing ever reported it.
    name: "leaves the session vault in the container's writable layer",
    mutate: (c) => {
      c.services.orchestrator.volumes = (c.services.orchestrator.volumes ?? []).filter(
        (v) => (typeof v === "string" ? v : v?.target) !== "/srv/msout/vault",
      );
    },
    expectMessage: /writable layer/,
  },
  {
    // The other half: the volume was mounted, but the *image* prepared
    // `/srv/vault` rather than `/srv/msout/vault`, so Docker seeded nothing, the
    // volume came out root-owned, and `mkdir /srv/msout/vault` failed for uid
    // 65532. Both assertions are needed — either alone passes the other bug.
    name: "seeds the vault volume from an unrelated image path",
    mutateFile: { file: "orchestrator/Dockerfile", find: "/out/srv/msout/vault", replace: "/out/srv/vault" },
    expectMessage: /nothing seeds \/srv\/msout\/vault/,
  },
  {
    // `mkdir -p a b` is one instruction with two paths. An assertion that matched
    // a single path per line would find only the first and pass while `artifacts`
    // was broken.
    name: "prepares only the first path of a multi-path mkdir",
    mutateFile: {
      file: "orchestrator/Dockerfile",
      find: "RUN mkdir -p /out/srv/msout/vault /out/srv/msout/artifacts",
      replace: "RUN mkdir -p /out/srv/msout/vault",
    },
    expectMessage: /nothing seeds \/srv\/msout\/artifacts/,
  },
  {
    // §2.1: only the orchestrator and the runners it creates may read a vault.
    // A vault mount on the api would hand it every session's cookie jar.
    name: "gives the api the session vault",
    mutate: (c) => {
      c.services.api.volumes = [...(c.services.api.volumes ?? []), { target: "/srv/msout/vault" }];
    },
    expectMessage: /api mounts \/srv\/msout\/vault/,
  },
  {
    name: "points the orchestrator's token path at nothing",
    mutate: (c) => {
      c.services.orchestrator.environment.ORCH_RUNNER_TOKEN_FILE = "/etc/passwd";
    },
    expectMessage: /ORCH_RUNNER_TOKEN_FILE is/,
  },
  {
    // The mistake that shipped. The value looked correct — it named a path the
    // orchestrator really does mount — but it was a *container* path used as a
    // bind *source*, so on a host where it does not exist Docker created a
    // directory and every runner exited 1. The previous assertion checked for
    // exactly this value and passed.
    name: "gives the orchestrator the container path as a bind source",
    mutate: (c) => {
      c.services.orchestrator.environment.ORCH_RUNNER_TOKEN_FILE = "/run/secrets/runner_token";
    },
    // Matches on the *reason* rather than the variable name, because the variable
    // name is in the message too and a regex written against the old message
    // would fail on a correct rejection — which is how a check gets "fixed" by
    // being weakened.
    expectMessage: /must resolve on the host/,
  },
];

// ---- each violation must be caught ----------------------------------------

let missed = 0;

for (const testCase of cases) {
  const cfg = clone(base);
  // `mutateFile` cases stage the *other* half of the violation — the Dockerfile —
  // and still need a config mutation, so a no-op is allowed rather than each of
  // them having to invent one. A required `mutate` would push every file-level case
  // towards a filler function that looks like it is asserting something.
  testCase.mutate?.(cfg);
  const script = testCase.mutateFile
    ? stageDockerfile(testCase.mutateFile.find, testCase.mutateFile.replace)
    : SCRIPT;

  if (runScript(script, cfg) === 0) {
    console.error(`FAIL  not caught: ${testCase.name}`);
    missed++;
    continue;
  }

  // Not just "it failed" — it failed for the right reason. A check that exits
  // non-zero for an unrelated reason is no better than one that passes.
  let output = "";
  try {
    execFileSync("node", [script], { input: JSON.stringify(cfg), stdio: ["pipe", "pipe", "pipe"] });
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