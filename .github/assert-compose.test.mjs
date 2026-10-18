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
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

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

/** A deep clone, so each case starts from the real config untouched. */
const clone = (cfg) => structuredClone(cfg);

/**
 * The bind-mount sources the compose file requires. Absolute, and named so the
 * harness cases can say "nothing is mounted at this path" without repeating a
 * literal that has to be kept in step with `docker-compose.yml`.
 *
 * They are passed to `docker compose` below rather than being asserted against as
 * constants, because a check that re-declares the value it is checking tests
 * nothing.
 */
const VAULT_DIR = "/srv/msout/vault-host";
const ARTIFACT_DIR = "/srv/msout/artifacts-host";

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
      VAULT_HOST_DIR: VAULT_DIR,
      ARTIFACT_HOST_DIR: ARTIFACT_DIR,
      SECRETS_DIR: "/srv/msout/secrets",
      RUNNER_IMAGE: "ghcr.io/ms-one-note-exporter/msout-runner:0000000",
      // Required by compose with `:?`. Present here so the cases below can assert
      // about it rather than every case failing on interpolation.
      API_TRUSTED_PROXIES: "172.24.0.0/16",
    },
  }),
);

// ---- the happy path --------------------------------------------------------

if (run(clone(base)) !== 0) {
  console.error("the real config does not pass the assertions — fix that first");
  process.exit(1);
}
console.log("ok    the real compose config passes every assertion");

/**
 * stages the assertion script beside a scratch copy of everything it reads, applying
 * zero or more mutations, and returns the path to that copy of the script.
 *
 * The script reads four things: the resolved config on stdin, and — resolved relative
 * to itself — the two Dockerfiles the uid check compares, `.env.example`,
 * `docker-compose.yml`, and the component source trees the documented-key check
 * scans. A staged tree missing any of them makes the script fail on a **missing file**
 * rather than on the violation, and the harness counts any non-zero exit as "caught":
 * every case would pass while asserting nothing.
 *
 * That is not hypothetical. The documented-key check added a third read, and the
 * first version of this harness kept staging only the Dockerfiles — so the allowlist
 * cases below failed on "no component source could be read" and reported it as a
 * broken allowlist.
 *
 * A temp tree rather than an in-place edit-and-restore, for the reason
 * `stageDockerfile` gives: restoring in a `finally` means an interrupt leaves the
 * repository broken, and a broken repository is a worse outcome than a failed harness.
 *
 * `mutations` is `{relativePath: [find, replace] | null}`, where `null` means "omit
 * this file" — a deleted `.env.example` is not the same violation as an edited one.
 * A `find` that matches nothing **throws**, so a case cannot stage an identical tree
 * and pass without asserting anything.
 */
function stageScript(mutations) {
  const root = mkdtempSync(join(tmpdir(), "assert-compose-"));
  mkdirSync(join(root, ".github"));
  writeFileSync(join(root, ".github", "assert-compose.mjs"), readFileSync(SCRIPT));

  // Everything the script reads, copied verbatim. Enumerated rather than walked,
  // because an omitted entry is silent: the script fails on the missing path and the
  // harness counts that as a caught violation.
  const COPIED_TREES = ["api/src", "runner/src", "orchestrator"];
  const COPIED_FILES = ["orchestrator/Dockerfile", "runner/Dockerfile", "docker-compose.yml", ".env.example"];

  for (const path of [...COPIED_TREES, ...COPIED_FILES]) {
    const destination = join(root, path);
    mkdirSync(dirname(destination), { recursive: true });
    cpSync(path, destination, { recursive: true });
  }

  for (const [path, mutation] of Object.entries(mutations)) {
    if (mutation === null) {
      rmSync(join(root, path), { force: true, recursive: true });
      continue;
    }
    const [find, replace] = mutation;
    const target = join(root, path);
    const original = readFileSync(target, "utf8");
    if (!original.includes(find)) {
      throw new Error(
        `${path} does not contain ${JSON.stringify(find)}; the mutation would stage an ` +
          `identical tree and the case would pass without asserting anything`,
      );
    }
    writeFileSync(target, original.split(find).join(replace));
  }

  return join(root, ".github", "assert-compose.mjs");
}

/** @type {{name: string, mutate: (cfg: any) => void, expectMessage: RegExp}[]} */
const cases = [
  {
    // The deployed failure, stated as a mutation. Caddy sets X-Forwarded-For and the
    // api refuses to believe it, so every caller is rate-limited as the proxy: three
    // sessions an hour for the whole internet, with every request logging
    // `"remoteAddress":"172.24.0.4"`. Observed on the live host.
    name: "drops API_TRUSTED_PROXIES",
    mutate: (c) => {
      delete c.services.api.environment.API_TRUSTED_PROXIES;
    },
    expectMessage: /API_TRUSTED_PROXIES/,
  },
  {
    // The api's `environment:` is an allowlist, so a variable absent from it is a
    // variable the process never reads. The operator sets it in `.env`, sees no
    // error, and the api keeps its compiled-in default — for the rate limiter that
    // means raising the cap has no effect and a 429 still arrives mid-proof,
    // which reads as a fault in the thing being proved rather than a config miss.
    name: "drops RATE_LIMIT_SESSIONS_PER_HOUR from the api's environment",
    mutate: (c) => {
      delete c.services.api.environment.RATE_LIMIT_SESSIONS_PER_HOUR;
    },
    expectMessage: /RATE_LIMIT_SESSIONS_PER_HOUR/,
  },
  {
    // A container's IP changes on recreate, so an exact address works until the next
    // deploy and then fails by becoming a silent global limit again.
    name: "trusts a single container address rather than a network",
    mutate: (c) => {
      c.services.api.environment.API_TRUSTED_PROXIES = "172.24.0.0/16";
      c.services.api.environment.API_TRUSTED_PROXIES = "172.24.0.4";
    },
    expectMessage: /single address/,
  },
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
    // A hyphen short. `RUNNER_IMAGE` said `ms-onenote-exporter`, compose builds
    // `ms-one-note-exporter`, and every rebuild landed in a different repository while
    // the orchestrator kept creating runners from a 15-hour-old image — with
    // `docker images` showing a fresh build the whole time.
    //
    // This is the one assertion in this file about a value the *operator* supplies,
    // and it is here because two independent names for one image is the same shape as
    // every other drift in this PR: a place where nothing checks that two namings mean
    // the same thing.
    name: "has the orchestrator create runners from a different image than the stack runs",
    mutate: (c) => {
      c.services.orchestrator.environment.ORCH_RUNNER_IMAGE =
        "ghcr.io/ms-onenote-exporter/msout-runner:0000000";
    },
    expectMessage: /image the stack runs|independent/,
  },
  {
    // Dropping `external` makes Compose prune the network it just created, because
    // the only service that joins it is behind a profile. The failure appears as
    // `404 network msout-runner not found` at the first runner create — on a real
    // host, and in CI only because the orchestrator-create step was added.
    //
    // Without the flag, compose itself refuses to start: `network msout-runner was
    // found but has incorrect label com.docker.compose.network`. Which is a deploy
    // step failing loudly, not an assertion.
    name: "lets Compose prune the runner's egress network",
    mutate: (c) => {
      c.networks["msout-runner"].external = false;
    },
    expectMessage: /external/,
  },
  {
    // The shipped bug: distroless `nonroot` is 65532 and the runner's `node` is 1000.
    // They share `/srv/msout/data`, so the orchestrator created a session directory
    // the runner could not write to, and every login failed with
    // `EACCES: permission denied, mkdir '/data/<guid>'` — from a container that was
    // healthy, correctly mounted and correctly addressed.
    //
    // Staged as a Dockerfile edit rather than a config edit precisely because the
    // config carries no uid at all: the two images name the identity independently,
    // which is why nothing compared them.
    name: "gives the orchestrator a different uid from the runner",
    mutateFile: {
      file: "orchestrator",
      find: "USER 1000:1000",
      replace: "USER 65532:65532",
    },
    expectMessage: /share \/srv\/msout\/data/,
  },
  {
    // A named uid cannot be compared, so the check refuses rather than passing. The
    // runner's Dockerfile said `USER node` while the orchestrator's said
    // `USER 1000:1000`, and a check that skipped the mismatch rather than objecting
    // to it would have been the thing that let the pair through.
    name: "declares the runner's uid by name, so it cannot be compared",
    mutateFile: {
      file: "runner",
      find: "USER 1000:1000",
      replace: "USER node",
    },
    expectMessage: /must be numeric/,
  },
  {
    // The shipped bug, form 1: a named volume. On the host `/srv/msout/vault` is
    // not the volume at all — it is an empty root-owned directory Docker created —
    // and every runner mounted it as `/data` and failed with EACCES.
    //
    // Resolved config cannot distinguish this from a bind mount on the target, so
    // this case is expressed the way the mistake was: the env var is right, and the
    // orchestrator has nothing mounted there.
    name: "leaves the vault root with nothing mounted at that path",
    mutate: (c) => {
      c.services.orchestrator.volumes = (c.services.orchestrator.volumes ?? []).filter(
        (v) => (typeof v === "string" ? v : v?.target) !== VAULT_DIR,
      );
    },
    expectMessage: /resolved on the \*host\*/,
  },
  {
    // The shipped bug, form 2: no mount at all, so the vault lived in the
    // container's writable layer and one `--force-recreate` deleted every session.
    // With no volume and no env var, the orchestrator falls back to
    // `/srv/msout/vault`, which is a container path that resolves nowhere on the host.
    name: "leaves the vault in the container's writable layer",
    mutate: (c) => {
      delete c.services.orchestrator.environment.ORCH_VAULT_ROOT;
      c.services.orchestrator.volumes = (c.services.orchestrator.volumes ?? []).filter(
        (v) => (typeof v === "string" ? v : v?.target) !== "/srv/msout/vault",
      );
    },
    expectMessage: /ORCH_VAULT_ROOT is undefined/,
  },
  {
    // A relative root cannot be resolved by the Engine at all, and resolves against
    // whatever working directory it happens to pick if it can be.
    name: "makes the artifact root relative",
    mutate: (c) => {
      c.services.orchestrator.environment.ORCH_ARTIFACT_ROOT = "./artifacts";
    },
    expectMessage: /ORCH_ARTIFACT_ROOT is "\.\/artifacts"/,
  },
  {
    // §2.1: only the orchestrator and the runners it creates may read a vault.
    // A vault mount on the api would hand it every session's cookie jar.
    name: "gives the api the session vault",
    mutate: (c) => {
      c.services.api.volumes = [
        ...(c.services.api.volumes ?? []),
        { type: "bind", source: VAULT_DIR, target: VAULT_DIR },
      ];
    },
    expectMessage: /api mounts .*vault-host/,
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

  // ---- `.env.example` reachability ------------------------------------------
  //
  // Three keys shipped documented and dead: `LOGIN_TIMEOUT_MS` /
  // `EXPORT_TIMEOUT_MS`, which nothing read under either name, and
  // `CHROMIUM_NO_SANDBOX`, which advertised disabling a security control. All three
  // deployed cleanly and did nothing.
  //
  // These are the mutations of that class, and they need `mutateRepoFile` rather than
  // `mutateFile` because the thing being broken is a **file in the repository** rather
  // than the resolved config. The script reads `.env.example` and `docker-compose.yml`
  // from the repo root relative to itself, so staging those two beside a copy of the
  // script is the only way a violation can be expressed at all.
  {
    // The original defect, form 1: a documented key nothing reads. An operator sets
    // it, restarts, and every runner is on the runner's own default — with no error
    // anywhere, because the orchestrator is not misconfigured; it is simply never
    // told.
    name: "documents a key nothing consumes",
    mutateRepoFile: { file: ".env.example", find: "LOG_LEVEL=info", replace: "LOG_LEVEL=info\nTOTALLY_MADE_UP_KNOB=1" },
    expectMessage: /documents TOTALLY_MADE_UP_KNOB and nothing consumes it/,
  },
  {
    // **The defect that actually shipped**, and the sharpest case in this section.
    //
    // The sharpest form of this check: a documented key whose name **contains** a
    // consumed name as a substring. `X_EXPORT_TIMEOUT_MS` contains `EXPORT_TIMEOUT_MS`,
    // which is itself a real key here. A check that asked "does this string appear
    // anywhere?" would call it consumed. This one compares the whole name, so it must
    // report it dead.
    //
    // This case is why the check is not a `grep`, and the nesting is real in this
    // repository: the operator's host-side `EXPORT_TIMEOUT_MS`, the orchestrator's
    // `ORCH_RUNNER_EXPORT_TIMEOUT_MS`, and the runner's `MSOUT_EXPORT_TIMEOUT_MS` — each
    // name contains the previous one.
    name: "documents a key whose name merely contains a consumed one",
    mutateRepoFile: {
      file: ".env.example",
      find: "EXPORT_TIMEOUT_MS=3600000",
      replace: "X_EXPORT_TIMEOUT_MS=3600000",
    },
    expectMessage: /documents X_EXPORT_TIMEOUT_MS and nothing consumes it/,
  },
  {
    // The original defect, form 3: `CHROMIUM_NO_SANDBOX`. Nothing reads it in any
    // name, so an operator who set it would see no error and conclude the renderer
    // sandbox was off. It was deleted rather than wired, because wiring it would have
    // turned a control into a default.
    name: "documents the Chromium sandbox flag again",
    mutateRepoFile: { file: ".env.example", find: "MSOUT_FAKE=0", replace: "MSOUT_FAKE=0\nCHROMIUM_NO_SANDBOX=0" },
    expectMessage: /documents CHROMIUM_NO_SANDBOX and nothing consumes it/,
  },
  {
    // The other direction: stop interpolating a documented key in compose while
    // leaving `.env.example` alone. The operator's value stops reaching compose, the
    // orchestrator falls back to a default, and nothing reports it.
    //
    // `RUNNER_MEMORY_LIMIT` specifically because it is **only** consumed through
    // compose — no component source reads that string, which is the same fact this
    // check asserts on its own. `LOG_LEVEL` would not work here: the api reads it
    // directly, so the key survives losing its interpolation and the case would pass
    // vacuously.
    name: "stops interpolating a documented key in compose",
    mutateRepoFile: {
      file: "docker-compose.yml",
      find: "${RUNNER_MEMORY_LIMIT:-2g}",
      replace: "2g",
    },
    expectMessage: /documents RUNNER_MEMORY_LIMIT and nothing consumes it/,
  },
  {
    // A `.env.example` that cannot be read at all. The check must say so rather than
    // reporting zero unconsumed keys and passing: "found nothing" and "found nothing
    // wrong" are indistinguishable from the outside, and this is the shape of a check
    // that has been defeated by a path change.
    name: "cannot read .env.example from the repo root",
    mutateRepoFile: { file: ".env.example", find: null },
    expectMessage: /could not read \.env\.example/,
  },
  {
    // **The value `.env.example` shipped with.** `LOGIN_TIMEOUT_MS=900000` was exactly
    // `TTL.loginInProgress`, so a reader who copied the template unchanged would have
    // got an orchestrator that refused to start — once the knob was wired at all.
    //
    // A reachability check cannot see this: the key *is* consumed. The value is a
    // separate question, and it is the one that decides whether the file describes a
    // configuration the stack can actually run.
    name: "documents a value the orchestrator refuses at boot",
    mutateRepoFile: {
      file: ".env.example",
      find: "LOGIN_TIMEOUT_MS=300000",
      replace: "LOGIN_TIMEOUT_MS=900000",
    },
    expectMessage: /documents LOGIN_TIMEOUT_MS=900000, which compose maps to/,
  },
  {
    // The other TTL, on the export side: `TTL.absolute` at 12 hours. A value above it
    // is not merely unbounded — the sweeper's 12-hour cap becomes the only thing that
    // ends a wedged export, which is strictly worse than the runner's own 60 minutes.
    name: "documents an export timeout above the api's absolute TTL",
    mutateRepoFile: {
      file: ".env.example",
      find: "EXPORT_TIMEOUT_MS=3600000",
      replace: "EXPORT_TIMEOUT_MS=43200000",
    },
    expectMessage: /documents EXPORT_TIMEOUT_MS=43200000, which compose maps to/,
  },
];

// ---- the allowlist cannot swallow everything --------------------------------
//
// The two OUT_OF_BAND_CONSUMERS entries are the check's escape hatch, and an escape
// hatch that cannot be opened is a claim. Each one is removed in turn and the real
// `.env.example` is required still to pass — so a key that is *only* alive because an
// allowlist entry names it fails as soon as that entry is gone.
//
// The two are removed by **repointing the named consumer at a file that does not
// exist**, rather than by deleting the entry. Deleting a line changes the file's shape
// and a harness that matched on exact indentation would break the first time somebody
// reformatted it; repointing names the property under test — that the entry is *carrying*
// this key — and a file that no longer consumes it is precisely how such an entry rots.
//
// Both are checked, and starting from a passing state is the whole assertion: a key
// with a second consumer would pass with its entry repointed and would prove nothing.
// That is the failure mode being guarded against — an allowlist that keeps entries long
// after the thing they excused is fixed.
for (const [key, consumer] of [
  ["ORCHESTRATOR_HMAC_SECRET_FILE", ".github/workflows/ci.yml"],
  ["MSOUT_FAKE", "runner/package.json"],
]) {
  if (run(clone(base)) !== 0) {
    console.error(`allowlist: the real config does not pass, so ${key} proves nothing`);
    process.exit(1);
  }
  const staged = stageScript({
    ".github/assert-compose.mjs": [
      `"${consumer}"`,
      `".github/workflows/nothing-consumes-this.mjs"`,
    ],
  });
  const code = runScript(staged, clone(base));
  if (code !== 0) {
    let output = "";
    try {
      execFileSync("node", [staged], { input: JSON.stringify(clone(base)), stdio: ["pipe", "pipe", "pipe"] });
    } catch (error) {
      output = String(error.stderr ?? "");
    }
    console.error(
      `FAIL  repointing the ${key} allowlist entry at a file that consumes nothing made ` +
        `the real .env.example fail`,
    );
    console.error(
      `      so ${key} has another consumer and the allowlist entry is not carrying it: ` +
        `update the check's comment to name the consumer that is. Got: ` +
        `${output.trim().split("\n").filter((l) => l.includes("FAIL")).join(" | ") || "(no FAIL line)"}`,
    );
    process.exit(1);
  }
  console.log(`ok    ${key} is carried by its allowlist entry, not by something else`);
}

// ---- each violation must be caught ----------------------------------------

let missed = 0;

for (const testCase of cases) {
  const cfg = clone(base);
  // `mutateFile` cases stage the *other* half of the violation — the Dockerfile —
  // and still need a config mutation, so a no-op is allowed rather than each of
  // them having to invent one. A required `mutate` would push every file-level case
  // towards a filler function that looks like it is asserting something.
  testCase.mutate?.(cfg);
  const script = stageScript(
    testCase.mutateFile
      ? { [`${testCase.mutateFile.file}/Dockerfile`]: [testCase.mutateFile.find, testCase.mutateFile.replace] }
      : testCase.mutateRepoFile
        ? {
            [testCase.mutateRepoFile.file]:
              testCase.mutateRepoFile.find === null
                ? null
                : [testCase.mutateRepoFile.find, testCase.mutateRepoFile.replace],
          }
        : {},
  );

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