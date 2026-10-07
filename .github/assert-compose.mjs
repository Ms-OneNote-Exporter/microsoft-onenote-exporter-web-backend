#!/usr/bin/env node
/**
 * Static assertions about the resolved compose config.
 *
 * Run against `docker compose config --format json`, so it checks what Compose
 * actually resolved rather than what the YAML appears to say. That distinction is
 * the point: every one of these mistakes produces a stack that starts, serves, and
 * looks fine.
 *
 *   docker compose config --format json | node .github/assert-compose.mjs
 *
 * None of this proves a container is isolated — that needs running containers and
 * lives in capability.yml. These are the properties that are wrong in the file
 * rather than wrong at runtime, and they are cheap because `config` needs no
 * daemon.
 */

import { readFileSync } from "node:fs";

const cfg = JSON.parse(readFileSync(0, "utf8"));

/** @type {string[]} */
const failures = [];
/** @type {string[]} */
const passes = [];

const check = (condition, okMessage, failMessage) => {
  if (condition) passes.push(okMessage);
  else failures.push(failMessage);
};

const services = cfg.services ?? {};

// 1. The control network has no route to the internet.
//
// §2.1: the orchestrator talks only to the Docker socket, which is not a network,
// so it needs no egress. A network declared without `internal: true` still works
// perfectly, so nothing else in the stack would complain — the orchestrator would
// simply be able to reach the internet, which is exactly what the component split
// exists to prevent.
check(
  cfg.networks?.["msout-control"]?.internal === true,
  "msout-control has internal: true (no route to the internet)",
  "msout-control is missing `internal: true` — the control plane can reach the internet",
);

// 2. Only Caddy publishes a port.
//
// The api and the orchestrator being unreachable from the host is the reason to
// split them into separate components; a published port would undo it without any
// error.
for (const svc of ["api", "orchestrator"]) {
  const ports = services[svc]?.ports ?? [];
  check(
    ports.length === 0,
    `${svc} publishes no port`,
    `${svc} publishes ${ports.length} port(s): ${JSON.stringify(ports)}`,
  );
}
check(
  (services.caddy?.ports ?? []).length > 0,
  "caddy publishes 80/443",
  "caddy publishes no port, so nothing is reachable",
);

// 3. The Docker socket belongs to the orchestrator and only the orchestrator.
//
// This is §2.1 in one assertion. The socket *is* container creation, so it is the
// entire reason the orchestrator is a separate component — a process that can
// create a container can ignore every other restriction.
//
// Matched on the mount's **source**, not its target. The first version of this
// check stringified the whole volume and looked for "docker.sock", which matched
// the *target* — so replacing the source with an unrelated path still passed. That
// is the direction that matters: the question is always "does this process have
// the host's socket", and the answer lives in the source.
const DOCKER_SOCK = "/var/run/docker.sock";

/** Every bind mount whose source is the host's docker socket. */
const socketsFor = (svc) =>
  (services[svc]?.volumes ?? []).filter(
    (v) => v.type === "bind" && String(v.source).endsWith("docker.sock"),
  );

/** Every bind mount at all, for a service. */
const bindsFor = (svc) =>
  (services[svc]?.volumes ?? []).filter((v) => v.type === "bind");

check(
  socketsFor("orchestrator").length === 1,
  "orchestrator mounts the host docker socket, once",
  `orchestrator has ${socketsFor("orchestrator").length} docker socket mount(s); expected exactly 1`,
);
for (const svc of ["api", "caddy", "runner"]) {
  check(
    socketsFor(svc).length === 0,
    `${svc} mounts no docker socket`,
    `${svc} mounts a docker socket — it must never hold one (§2.1)`,
  );
}

// 3a. The runner takes no host path and carries no session secret.
//
// **Presence is asserted first, and on its own.** Every check below reads
// `services.runner`, and a service that is absent from the resolved config makes
// each of them pass vacuously — `undefined ?? {}` is empty, so "no bind mounts"
// and "no socket" and "publishes no port" are all true of nothing at all. That is
// the worst shape an assertion can have: green, and checking nothing.
//
// It was not hypothetical. The runner sits behind a compose profile, so
// `docker compose config` *without* `--profile runner` prunes the service out
// entirely, and the first run of this file did exactly that.
//
// §2.1's rule, and the sharpest form of it here: the runner is the only component
// that sees the credential bytes, so every additional capability it holds is a
// capability an attacker reaches *after* the password. Its **data** root is a
// named volume, so erase is one directory removal, and it gets no CSRF key and no
// session secret.
//
// The runner *does* carry MSOUT_RUNNER_TOKEN_FILE, which is a token for the
// orchestrator to authenticate with, not a session credential: it authorises
// starting work in a container the orchestrator created, and never carries or
// reveals a password.
//
// **Exactly one bind mount is therefore correct, and it is the secret.** Docker
// Compose has no secret mechanism other than bind-mounting the file, so a
// "no bind mounts at all" check on any service declaring `secrets:` is wrong by
// construction — and it was: the capability suite failed on the runner's token
// mount, which is the one thing §2.1 asks it to have. Caddy is already allowed
// exactly one bind above, for the same reason.
//
// So: the allowlist is the secret file and nothing else. A bind to a vault, a
// data directory or a host path fails here, which is the property that matters.
check(
  "runner" in services,
  "the runner service is present in the resolved config",
  "FAIL: there is no `runner` service. Run this with `--profile runner` — the service " +
    "is behind a profile so `docker compose up` does not start it, and without the " +
    "profile every runner assertion below would pass against nothing.",
);

// 3b. The orchestrator can actually hand a runner its token.
//
// The orchestrator bind-mounts a *file* from its own container into each runner.
// If the file is not mounted **in the orchestrator**, Docker creates the
// destination as an empty directory — so the runner mounts a directory over its
// own secret path, tries to read a file inside it, and exits 1. Every container
// starts, every orchestrator check passes, and no runner ever becomes healthy.
//
// That is not hypothetical: the orchestrator gained a runner_token mount in the
// same commit as this assertion, and the two are asserted together so the second
// cannot be dropped without the first.
const orchSecrets = (services.orchestrator?.secrets ?? []).map((s) => s.source);
check(
  orchSecrets.includes("runner_token"),
  "the orchestrator holds runner_token, to mount into each runner",
  `the orchestrator's secrets are [${orchSecrets.join(", ")}]. It bind-mounts that file ` +
    "into every runner, so without it Docker creates an empty directory at the " +
    "destination and each runner exits 1 at startup",
);
check(
  services.orchestrator?.environment?.ORCH_RUNNER_TOKEN_FILE === "/run/secrets/runner_token",
  "orchestrator: ORCH_RUNNER_TOKEN_FILE points at the mounted secret",
  `orchestrator ORCH_RUNNER_TOKEN_FILE is ${JSON.stringify(
    services.orchestrator?.environment?.ORCH_RUNNER_TOKEN_FILE,
  )}; it must name the path the token is mounted at, or the mount source is wrong`,
);
const runnerBinds = bindsFor("runner").map((v) => String(v.source));
check(
  runnerBinds.every((src) => src.endsWith("runner_token")),
  `runner bind-mounts only its token (${runnerBinds.join(", ") || "none"})`,
  `runner bind-mounts something unexpected: ${runnerBinds.join(", ")}. §2.1 gives it no host ` +
    "path — its data root is a named volume and the only bind allowed is its own secret file",
);
for (const key of ["CSRF_KEY", "CSRF_KEY_FILE", "SESSION_SECRET", "ORCHESTRATOR_HMAC_SECRET"]) {
  check(
    !(key in (services.runner?.environment ?? {})),
    `runner environment has no ${key}`,
    `runner environment carries ${key}. It holds credential bytes and must know nothing of sessions`,
  );
}
check(
  "MSOUT_RUNNER_TOKEN_FILE" in (services.runner?.environment ?? {}),
  "runner: MSOUT_RUNNER_TOKEN_FILE points into /run/secrets",
  "FAIL: the runner has no MSOUT_RUNNER_TOKEN_FILE — it would refuse to start",
);

// The runner publishes no port. The orchestrator reaches it by container name on
// the runner network; a published port would make it an API on the internet.
check(
  (services.runner?.ports ?? []).length === 0,
  "runner publishes no port",
  `runner publishes ${JSON.stringify(services.runner?.ports ?? [])}`,
);

// ...and it is on the runner network only. Being on the control network would
// put it where the orchestrator and api live, one compromise away from both.
const runnerNetworks = Object.keys(services.runner?.networks ?? {});
check(
  runnerNetworks.length === 1 && runnerNetworks[0] === "msout-runner",
  `runner is on msout-runner only (found: [${runnerNetworks}])`,
  `runner is on [${runnerNetworks}]; expected [msout-runner] only`,
);

// The renderer sandbox stays on. `--no-sandbox` is a documented fallback for a
// host that cannot enable unprivileged user namespaces, never a default, so its
// absence here is asserted rather than assumed — a compose file that grew it would
// otherwise disable the sandbox on every host silently.
const runnerCommand = JSON.stringify(services.runner?.command ?? services.runner?.entrypoint ?? "");
check(
  !runnerCommand.includes("--no-sandbox"),
  "runner does not pass --no-sandbox",
  "FAIL: the runner passes --no-sandbox. The renderer sandbox is a control, not a default",
);

// 3b. The api takes no host path whatsoever.
//
// §2.1: no socket, no vault mount, no host tree. Everything it needs arrives over
// the network or through a Docker secret. A bind mount here is a hole in the split
// that nothing else would notice, so it is asserted rather than reviewed.
check(
  bindsFor("api").length === 0,
  "api has no bind mounts at all",
  `api bind-mounts ${bindsFor("api").map((v) => v.source).join(", ")}; §2.1 gives it no host path`,
);

// 3c. Caddy takes no host path either, and no socket.
// Its only host surface is the read-only Caddyfile, which compose renders as a
// bind; everything else it needs is a named volume.
const caddyBinds = bindsFor("caddy").map((v) => v.source);
check(
  caddyBinds.every((src) => src.endsWith("Caddyfile")),
  `caddy bind-mounts only its config (${caddyBinds.join(", ") || "none"})`,
  `caddy bind-mounts something unexpected: ${caddyBinds.join(", ")}`,
);

// 4. The edge network holds Caddy alone.
//
// So the api's unreachability is a property of the topology rather than of
// remembering not to publish a port. The api reaches Caddy over msout-control,
// which Caddy also joins.
const onEdge = Object.entries(services)
  .filter(([, def]) => Object.keys(def.networks ?? {}).includes("msout-edge"))
  .map(([name]) => name);
check(
  onEdge.length === 1 && onEdge[0] === "caddy",
  `msout-edge holds only caddy (found: [${onEdge}])`,
  `msout-edge holds [${onEdge}]; expected [caddy] only`,
);

// 5. The orchestrator learns nothing it has no use for.
//
// §2.1 restricts it deliberately. An env var is how such a restriction quietly
// stops being true — one copy-pasted line, and the component that should know
// least about sessions knows the CSRF key.
for (const key of [
  "PUBLIC_HOST",
  "PUBLIC_ORIGIN",
  "ALLOWED_ORIGINS",
  "CSRF_KEY",
  "CSRF_KEY_FILE",
]) {
  check(
    !(key in (services.orchestrator?.environment ?? {})),
    `orchestrator environment has no ${key}`,
    `orchestrator environment carries ${key}, which it must not know`,
  );
}

// 6. Secrets arrive as file paths, never as values.
//
// An env var is visible in `docker inspect`, in `/proc/<pid>/environ`, and to
// anything that can read the container's config. The value must never appear in
// the compose file itself.
//
// An explicit list rather than a pattern like /SECRET|SESSION/. The first version
// of this check used a pattern and flagged SESSION_TTL_HOURS, which is a duration
// and not a secret — and a check that fires on harmless configuration trains a
// reader to ignore it, which is worse than no check at all.
const SECRET_VARS = [
  "CSRF_KEY",
  "ORCHESTRATOR_HMAC_SECRET",
  "SESSION_SECRET",
  "ARTIFACT_ENCRYPTION_KEY",
];

for (const svc of Object.keys(services)) {
  const env = services[svc]?.environment ?? {};

  for (const name of SECRET_VARS) {
    if (name in env) {
      failures.push(
        `${svc}: ${name} is assigned inline. Use ${name}_FILE pointing at /run/secrets/...`,
      );
    }
  }

  // Every *_FILE that is present must point at a real secret path.
  for (const [key, value] of Object.entries(env)) {
    if (!key.endsWith("_FILE")) continue;
    check(
      typeof value === "string" && value.startsWith("/run/secrets/"),
      `${svc}: ${key} points into /run/secrets`,
      `${svc}: ${key} is "${value}", which is not a /run/secrets path`,
    );
  }
}

// 7. Each service names the secret variable its own code actually reads.
//
// Both components read the same file under different variable names: the api uses
// ORCHESTRATOR_HMAC_SECRET_FILE, the orchestrator uses ORCH_HMAC_SECRET_FILE. The
// orchestrator was given the api's name, so the secret never arrived and it
// refused to start — reported by Docker only as "unhealthy", with the real reason
// sitting in a log nobody was reading during a first deploy.
//
// No test on either side could have caught it, because each mocks the other
// component. This is the same shape as a CMD naming a file that was never
// written: two correctly-implemented halves disagreeing about one string.
//
// Asserted here, in the file that wires them, because that is the only place both
// names are visible at once.
const SECRET_VAR_BY_SERVICE = {
  api: "CSRF_KEY_FILE",
  orchestrator: "ORCH_HMAC_SECRET_FILE",
};

for (const [svc, expected] of Object.entries(SECRET_VAR_BY_SERVICE)) {
  const env = services[svc]?.environment ?? {};
  const present = Object.keys(env).filter((k) => k.endsWith("_FILE"));
  check(
    expected in env,
    `${svc} reads its secret from ${expected}`,
    `${svc} does not set ${expected}, which is what its own config reads ` +
      `(it sets: ${present.join(", ") || "nothing"})`,
  );
}

// 8. Every variable given to the orchestrator is one it actually reads.
//
// Found on the first deploy: compose passed POOL_SIZE and RUNNER_TTL_SECONDS, and
// the orchestrator reads ORCH_POOL_SIZE and has no runner-TTL variable at all. Both
// were silently ignored, so the pool came up at its built-in default of 4 rather
// than the configured 2, and nothing anywhere said so.
//
// A variable in the wrong namespace is the worst kind of config error, because the
// container starts, looks configured, and ignores you. The list below is read out of
// the orchestrator's own config.go; add to it there and here together.
const ORCH_VARS_ACTUALLY_READ = new Set([
  "ORCH_LISTEN",
  "ORCH_DOCKER_SOCKET",
  "ORCH_HMAC_SECRET_FILE",
  "ORCH_POOL_SIZE",
  "ORCH_REPLAY_WINDOW_SECONDS",
  "ORCH_RUNNER_IMAGE",
  "ORCH_RUNNER_NETWORK",
  "ORCH_VAULT_ROOT",
  "ORCH_ARTIFACT_ROOT",
  // The host path of the bearer token each runner mounts read-only. Read in
  // config.go and used only as a bind source — the value is never read here, so
  // the token is not in this container's environment.
  "ORCH_RUNNER_TOKEN_FILE",
  // Not read by the orchestrator; Docker's own group_add interpolation.
  "_DOCKER_GID",
]);

const orchEnv = services.orchestrator?.environment ?? {};
for (const key of Object.keys(orchEnv)) {
  check(
    ORCH_VARS_ACTUALLY_READ.has(key),
    `orchestrator environment: ${key} is a variable it reads`,
    `orchestrator is given ${key}, which its config never reads — it is silently ` +
      `ignored and the process uses a default instead`,
  );
}

// 9. The api image is stamped with the commit it was built from.
//
// mac's point: `build` on /api/public/version read "dev" on a live deployment with
// a real certificate. It was harmless only because nothing consumed it, which is
// not a property to rely on — the day something branches on it, the string has to
// be trustworthy. Made true instead: the image bakes in the commit.
//
// Asserted here rather than in the Dockerfile because a missing build arg produces
// an image that looks fine and lies, and the Dockerfile cannot check what compose
// passed it.
const apiBuildArgs = cfg.services?.api?.build?.args ?? {};
check(
  typeof apiBuildArgs.BUILD_ID === "string" && apiBuildArgs.BUILD_ID.length > 0,
  `the api image is stamped with BUILD_ID=${apiBuildArgs.BUILD_ID}`,
  "the api image has no BUILD_ID, so it would report itself as a local run",
);

// 10. The api is not root and holds no extra capabilities.
//
// A `USER` directive does not survive `docker compose config` — it lives in the
// image — so this is checked where it is actually true, in the Dockerfile, by CI
// grepping the built image. Here the half that does resolve: no added capabilities.
for (const svc of ["api", "orchestrator", "caddy"]) {
  const added = services[svc]?.cap_add ?? [];
  check(
    (services[svc]?.cap_drop ?? []).includes("ALL"),
    `${svc} drops ALL capabilities`,
    `${svc} does not cap_drop ALL`,
  );

  // Only Caddy legitimately needs one capability, to bind :80 and :443. The api
  // and the orchestrator need none at all.
  //
  // Two separate checks rather than one condition with a `svc !== "caddy" &&`
  // guard: that version short-circuits to true for every service except caddy, so
  // `cap_add: [SYS_ADMIN]` on the api passed. The meta-test in
  // assert-compose.test.mjs is what found it.
  if (svc === "caddy") {
    check(
      added.every((c) => c === "NET_BIND_SERVICE"),
      `caddy adds only NET_BIND_SERVICE (${added.join(",") || "none"})`,
      `caddy adds unexpected capabilities: ${added.join(",")}`,
    );
  } else {
    check(
      added.length === 0,
      `${svc} adds no capabilities`,
      `${svc} adds capabilities it has no use for: ${added.join(",")}`,
    );
  }
}

for (const line of passes) console.log(`  ok    ${line}`);
if (failures.length > 0) {
  console.error("");
  for (const line of failures) console.error(`  FAIL  ${line}`);
  console.error(
    `\n${failures.length} of ${failures.length + passes.length} static capability assertions failed.`,
  );
  process.exit(1);
}
console.log(`\n${passes.length} static capability assertions passed.`);