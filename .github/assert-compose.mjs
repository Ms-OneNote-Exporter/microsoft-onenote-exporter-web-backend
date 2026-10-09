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
// The vault and artifact roots are bind-mount **sources**, which the Engine resolves
// on the **host** — a different kind of setting from every other path in this file,
// and one that breaks in a way nothing else here can see.
//
// What shipped, in two forms:
//
//   1. as a **named volume** at `/srv/msout/vault`. On the host that path is
//      `/var/lib/docker/volumes/msout_vault/_data`, so `/srv/msout/vault` named an
//      empty root-owned directory that Docker created and nothing wrote to. Every
//      runner got it as `/data` and could not create its session directory:
//
//          EACCES: permission denied, mkdir '/data/<guid>'
//
//   2. with **no volume at all**, the vault lived in the container's writable layer,
//      so one `--force-recreate orchestrator` deleted every session's auth.json and
//      exported vault — with nothing failing and nothing reporting it.
//
// So the assertion is the property both fixes depend on: the path the orchestrator
// hands the Engine must be **the same absolute path** the orchestrator itself has
// mounted. Then it is unambiguous on both sides of the container boundary.
//
// Docker's volume-seeding behaviour is deliberately *not* asserted. It was the
// right mechanism for a named volume and it worked — ownership came out `65532`, as
// intended. It was simply the wrong mechanism for a path that has to survive as a
// string and be resolved on the other side of the boundary.
for (const [envVar, role] of [
  ["ORCH_VAULT_ROOT", "session vault"],
  ["ORCH_ARTIFACT_ROOT", "finalized exports"],
]) {
  const root = services.orchestrator?.environment?.[envVar];

  check(
    typeof root === "string" && root.startsWith("/"),
    `orchestrator: ${envVar} is an absolute path`,
    `orchestrator ${envVar} is ${JSON.stringify(root)}. It is the *source* of a bind ` +
      `mount, so a relative path either cannot be resolved by the Engine or resolves ` +
      `against a working directory nobody chose`,
  );

  check(
    root !== undefined &&
      (services.orchestrator?.volumes ?? []).some(
        (v) => (typeof v === "string" ? v : v?.target) === root,
      ),
    `orchestrator: mounts the ${role} at ${root}, the same path it hands the Engine`,
    `orchestrator ${envVar} is ${JSON.stringify(root)} but nothing is mounted there. A ` +
      `bind source is resolved on the *host*: if that path only exists inside this ` +
      `container, the Engine creates an empty root-owned directory there and every ` +
      `runner mounts a directory nobody writes to (\`EACCES: mkdir '/data/<guid>'\`)`,
  );
}

// The vault must not be mounted anywhere else. §2.1 forbids the api from reading a
// cookie jar, and it forbids Caddy reading a vault path.
const vaultRoot = services.orchestrator?.environment?.ORCH_VAULT_ROOT;
for (const svc of ["api", "caddy"]) {
  check(
    typeof vaultRoot !== "string" ||
      !(services[svc]?.volumes ?? []).some(
        (v) => (typeof v === "string" ? v : v?.target) === vaultRoot,
      ),
    `${svc} has no vault mount`,
    `${svc} mounts ${vaultRoot}; §2.1 requires that only the orchestrator and the ` +
      `runners it creates can read a vault`,
  );
}

// ORCH_RUNNER_TOKEN_FILE must be a **host** path, not the container path the
// orchestrator mounts the secret at.
//
// The previous assertion here checked that it equalled
// `/run/secrets/runner_token` — the orchestrator's own mount point — and passed.
// It was checking the wrong thing: this value is used as the **source** of a bind
// when creating each runner, and a bind source is resolved on the host. On a host
// where that path does not exist, Docker creates a directory there, the runner
// mounts a directory over its own secret path, and exits 1:
//
//   MSOUT_RUNNER_TOKEN_FILE could not be read at /run/secrets/runner_token: ENOENT
//
// Every container started and `/healthz` said `ok`; it surfaced only on the first
// real login. So the assertion is that the path lives **under SECRETS_DIR**, which
// is where the `secrets:` block actually reads from.
const secretsDir = cfg.secrets?.runner_token?.file?.slice(0, -"/runner_token".length);
const tokenHostFile = services.orchestrator?.environment?.ORCH_RUNNER_TOKEN_FILE;
check(
  secretsDir !== undefined &&
    tokenHostFile !== undefined &&
    tokenHostFile.startsWith(secretsDir) &&
    tokenHostFile.endsWith("/runner_token"),
  "orchestrator: ORCH_RUNNER_TOKEN_FILE is the HOST path of the token",
  `orchestrator ORCH_RUNNER_TOKEN_FILE is ${JSON.stringify(tokenHostFile)} but the ` +
    `runner_token secret is read from ${JSON.stringify(
      cfg.secrets?.runner_token?.file,
    )}. This value is the *source* of a bind mount, so it must resolve on the host; ` +
    `a container path makes Docker create a directory there and every runner exits 1`,
);
// The orchestrator must create runners from **the image this stack runs**, not from
// some other image that happens to share a name.
//
// `ORCH_RUNNER_IMAGE` comes from the operator's `RUNNER_IMAGE`, and the `runner`
// service's `image:` comes from `${IMAGE_TAG:-local}`. Two independent names for one
// image, and nothing compared them.
//
// It cost a whole afternoon of "the rebuild did nothing": the deployment's `.env` had
//
//     RUNNER_IMAGE=ghcr.io/ms-onenote-exporter/msout-runner:<sha>     # one "one"
//
// while compose builds
//
//     ghcr.io/ms-one-note-exporter/msout-runner:<sha>                # two
//
// — a hyphen short. Every rebuild succeeded and went to a *different repository*, and
// the orchestrator went on creating runners from a 15-hour-old image under the wrong
// name. Nothing failed. `docker images` showed a fresh build, so the only symptom was
// that the code in the container never changed.
//
// The canonical name is the lowercased repository owner, which is what `publish.yml`
// writes to `REGISTRY_PREFIX`; these lines use that spelling literally.
const runnerImage = services.runner?.image;
const orchRunnerImage = services.orchestrator?.environment?.ORCH_RUNNER_IMAGE;
check(
  runnerImage !== undefined && runnerImage === orchRunnerImage,
  `orchestrator creates runners from the image the stack runs (${runnerImage})`,
  `the runner service runs ${JSON.stringify(runnerImage)} but the orchestrator creates ` +
    `runners from ${JSON.stringify(orchRunnerImage)}. The two names are set independently ` +
    `— \`image: \${IMAGE_TAG}\` and the operator's RUNNER_IMAGE — and nothing compared them. ` +
    `A rebuild then lands in a different repository while the orchestrator keeps using ` +
    `a stale image, and the only symptom is that the code in the container never changes. ` +
    `The canonical prefix is the lowercased repository owner, as publish.yml sets it`,
);

// The orchestrator and the runner must run as the **same uid**, because they share
// `/srv/msout/data`: the orchestrator creates a session's vault directory, the runner
// writes `auth.json` and the exported notes into it, and the orchestrator sweeps it.
//
// They did not. `nonroot` is 65532 and the runner's `node` is 1000, so every login
// failed from a container the orchestrator had just created, with a correct mount and a
// correct path:
//
//     EACCES: permission denied, mkdir '/data/<guid>'
//
// The orchestrator moved to 1000 rather than the runner, because the runner's uid is
// what Chromium's sandbox runs as. The assertion reads both Dockerfiles, so this is a
// comparison rather than two literals that can drift.
//
// Both are read as text because that is all a static check can do — and it is exactly
// enough, since the failure mode is two files naming one identity independently.
function declaredUid(dockerfile) {
  const match = dockerfile.match(/^USER\s+(\S+)/m);
  if (match === null) return undefined;
  const raw = match[1].split(":")[0];
  // Named users (`node`, `nonroot`) are resolved by the base image, so only a numeric
  // one can be compared. A named uid here means the check cannot do its job, and says
  // so rather than passing.
  return /^\d+$/.test(raw) ? Number(raw) : raw;
}

const orchestratorUid = declaredUid(
  readFileSync(new URL("../orchestrator/Dockerfile", import.meta.url), "utf8"),
);
const runnerUid = declaredUid(
  readFileSync(new URL("../runner/Dockerfile", import.meta.url), "utf8"),
);

check(
  typeof orchestratorUid === "number" && orchestratorUid === runnerUid,
  `orchestrator and runner share uid ${orchestratorUid}`,
  `the orchestrator runs as ${JSON.stringify(orchestratorUid)} and the runner as ` +
    `${JSON.stringify(runnerUid)}. They share /srv/msout/data — the orchestrator creates ` +
    `a session's vault directory and the runner writes into it — so a mismatch means ` +
    `every login fails with \`EACCES: permission denied, mkdir '/data/<guid>'\`, from a ` +
    `container the orchestrator had just created. Both must be numeric so this can be ` +
    `compared at all`,
);

// The runner takes no host path at all.
//
// Not "no host path of its own choosing" — **none**. The runner holds the Microsoft
// credential and is the only component pointed at the open internet, so it gets its
// data and its artifacts as named volumes and its token as a Docker secret, and
// nothing else.
//
// This is asserted against the compose `runner` service, which is the *development*
// runner: nothing creates it through the orchestrator, so no grants are in play and
// the full property is available. An orchestrator-created runner cannot have it — the
// orchestrator binds that one the per-session vault and the artifact root, because
// artifacts must leave the container and the vault must persist. T-X-R2 in
// `capability.yml` asserts the same property against a running container.
//
// The temptation this guards against: pointing the dev runner at
// `ARTIFACT_HOST_DIR` "so both runners share an artifacts directory". That is a
// convenience, and it costs the only assertion about the runner's mounts on a real
// container. It was tried, and reverted.
const runnerBinds = bindsFor("runner").map((v) => String(v.source));
check(
  runnerBinds.every((src) => src.endsWith("runner_token")),
  `runner bind-mounts only its token (${runnerBinds.join(", ") || "none"})`,
  `runner bind-mounts something unexpected: ${runnerBinds.join(", ")}. §2.1 gives it no host ` +
    `path — its data root and its artifact root are named volumes, and the only bind ` +
    `allowed is its own secret file`,
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

// The runner publishes no port. The api reaches it by container alias on
// msout-runner-api; a published port would make it an API on the internet.
check(
  (services.runner?.ports ?? []).length === 0,
  "runner publishes no port",
  `runner publishes ${JSON.stringify(services.runner?.ports ?? [])}`,
);

// The api's `environment:` is an ALLOWLIST, not a passthrough.
//
// Every variable the api reads has to be named in that block, because a variable
// in `.env` that is not listed here never reaches the process. The api then reads
// its own compiled-in default while the operator believes the change took effect,
// and nothing reports it — the configuration is a claim and nothing checks it.
//
// This has already produced "a configuration the process never read" twice in this
// stack, so the variables that exist to be tuned per-deployment are asserted
// rather than trusted. `RATE_LIMIT_SESSIONS_PER_HOUR` is the first of them: it was
// added with a default and an `.env` entry, and would have been silently ignored
// without this line.
const TUNABLE_API_ENV = ["RATE_LIMIT_SESSIONS_PER_HOUR"];
const apiEnv = services.api?.environment ?? {};
for (const key of TUNABLE_API_ENV) {
  check(
    key in apiEnv,
    `api environment names ${key}`,
    `FAIL: the api's environment block omits ${key}. That block is an allowlist — a ` +
      `variable in .env that is not named there never reaches the process, so the ` +
      `operator would set it and the api would keep using its compiled-in default, ` +
      `reporting nothing`,
  );
}

// The api can authenticate to a runner, which means it holds the same token.
//
// Without the mount the api has no token to present, so every credential
// submission is refused with 401 — and the failure reads as "the runner rejected
// the password", which sends an operator looking at the wrong component. This
// binds the assertion to the mount, as the orchestrator's is bound above, so
// dropping one without the other fails here instead of in production.
const apiSecrets = (services.api?.secrets ?? []).map((s) => s.source);
check(
  apiSecrets.includes("runner_token"),
  "the api holds runner_token, to authenticate to a runner",
  `the api's secrets are [${apiSecrets.join(", ")}]. It calls a runner's HTTP API, so ` +
    "without this every credential submission is refused 401",
);
check(
  services.api?.environment?.RUNNER_TOKEN_FILE === "/run/secrets/runner_token",
  "api: RUNNER_TOKEN_FILE points at the mounted secret",
  `api RUNNER_TOKEN_FILE is ${JSON.stringify(services.api?.environment?.RUNNER_TOKEN_FILE)}; ` +
    "it must name the path the token is mounted at, or the file is never read",
);
// The path, never the value — the same rule the other two secrets follow here.
for (const key of ["RUNNER_TOKEN", "CSRF_KEY", "SESSION_SECRET"]) {
  check(
    !(key in (services.api?.environment ?? {})),
    `api environment has no ${key}`,
    `api environment carries ${key} as a value. Secrets travel as file paths: an env ` +
      "var is visible in docker inspect",
  );
}

// ...and it is on exactly two networks: egress for Microsoft, and an internal one
// whose only other member is `api`.
//
// The set is the assertion, not the count. `msout-runner` is where the runner
// reaches login.microsoft.com; `msout-runner-api` is how the credential gets to
// it without giving `api` egress. Being on `msout-control` instead would put it
// where the orchestrator lives, one compromise away from the Docker socket —
// that is the member this check refuses.
const runnerNetworks = Object.keys(services.runner?.networks ?? {});
const wantRunnerNetworks = ["msout-runner", "msout-runner-api"];
check(
  runnerNetworks.length === wantRunnerNetworks.length &&
    wantRunnerNetworks.every((n) => runnerNetworks.includes(n)),
  `runner is on egress + credential-path networks only (found: [${runnerNetworks}])`,
  `runner is on [${runnerNetworks}]; expected exactly [${wantRunnerNetworks}] — it must ` +
    `not join msout-control, which is where the orchestrator's socket lives`,
);

// The credential-path network must be internal, and that is the whole reason it
// exists. A non-internal network gives `api` a default route, so the api would
// reach the internet — §2.1's prohibition, and a deployment that otherwise works.
check(
  cfg.networks?.["msout-runner-api"]?.internal === true,
  "msout-runner-api has internal: true (api gains a route to runners, not egress)",
  "FAIL: msout-runner-api is missing `internal: true`. The api would join it with " +
    "egress, which is what PLAN-v3 §2.1 forbids — put the api on msout-runner instead",
);

// And it must hold the api and the runners, and nothing else. The orchestrator on
// it would put the credential path and the Docker socket on one network.
const onRunnerApi = Object.entries(services)
  .filter(([, def]) => Object.keys(def.networks ?? {}).includes("msout-runner-api"))
  .map(([name]) => name)
  .sort();
check(
  onRunnerApi.length === 2 && onRunnerApi.includes("api") && onRunnerApi.includes("runner"),
  `msout-runner-api holds api and runner only (found: [${onRunnerApi}])`,
  `msout-runner-api holds [${onRunnerApi}]; expected exactly [api, runner]. The ` +
    `orchestrator must not be on the credential path`,
);

// The api must be on the credential-path network, or it cannot hand over a
// credential at all — and the symptom would be a 501 rather than a config error,
// which is what this check exists to prevent.
check(
  Object.keys(services.api?.networks ?? {}).includes("msout-runner-api"),
  "api is on msout-runner-api",
  "FAIL: the api is not on msout-runner-api, so it has no route to a runner and " +
    "every credential submission would fail",
);

// The two runner networks must exist under the names the orchestrator asks for.
//
// Compose prefixes a network with the project name — `msout_msout-runner` — while
// `ORCH_RUNNER_NETWORK` names it `msout-runner`. The orchestrator builds its create
// request by name, so a mismatch means it asks the Engine for a network that does
// not exist and every slot fails with `404 network not found`.
//
// CI could not see it: in the capability suite compose creates the runner, so the
// orchestrator's create path never runs. The first real deployment failed on it.
// `name:` on the network is what makes the two agree by construction; this asserts
// they do.
for (const [network, envVar] of [
  ["msout-runner", "ORCH_RUNNER_NETWORK"],
  ["msout-runner-api", "ORCH_RUNNER_CONTROL_NETWORK"],
]) {
  check(
    cfg.networks?.[network]?.name === network,
    `${network} exists under its own name`,
    `${network} would be created as "<project>_${network}" by Compose, but the ` +
      `orchestrator asks for "${network}" by name (${envVar}). Add \`name: ${network}\` ` +
      `under it, or every runner create fails with "network not found" — and CI cannot ` +
      `see it, because the capability suite creates the runner through Compose`,
  );
}

// `msout-runner` must be `external`, and it is the only network that can be.
//
// Compose prunes a network no **non-profile** service joins, and the only service that
// joins this one is the `runner` service, which sits behind a profile. So a plain
// `docker compose up` creates it and then removes it, and the orchestrator — which asks
// the Engine for it by name — gets:
//
//     404 {"message":"network msout-runner not found"}
//
// There is no compose expression for "keep a network nothing joins", so it is declared
// operator-provided. Without `external: true` this check cannot be made at all,
// because Compose's own error when the network already exists is:
//
//     network msout-runner was found but has incorrect label
//     com.docker.compose.network set to "" (expected: "msout-runner")
//
// — which is a deploy step failing, not an assertion.
check(
  cfg.networks?.["msout-runner"]?.external === true,
  "msout-runner is external, so Compose cannot prune the network nothing joins",
  `msout-runner is not external. Compose prunes any network no non-profile service ` +
    `joins, and the only service that joins this one is behind the runner profile — so ` +
    `a plain \`docker compose up\` creates it and deletes it, and the orchestrator's ` +
    `first runner create fails with "network msout-runner not found". Create it first ` +
    `(docker network create --driver bridge msout-runner) and mark it external. ` +
    `\`capability.yml\` does this`,
);

// The api must not be on the egress network. This is the error the whole
// three-network arrangement is built to make impossible, and it would deploy
// cleanly.
check(
  !Object.keys(services.api?.networks ?? {}).includes("msout-runner"),
  "api is not on the egress network",
  "FAIL: the api is on msout-runner, which has egress. PLAN-v3 §2.1 says the api " +
    "has no route to the internet; remove it and use msout-runner-api instead",
);

// The runner's egress network must be UNRESTRICTED.
//
// The opposite assertion to the ones above, and deliberately so. A runner has to
// be able to log in wherever Microsoft decides to host the login, because an
// allowlist fails *silently* the day Microsoft changes a hostname — no error, no
// failing test, just sign-in that stopped working. That is a worse failure than
// one extra host being reachable.
//
// So this asserts the network is a plain bridge with no policy attached, rather
// than asserting a list of permitted hosts. It also would not be possible to
// assert such a list here: compose cannot enforce one, which is the whole reason
// the choice is unrestricted egress plus topology-based denies.
//
// The denies are asserted in capability.yml against running containers (T-N9),
// because the ones that matter — the metadata service, the host gateway — are
// properties of the host's routing rather than of this file.
check(
  !("internal" in (cfg.networks?.["msout-runner"] ?? {})),
  "msout-runner has egress (not internal)",
  "FAIL: msout-runner is internal, so a runner cannot reach the internet and every " +
    "login will fail. Do not fix this with an allowlist — see the comment on this " +
    "network in docker-compose.yml",
);

// ...and not on the orchestrator's network either, for the same reason: it would
// be a step from the api to the only process holding the Docker socket.
check(
  !Object.keys(services.runner?.networks ?? {}).includes("msout-control"),
  "runner is not on msout-control",
  "FAIL: the runner is on msout-control, which is where the orchestrator lives. The " +
    "credential path and the socket must not share a network",
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

// 3c. Caddy takes no host path but two, and no socket.
//
// One is the read-only Caddyfile, which compose renders as a bind; everything else
// it needs is a named volume. The other is the artifact root, which §2.2 requires
// Caddy to have **read-only** — it serves the archives and makes no authorisation
// decision, so it needs to see them and nothing more.
//
// The second one was added late and **the assertion caught it**: the capability
// suite went red on a compose file whose change was deliberate, which is what it is
// for. An allowlist that nobody widens when a control legitimately grows is an
// allowlist that gets deleted the first time it is inconvenient.
const caddyBinds = bindsFor("caddy").map((v) => v.source);
// Compared against `ARTIFACT_HOST_DIR` rather than a literal like "artifacts/",
// because the two environments that run this disagree about it: CI stages at
// `/srv/msout/artifacts-host`, the deployed host at `/opt/msout/data/artifacts`.
// A hardcoded suffix passes CI and is wrong everywhere else — "green because the
// fixture happened to be right", which is the failure this file exists to catch.
const artifactRoot = `${process.env.ARTIFACT_HOST_DIR}/`;
const caddyUnexpected = caddyBinds.filter(
  (src) => !src.endsWith("Caddyfile") && src !== artifactRoot,
);
check(
  caddyUnexpected.length === 0,
  `caddy bind-mounts only its config and the artifact root (${caddyBinds.join(", ") || "none"})`,
  `caddy bind-mounts something unexpected: ${caddyUnexpected.join(", ")}`,
);

// The artifact mount must be **read-only**, asserted rather than reviewed.
//
// A writable artifact tree is worse than no artifact tree: the orchestrator
// publishes by renaming a staging directory into place, and a Caddy that can write
// can replace an archive a user is part-way through downloading. `compose config`
// reports this as `read_only` on the mount.
const caddyArtifactMount = bindsFor("caddy").find((v) => String(v.source) === artifactRoot);
check(
  caddyArtifactMount !== undefined && caddyArtifactMount.read_only === true,
  "caddy's artifact mount is read-only",
  caddyArtifactMount === undefined
    ? "caddy has no artifact mount at all. /files/* would 404 for every user: the file " +
      "server's root would not exist inside the container, which is exactly what " +
      "happened on 2026-10-09 for a deployment that looked entirely healthy"
    : `caddy's artifact mount is WRITABLE (read_only: ${caddyArtifactMount.read_only}). ` +
      "Caddy only serves archives; the orchestrator publishes them",
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

// 6. The api is told which proxies it may believe.
//
// This exists because the value could not be set at all before, and the empty
// default behind a reverse proxy is not a safe default - it is a **global** rate
// limit. Observed on the live host: Caddy at 172.24.0.4 was the only address the
// limiter ever saw, so three sessions an hour were shared by every caller on the
// internet, and every request logged `"remoteAddress":"172.24.0.4"`.
//
// These assertions read the **rendered** config, so they see the substituted value
// and not the `${API_TRUSTED_PROXIES:?...}` expression. That the expression *refuses*
// when unset is checked separately by running `config --quiet` without it - see
// `assert-compose.test.mjs`, because a rendered value cannot show whether a default
// exists behind it.
const trustedProxies = String(services.api?.environment?.API_TRUSTED_PROXIES ?? "");
check(
  trustedProxies !== "",
  "api declares API_TRUSTED_PROXIES",
  "api does not set API_TRUSTED_PROXIES; every caller will be rate-limited as the proxy",
);
check(
  trustedProxies.includes("/"),
  `api's API_TRUSTED_PROXIES is a network (${trustedProxies})`,
  `api's API_TRUSTED_PROXIES is "${trustedProxies}", a single address; it expires on ` +
    `the next recreate and then silently becomes a global limit again`,
);

// There is deliberately **no** assertion here that the trusted network is one Caddy is
// actually on. It cannot be made from the file: Docker assigns subnets at `network
// create`, so `msout_msout-control` is `172.24.0.0/16` on one host and something else on
// the next. A check written against a literal subnet would pass here and be wrong
// elsewhere, which is the same failure as the `RUNNER_IMAGE` repository-name one.
//
// So it is checked where it can honestly be: `API_TRUSTED_PROXIES` uses `${VAR:?}` and
// therefore refuses to render unset (asserted by running `config --quiet` without it, in
// `assert-compose.test.mjs`), and `.env.example` gives the `docker network inspect`
// command that finds the right value. What the api then does with it is visible in the
// api log, which records the address and source whenever a limit is charged.

// 7. Secrets arrive as file paths, never as values.
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
  //
  // **`ORCH_RUNNER_TOKEN_FILE` is the exception, and it is a real one.** It is the
  // *source* of a bind mount when the orchestrator creates each runner, and a bind
  // source is resolved on the **host** — so it must be a host path under
  // SECRETS_DIR, not `/run/secrets/...`. It was `/run/secrets/runner_token` until a
  // deployment created a runner for the first time and every runner exited 1,
  // because Docker had created a directory at a host path that did not exist.
  //
  // It is asserted separately and correctly above; excluding it here is what keeps
  // that assertion from being contradicted by this generic rule.
  for (const [key, value] of Object.entries(env)) {
    if (!key.endsWith("_FILE")) continue;
    if (svc === "orchestrator" && key === "ORCH_RUNNER_TOKEN_FILE") continue;
    check(
      typeof value === "string" && value.startsWith("/run/secrets/"),
      `${svc}: ${key} points into /run/secrets`,
      `${svc}: ${key} is "${value}", which is not a /run/secrets path`,
    );
  }
}

// 8. Each service names the secret variable its own code actually reads.
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

// 9. Every variable given to the orchestrator is one it actually reads.
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
  // A runner's CPU allowance, in billionths of a core. Exists because a hardcoded
  // 2e9 made the orchestrator unable to create any container on a host with fewer
  // than two cores — found by deploying to a 1-CPU VPS, where the pool stayed empty
  // and the api reported it as "every session is busy".
  "ORCH_RUNNER_NANO_CPUS",
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

// 10. The api image is stamped with the commit it was built from.
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