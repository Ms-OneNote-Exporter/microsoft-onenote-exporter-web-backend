# infra

Caddy, compose, and the host paths. Everything that is not application code.

**Deployed at `https://one-backend.phttp.com`.** For the runbook, the host state and
the two values an operator has to supply, see [`DEPLOYMENT.md`](./DEPLOYMENT.md).

## Topology

```
                    internet
                       │
                  ┌────▼────┐
                  │  Caddy  │  80/443 published — the only service with a port
                  └────┬────┘
             msout-edge │ (single member)
                  ┌────▼─────────────────────┐
                  │ api                      │  no socket, no vault, no bind mount
                  │  SQLite (named volume)   │
                  └────┬─────────────────────┘
        msout-control   │  (internal: true — no route to the internet)
                  ┌────▼────┐
                  │  orch.  │  the ONLY docker socket
                  └─────────┘
                        ╳  no path: the orchestrator and the api are on
                           internal networks only, so a runner cannot reach either
                   ┌────────────────────────────────────────────┐
   internet ──────▶│  runner   msout-runner      (egress: open) │
                   │    │      msout-runner-api  (internal)     │
                   └────┼───────────────────────────────────────┘
                        └──▶ api  (the credential path — nothing back the other way)
```

Four networks, and each exists for a stated reason:

- `msout-edge` — **Caddy alone.** The api and the orchestrator are not on it, so
  "not reachable from outside" is a property of the topology rather than of
  remembering not to publish a port.
- `msout-control` — `internal: true`. Carries Caddy↔`api` and `api`↔`orchestrator`.
  This is the word that matters most in the file: it means these three services
  have **no route to the internet**. A network declared without it still works, so
  nothing else would fail — the orchestrator would simply be able to reach out.
- `msout-runner-api` — `internal: true`, and holds `api` plus the runners. The
  credential path. Internal, so joining it cannot give `api` egress; and the
  orchestrator is **not** on it, so the credential is one hop from the Docker
  socket rather than on it.
- `msout-runner` — **the runner's internet access, deliberately unrestricted.**

## The runner's egress is unrestricted, and that is a decision

A runner may make any outbound call to the internet. There is no allowlist of
Microsoft hosts, and adding one is the change to avoid.

**Why:** an allowlist can only be as current as the last login somebody observed.
Microsoft changes a hostname — a SharePoint tenant, an asset CDN, a regional login
endpoint — and the product breaks with **no signal at all**: no error, no failing
test, just sign-in that stopped working. The observation that mattered is the one
nobody made. Every other property in this stack is asserted rather than
maintained; an allowlist is the one thing here that would have to be maintained,
and it would fail quietly.

**What is still denied**, and none of it is a list:

| target | why it is safe to deny |
|---|---|
| the cloud metadata service (`169.254.169.254`) | Microsoft will never log in through it. It is a path to the *instance's* credentials, not ours |
| the host gateway | same; nothing Microsoft does goes there |
| the Docker socket | only the orchestrator has it, and it is not on the runner's networks |
| `api` and `orchestrator` by name | they are on internal networks the runner's egress net does not route to |

The first two are *topology* on most hosts, and `capability.yml` asserts all four
from inside a running container (T-N9). On an instance type that actually has a
metadata service the topology may not be enough, and that is the one rule worth
adding at the host level — it constrains nothing Microsoft does:

```sh
# Deny the metadata service and the Docker socket to the runner's bridge subnet.
# Find the subnet first:  docker network inspect msout_msout-runner \
#   --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
iptables -I DOCKER-USER -s <subnet> -d 169.254.169.254 -j DROP
iptables -I DOCKER-USER -s <subnet> -d 172.17.0.1 -p tcp --dport 2375 -j DROP
```

Not applied by this repository, because a host firewall rule is not something a
compose file should install and a VPS is the operator's.

**Checked on the VPS on 2026-10-07: neither rule is present.** `DOCKER-USER` holds
only `-j RETURN`, and there is no `msout-runner` network there because the runner
is not deployed on that host — so no window is open, but there is also no rule, and
one must be installed **before** the runner is deployed there.

This was not a theoretical gap. `capability.yml`'s T-N9 was written, run, and
failed: on a real Linux host — GitHub's runner — the metadata service **answers**
from inside a runner container. On the Mac it was developed against, it returned
`ECONNREFUSED`, because Docker Desktop is not a cloud instance and has no metadata
service to refuse. The "topology already handles this" claim was true locally and
false on the platform that matters, which is precisely what the check existed to
catch.

`capability.yml` now installs the metadata rule before asserting, so the assertion
runs against a correctly configured host and a host that lacks the rule fails
honestly rather than silently passing.

**What could and could not be verified here.** The rule installs cleanly and lands
in the right chain — confirmed on the VPS:

```
-A DOCKER-USER -s 172.26.0.0/16 -d 169.254.169.254/32 -j DROP
```

Removing it again leaves `DOCKER-USER` back to just `-j RETURN`. But **the
fail-open half could not be demonstrated on the VPS**, because that host has no
metadata service to reach: the probe is blocked with and without the rule. The
demonstration that the rule is load-bearing is GitHub's runner, where T-N9 went red
without it. Both hosts are now clean — the probe network and container were removed
and the VPS chain restored.

## The host name is written down once

`PUBLIC_HOST` in `.env` is the only place the domain appears. Compose feeds it to
two consumers:

| where | how |
|---|---|
| Caddy | `PUBLIC_HOST: ${PUBLIC_HOST}` → `{$PUBLIC_HOST}` in the Caddyfile |
| api | `PUBLIC_ORIGIN: https://${PUBLIC_HOST}` |

Changing the domain is therefore one edit. Three things must agree, and only the
first lives in this repo:

- `PUBLIC_HOST` — `.env`, here
- `PUBLIC_ORIGIN` — derived above, read by the api
- `VITE_API_ORIGIN` — mac's frontend build; he is told separately

`PUBLIC_HOST` is marked required (`${PUBLIC_HOST:?...}`), so a typo is a startup
failure rather than a deployment on the wrong origin where every artifact download
URL is silently wrong.

## Host paths

```
/srv/msout/vault/<guid>/           auth.json, notebook cache, logs   (orch rw, runner rw)
/srv/msout/artifacts/<artifactId>/ finalised zip, partial marker    (orch rw, caddy ro)
```

Split, not shared. v2 mounted one tree and let Caddy `file_server` it, which meant
Caddy could also read `auth.json` — a live Microsoft cookie jar. Keeping them apart
means the component in the credential path (Caddy) and the component that decides
who may download (`api`) can *neither* read session data. That is a genuine
improvement over v2 and the split is what makes it cheap (§2.2).

## Caddy

- TLS, HSTS, **no body logging anywhere** — the global `log` block discards, and
  the credential route's body *is* the Microsoft password.
- `/files/*` → `forward_auth` to `api`, then `file_server` with `sendfile` and
  `Range`. Multi-gigabyte downloads never pass through Node.
- Downloads are `GET /files/<artifactId>` where the id is
  `crypto.randomBytes(32)` → base64url. **No GUID and no notebook name in any
  URL.** v2 leaked the GUID into Caddy access logs and the notebook name into any
  `Referer`.
- **Served on the api's origin, not the frontend's, and that is load-bearing.**
  The session cookie is `__Host-msout`; the `__Host-` prefix forbids a `Domain`
  attribute, so the browser only sends it to the api's host. A relative
  `/files/<id>` would resolve against the frontend's origin where the cookie
  cannot travel, and `forward_auth` would see no `Cookie` header and refuse every
  download. `SameSite=None` does not help: SameSite governs site, not host.
- `forward_auth` hits `/internal/authorize-download`, which is an ordinary
  authenticated GET — it needed no auth exemption, because the hook in `server.ts`
  already requires a session cookie for GETs. Caddy never routes `/internal/*` to
  the api, so it is not reachable from outside.
- **Partial labelling is server-enforced**: the api answers the `forward_auth`
  subrequest with `X-Artifact-Partial: 1` and Caddy copies it onto the download.
  The `.partial.zip` filename suffix is the client's half (`artifact.fileName` in
  the snapshot, used as the `download` attribute) — that split is stated rather
  than papered over with a placeholder trick that would produce a worse filename.

## Client IP

Caddy sets `X-Forwarded-For` itself; the api takes the **rightmost** entry — the
address Caddy actually saw. It never takes the leftmost and never trusts a bare
`X-Real-IP`. Stripping inbound headers would be correct but brittle, because it is
one Caddy directive a future edit can silently drop.

## What is verified, and how

| checked | by |
|---|---|
| the compose file parses and resolves | `docker compose config` — no daemon needed |
| `PUBLIC_HOST` is genuinely required | asserting the guard fails when empty |
| 24 static capability assertions | `.github/assert-compose.mjs` |
| the assertions can actually fail | `.github/assert-compose.test.mjs` |
| `node:sqlite` loads unflagged in the image | smoke test, in `api` CI |
| `dist/` contains no mock code | grep, in `api` CI |

The meta-test earns its place. It found two real defects in the assertions
themselves: the socket check matched a mount's **target** rather than its source,
so repointing the source passed; and the capability check short-circuited on
`svc !== "caddy"`, so `cap_add: [SYS_ADMIN]` on the api passed. A static check that
silently checks the wrong half of a thing is worse than none, because it reads as
coverage.

## Verified against running containers

`.github/workflows/capability.yml` brings the stack up and asserts §2.1's claims
against **running containers**, not against the compose file. It runs on every pull
request.

| assertion | what it proves |
|---|---|
| **T-X1** | the api sees no host path but its own writable volume |
| **T-X2** | only the orchestrator holds the Docker socket |
| **T-N1** | the control network cannot resolve DNS, let alone reach the internet |
| **T-N4** | the api cannot fetch an external URL |
| **T-P\*** | only Caddy publishes a port |
| **T-C7** | `/files/` never reaches Node |
| — | no service carries a secret inline; the api's is a path |
| — | nothing logs a request header (`.github/check-no-header-logging.sh`) |

| also checked | by |
|---|---|
| the compose file parses and resolves | `docker compose config` — no daemon needed |
| `PUBLIC_HOST` is genuinely required | asserting the guard fails when empty |
| 29 static capability assertions | `.github/assert-compose.mjs` |
| those assertions can actually fail | `.github/assert-compose.test.mjs` — 18 violations |
| `node:sqlite` loads unflagged in the image | smoke test, in `api` CI |
| `dist/` contains no mock code | grep, in `api` CI |

The meta-test earns its place. It found four real defects in the assertions
themselves: the socket check matched a mount's **target** rather than its source, so
repointing the source passed; the capability check short-circuited on
`svc !== "caddy"`, so `cap_add: [SYS_ADMIN]` on the api passed; an orphaned network
check never fired; and five exec-based assertions passed *vacuously* because a
container that never started returns non-zero. **A static check that silently checks
the wrong half of a thing is worse than none, because it reads as coverage.**

## This has been deployed

It runs at `https://one-backend.phttp.com` with a real Let's Encrypt certificate.
See `infra/DEPLOYMENT.md` for the runbook, the VPS state, and the two things an
operator has to supply (`PUBLIC_HOST` and a real `ACME_EMAIL`).

Nine of the bugs fixed during deployment were **config bugs, not logic bugs** — a
`CMD` naming a file that did not exist, a healthcheck naming a flag that did not
exist, a Dockerfile that did not parse, a secret variable in the api's namespace
given to the orchestrator, two more variables in the wrong namespace, a missing
docker group, a volume the container could not write to, a Caddy directive that does
not exist, and a global `ARG` used without being re-declared in its stage.

Every one was found by something executing the deployment. None was found by a test,
a static assertion, or a read of the file.

## What is deployed, and what is not

The runner **is** built and runs (`runner/`, behind `--profile runner`), and the
api calls it — the four runner-facing routes are wired. It is started by the
orchestrator per session in production rather than by compose, so `docker compose
up` without the profile does not start one; that is deliberate, because a runner
holds one session's credential and two of them in one compose project would share a
data root.

**Not deployed:** the host-level rules in the egress table above. They are a
firewall configuration, not a compose file, and a VPS is the operator's — so they
are documented rather than installed. T-N9 asserts the topology from inside a
container, which covers the targets that topology already blocks on this host.
