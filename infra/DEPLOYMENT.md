# DEPLOYMENT

Runbook for the deployment at `https://one-backend.phttp.com`.

Written after the fact, which is its weakness: it records what was actually done
rather than what was planned, so the steps here are the ones that worked. Where a
step was wrong the first time, it says so.

## The short version

```bash
git archive --format=tar.gz -o msout.tar.gz HEAD      # no .git, no node_modules
scp msout.tar.gz root@<host>:/root/
SHA=$(git rev-parse HEAD)                              # here, where git exists
ssh root@<host>
  cd /opt/msout && tar xzf /root/msout.tar.gz --exclude=.env --exclude=secrets && rm /root/msout.tar.gz
  sed -i "s|^IMAGE_TAG=.*|IMAGE_TAG=$SHA|" .env        # REQUIRED — see below
  docker compose config --quiet            # refuses rather than defaulting
  set -a && . ./.env && set +a            # compose interpolates at read time
  docker compose --profile runner build api orchestrator runner
  docker compose --profile runner up -d --wait
  ./infra/verify-deploy.sh "$SHA"         # proves the running stack is that commit
```

There is no git clone. The repository is private and putting a deploy key on the
host for one component's build is a credential to manage for no benefit — a tarball
of a known commit is the same artefact with nothing extra to revoke.

**The cost is that `git rev-parse` does not work on the host, so `IMAGE_TAG` must
be passed in — and forgetting to is silent.** See "Stamp the tag you are deploying"
below, which is the failure this cost produced.

### Stamp the tag you are deploying

`docker compose build` rebuilds the images from the source tree **that is on the
host**, and tags them with whatever `IMAGE_TAG` says in `.env`. Those are two
independent facts and nothing connects them. Rebuild today's source under last
month's tag and the image is new, the label is old, and every signal agrees with
the label — because all of them read it.

This is not hypothetical. On 2026-10-08 the host was serving `1f555a3` while
`docker ps`, `docker images` and the api's own `/healthz.build` all named
`305c56c`, nine commits earlier. The content was current, which is the worst case:
the tag was the only thing wrong, so nothing looked wrong.

`docker compose config --quiet` does not catch it. That refuses an **unset**
variable, and this tag was set — to a commit nine commits old. A value that is
present and wrong satisfies every guard that only checks presence.

So the tag is **verified**, not trusted:

```bash
./infra/verify-deploy.sh "$SHA"
```

It asks each running component what it is — the api over `/healthz`, Docker for the
orchestrator's image reference — and compares that to the commit you deployed. It
exits non-zero on the first disagreement, naming both values.

## Host state

| | |
|---|---|
| OS | Debian 13 (trixie), x86_64 |
| Docker | 26.1.5 from Debian's own repo |
| Compose | v2.39.1, plugin binary in `/usr/local/lib/docker/cli-plugins/` |
| Docker group GID | discover with `getent group docker \\| cut -d: -f3` |
| install root | `/opt/msout` |
| secrets | `/opt/msout/secrets`, mode `0700`, files `0444` |
| TLS | Let's Encrypt, via Caddy's ACME; `ACME_EMAIL` decides where expiry notices go |

`docker-compose-v2` is **not** in Debian trixie. The Compose plugin is a binary from
the Docker GitHub release, installed to the CLI-plugins directory.

### Why the secret files are `0444` inside a `0700` directory

Compose bind-mounts a `file:` secret as-is and cannot apply `uid`/`gid`/`mode`
outside swarm. A `0400` root-owned file is therefore unreadable by a container
running as any other uid — the api as `node` (1000), the orchestrator as distroless
`nonroot` (65532). So the *directory* is `0700`, which keeps it unreadable for every
other user on the host, and the *file* is world-readable so the containers can read
it through the mount.

The first deploy used `0400` and the api died on a permission error that had nothing
to do with the code.

### `_DOCKER_GID`

The orchestrator image runs as uid 65532 and the host's socket is `root:docker`
mode `0660`, so it needs the docker group. `group_add: ${_DOCKER_GID}` rather than
`USER root`, because running as root would work and would throw away the reason the
orchestrator is a separate component at all.

It is a **required** variable, so a missing one is a startup refusal rather than an
opaque "permission denied" from inside the container.

## What an operator has to supply

```bash
PUBLIC_HOST=one-backend.phttp.com     # required
ACME_EMAIL=<a real address>           # required — currently a guess
ALLOWED_ORIGINS=https://microsoft-onenote-exporter.phttp.com
SECRETS_DIR=./secrets
POOL_SIZE=2
IMAGE_TAG=<the commit>
_DOCKER_GID=<getent group docker | cut -d: -f3>
```

Generate the secrets **on the host**, never locally and never through a deploy:

```bash
mkdir -p secrets && chmod 700 secrets && umask 077
for f in csrf_key orchestrator_hmac_secret; do
  head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' | cut -c1-43 > "secrets/$f"
done
chmod 0444 secrets/*
```

43 base64url characters is 32 bytes unpadded, which is the shape both components
validate. The value never appears in `.env`, in a log line, or in this file.

## Verifying a deploy

`docker compose config --quiet` before anything starts — it refuses on a missing
required variable rather than defaulting.

Then, in order, because each one has caught a real bug:

```bash
docker compose ps                       # all three running, healthchecks passing
./infra/verify-deploy.sh "$SHA"         # the running stack IS the commit you deployed
curl -s https://$PUBLIC_HOST/api/public/version
#   expect {"protocol":3,"build":"<the commit you deployed>"}
```

`verify-deploy.sh` is the load-bearing one and the curl is a cross-check. `build`
must be a commit, not `dev` or `local` — it is baked in from `IMAGE_TAG` — and
`verify-deploy.sh` is what proves `IMAGE_TAG` described the tree that was actually
built, which `build` alone cannot: both are derived from the same variable, so
agreeing with each other says nothing about either. See "Stamp the tag you are
deploying".

CORS, cookies and the SSE headers are the things that only a browser proves. mac
found two bugs in this stack that curl could not see, so treat a green curl as
necessary and not sufficient.

## The four routes that answer 501

`POST /api/session/credential`, `/api/session/notebooks`, `/api/export` and
`/api/session/erase`. They need a runner, and the runner needs `@msout/*` packages
that are not published (§12 steps 1–2).

A 501 here is the correct answer, not a misconfiguration. `credential` and `erase`
return it; `notebooks` and `export` return **409** first, because they check
authentication before the runner exists.

## Redeploying safely

The api is stateless across restarts — the SQLite database is a named volume, and
SSE state is in memory and per-process. So a restart drops live event streams, which
clients reconnect to with `Last-Event-ID`. Nothing else needs care.

```bash
docker compose up -d --wait       # recreates what changed
docker image prune -f             # each build leaves the previous tag behind
```

Do **not** `docker compose down -v` casually: `-v` deletes the named volumes, and
`api-data` holds every session and the artifact mapping.

## What deploying found

Nine config bugs, none of them logic errors. Every component behaved correctly and
disagreed with the config:

1. a `CMD` naming a file that did not exist — the image built and died
2. a healthcheck naming a flag that did not exist — it started a second orchestrator
3. a Dockerfile whose multi-line `RUN` string did not parse
4. the orchestrator given the **api's** secret variable name
5. two more variables in the wrong namespace, silently ignored
6. a missing docker group, so the socket was unreachable
7. a volume the container could not write to
8. a Caddy directive that does not exist
9. a global `ARG` used without being re-declared inside its stage

Plus a tenth found by mac against the live host: **the SSE stream carried no CORS
headers**, so a browser could not read it — invisible to curl, which does not enforce
CORS.

And an eleventh, which would have made every login fail: `capStream` polled its
source with `read()`, and `read()` returning `null` means "nothing buffered right now"
rather than "the body is finished", so the wrapper ended the body before it began and
every adapter received **zero bytes**.

**Every one was found by something executing the deployment.** Not one by a test, a
static assertion, or a read of the file. That is the argument for deploying to a real
host rather than shipping another green PR, and it is why `capability.yml` builds
and starts the stack instead of only parsing it.

## What is not done

- **GHCR publish.** Images are built on the host with `ghcr.io/…` names but are
  never pushed. That needs a token with `packages: write`, and a half-verified
  publish path is the same shape as bug 3 above — it looks done until someone runs it.
- **ACME_EMAIL is a guess**, so certificate expiry notices go nowhere.
- **A restart policy is set** (`unless-stopped`) and Docker is enabled at boot, but
  nothing has rebooted the host to prove it comes back.