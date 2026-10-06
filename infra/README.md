# infra

Caddy, compose, and the host paths. Everything that is not application code.

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
                       ╳  msout-runner is declared but has no service on it yet
```

Three networks, and each one exists for a stated reason:

- `msout-edge` — **Caddy alone.** The api and the orchestrator are not on it, so
  "not reachable from outside" is a property of the topology rather than of
  remembering not to publish a port.
- `msout-control` — `internal: true`. Carries Caddy↔`api` and `api`↔`orchestrator`.
  This is the word that matters most in the file: it means these three services
  have **no route to the internet**. A network declared without it still works, so
  nothing else would fail — the orchestrator would simply be able to reach out.
- `msout-runner` — **declared with no egress enforcement, which compose cannot
  do.** Honest rather than omitted, so a reviewer reading the file sees the gap.
  Note it is pruned from the resolved config until a service joins it, so today it
  is documentation rather than a live network.

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

## Not verified

**No capability assertion has run against a running container.** There is no
`/var/run/docker.sock` access on the machine this was written on, so nothing in
this directory has been started. What is checked here is the *shape* of the
deployment; what is not checked is whether a running container can see what it
should not.

Per mac's argument, `.github/workflows/capability.yml` will land with its tests
present but `it.skip`ped and the reason attached — unproven assertions create the
*appearance* of coverage, and a test asserting mount isolation that never ran
passes if it is written against the compose file rather than against containers.

The runner service also does not exist yet: it depends on `@msout/*` packages that
are not published (§12 steps 1–2). This is a three-service deployment, not a
four-service one.