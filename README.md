# microsoft-onenote-exporter-web — backend (Component B)

This is **Component B** of PLAN-v3: the only trusted component. It holds the
credential path's server half, the session state, the Docker socket and the
pool of isolated export containers.

The frontend is a **separate repository**
(`microsoft-onenote-exporter-web-frontend`, Component A), deployed to a
different host on a different origin. That separation is deliberate and is
load-bearing — see [Why two repos](#why-two-repos).

Design documents, cited by section number from the code, live in
[`PLANNING/`](./PLANNING/):

| Document | What it is |
|---|---|
| [`PLANNING/PLAN-v3.md`](./PLANNING/PLAN-v3.md) | **The current design.** Two components, credential path, CORS/CSRF, capability separation, artifacts, acceptance tests. |
| [`PLANNING/PLAN-v2.md`](./PLANNING/PLAN-v2.md) | The single-host design v3 revises. Still normative for everything v3 does not restate — the SSE contract, TTLs, rate limits, the erase state machine, package changes. |

## What is in here

| Directory | Component | Holds | Must never hold |
|---|---|---|---|
| [`api/`](./api) | Fastify, TypeScript | SQLite (WAL), pool manager, idle-TTL + orphan sweepers, SSE hub, the credential raw-stream forwarder, CORS/CSRF/cookie verification, rate limiter | the Docker socket, any read of `vault/`, any route to the internet |
| [`orchestrator/`](./orchestrator) | the only `/var/run/docker.sock` holder | allowlisted verbs: claim · release · recycle · remove · stat | any caller-supplied command, image, flag, mount, network or path; any route off-host |
| [`runner/`](./runner) | Fastify sidecar + `@msout` packages + Playwright Chromium | the credential bytes, `auth.json`, the streaming zip | the Docker socket, the internal networks, the metadata service |
| [`infra/`](./infra) | Caddy, compose | TLS, HSTS, `/files/*` with `forward_auth` | any read of `vault/` |

The capability table is PLAN-v3 §2.1 and it is enforced at runtime, not by
convention: every row is a test that inspects the running container or attempts
the forbidden thing from inside it (`T-X1`…`T-X5`, `T-N1`…`T-N4`). A rule that
is only a rule in a README is not one of those rows.

`api` and `orchestrator` share this repository on purpose. Their separation is a
*runtime* boundary — process, mount, network membership — and every claim about
it is a runtime assertion. Splitting the source as well would add a cross-repo
release handshake for a signed HTTP protocol that has no independent release,
and would buy no security that `T-X1`…`T-X3` do not already prove.

## Why two repos

The deployment is two components, so the repositories are too. Three reasons,
in order of weight:

1. **CI secret separation.** PLAN-v3 §1.4 concedes that the frontend host runs
   our `npm install` and our build script, and that hPanel users can write
   `public_html`. If the frontend lived here, the `GHCR` push token and the VPS
   deploy key would sit in the same secret store as that build. Two repos means
   the frontend workflow has no token to leak, because it is not in its scope.
   This is the same blast-radius reduction §2.1 buys with the socket split,
   applied where it is cheapest.
2. **Repo layout is not deploy topology.** hPanel builds on push; Component B
   deploys on `compose pull && up`. Skew between the two artefacts exists
   whatever the repository layout is, so §7.2's `apiProtocol` handshake and the
   four skew rows in the §7.3 failure matrix are required either way. A
   monorepo does not remove the handshake; it only makes the constant easy to
   edit in the same commit.
3. **Invariants 1 and 10 stop being conventions.** "Component A never proxies
   `/api/*`" and "holds no authorisation logic" are true by construction when
   the api source is not in the tree. Here they would be a review rule plus the
   `T-A1`/`T-A4` greps — the class of control §2.1 opens by criticising.

The contract between the repositories is HTTP and nothing else: JSON shapes, SSE
events, the `apiProtocol` integer, and the header/CSP policy. There is no shared
package. The frontend pins `EXPECTED_PROTOCOL` as a literal and the handshake
turns a forgotten bump into a rendered "reload" screen instead of a subtle bug.

## Build order

Follow §12. Steps 1–4 are unchanged from v2 and are still the risky part; the
split does not reduce them. The one reordering is that `orchestrator` comes
before `api`, because `api` cannot be tested end-to-end without it and testing
it against a mock would validate the wrong boundary.

This repository is mid-build against that order. Where it stands:

| Step | Component | State |
|---|---|---|
| 4 | `orchestrator` | **done** — 92 tests, zero third-party deps |
| 5 | `api` | **partly done** — 422 tests; middleware, primitives, routes and pool binding complete, the runner-facing routes return 501 |
| 1–2 | `runner` | not started |
| 6 | Caddy, compose, GHCR, CI | not started |

Each directory's own README carries the detail for that component. The `api` one
has a table of what is wired and what is not, because "partly done" is not a
useful thing to read.

**Nothing here is deployed.** There is no compose file, no Dockerfile for the `api`
or the runner, and no CI yet, so the test suites are the only evidence any of it
works — which is a real limitation of the current state and the reason step 6 is
next. The orchestrator's Dockerfile exists and asserts its zero-dependency
property at build time, but has not been built.

## Open decisions

Some settled, some not. The settled ones are recorded here because a reader who
finds the reasoning in a component README should not have to assume it was still
open.

- **Orchestrator language — decided: Go, and now implemented.** C++ was
  considered and rejected; the reasoning is in
  [`orchestrator/README.md`](./orchestrator/README.md#language-go). It comes down
  to the orchestrator being the root-equivalent component, where a
  memory-safety bug is a host-root compromise that the verb allowlist never
  sees. Go gives memory safety *and* a dependency-free static binary, because
  the Docker Engine API is HTTP over a unix socket and everything else needed
  is stdlib. The zero-dependency property is now enforced by the build rather
  than asserted in a README.
- **SQLite driver — decided: `node:sqlite`.** A native addon
  (`better-sqlite3`) would mean a compilation step and a prebuilt-binary
  supply chain in the component that holds the session secret. The cost is an
  experimental API, which is why `api/package.json` pins `engines.node >=22.13.0`
  (the version where `node:sqlite` stopped being flag-gated, not the version
  where it was added).
- **CSRF token delivery — decided: response body, not a readable cookie.**
  PLAN-v3 §3.3 originally specified a readable cookie, which is a
  single-origin assumption. Under the split it is unreachable: a cookie set by
  Component B is invisible to `document.cookie` on Component A's host, and
  every mutating route failed closed on a token no page could read. The token
  now travels in the bodies of `POST /api/session` and
  `GET /api/session/status`. See `api/README.md` and the amendment in §3.3.
- **Fronting the api.** §2.1 has Caddy and `api` on the same host on an internal
  compose network, so `api` derives the client address from the socket peer
  (§3.5). If a CDN or load balancer ever goes in front of Caddy, §3.5's rule has
  to be updated explicitly. The default is fail-closed.
- **Dependency isolation.** The archived POC used npm workspaces with a
  `shared` package, because its app and runner consumed the same types. v3 has
  no shared package — `api` and `runner` talk over HTTP and share nothing — so
  each component has its own `package.json` and its own
  lockfile rather than a root workspace. That keeps Playwright out of the
  `api` image and keeps the `api`'s dependency tree out of the runner's,
  which is the same "no component holds another's capabilities" property as the
  mount and network separation. A single root lockfile is the thing to revisit
  if a real shared contract appears.
- **Rootless Docker.** §2.3 explains why a `docker-socket-proxy` sidecar was
  rejected: it would need `POST=1` to create runners, and `POST` on the
  containers API is root-equivalent, so it would reduce nothing. Rootless Docker
  or Podman is a genuine containment upgrade, deferred, with the caveat that it
  interacts with the Chromium sandbox (§5.2).

## Licence

MIT — see [`LICENSE`](./LICENSE) and [`NOTICE.md`](./NOTICE.md).

This repository consumes four packages from npm and **does not fork them**:
`@msout/microsoft-webauth`, `@msout/microsoft-onenote-list-notebooks`,
`@msout/microsoft-onenote-export-notebook`, and `microsoft-onenote-exporter` as
the documented fully-local alternative. PLAN-v3 §0.2 records why the Graph API
and MSAL alternatives are unavailable for this use case, with the upstream
documentation as the source; §14 carries the licence position, including the
note that the Microsoft Q&A page quoted as evidence is Microsoft's content and
is not vendored here.

## An assertion about the handler is not an assertion about the transport

mac's sentence, after the third instance of this shape across the two repositories.

| what the test asserted | what was actually broken |
|---|---|
| ACAO was **absent** for a foreign origin | it was absent for an **allowlisted** one too |
| the credential route returned 202 and emitted `login-started` | the adapter received **zero bytes** |

Both passed. Both were about the handler's behaviour, and both bugs were in the
path between the client and the handler — a header the hook set and the route
clobbered, and a stream wrapper that ended the body before it began.

The pattern is not specific to either bug. A test that exercises a handler can only
tell you what the handler did with what it was given; it cannot tell you whether it
was given the right thing. For the places where data crosses a boundary you did not
write — a proxy, a socket, a stream — that assertion has to be made against the
boundary itself, over a real connection rather than an in-memory harness.

Concretely, in this repository that has meant:

  - SSE headers asserted over a **real socket**, because `app.inject` materialises
    the response and cannot express a stream that does not end;
  - the credential asserted as **buffer equality over a real socket**, because
    `app.inject` materialises the request body before the handler runs, so the
    race in `capStream` could not fire under it.

Two of the three worst bugs in this project were invisible to a suite that had
hundreds of green tests, and both were invisible for the same reason.
