# api

Fastify + TypeScript. The public entry point, and the only component in this
repository that a browser can address.

## Status

Partially implemented — PLAN-v3 §12 step 5. **Not yet deployable.** The
middleware and the security-critical primitives are done and tested; the routes
that complete the flow are stubs returning 501.

| Area | State |
|---|---|
| Config validation, fail-closed | done |
| SQLite authority, atomic claim, both reconcilers | done |
| Session secrets, CSRF derivation | done |
| CORS + CSRF middleware | done |
| Client IP resolution (§3.5) | done |
| Credential path primitives | done |
| Cookie serialisation | done |
| Signed orchestrator client | done |
| SSE hub, ring buffer, replay, keepalive | done |
| Rate limiter, three layers | done |
| Erase state machine | done, needs runner half |
| `GET /api/public/version`, `/healthz` | done |
| `POST /api/session` | done |
| `GET /api/session/status` | done |
| `GET /api/session/events` | done |
| `POST /api/session/credential` | framing + caps, then 501 |
| `POST /api/session/notebooks` | guards, then 501 |
| `POST /api/export`, `/export/:id/abort` | state recorded, then 501 |
| `POST /api/session/erase` | machine runs, needs runner half |
| `GET /files/:artifactId` | 501 — Caddy serves it via `forward_auth` |
| Pool binding, claim-on-login, sweepers | not started |

`npm test` → 377 tests. `npm run typecheck` clean under `exactOptionalPropertyTypes`
and `noUncheckedIndexedAccess`.

## Routes that return 501

Four of them, and none of them lies. Each returns a body naming what is missing:

- `POST /api/session/credential` — needs the runner's address to stream to
- `POST /api/session/notebooks` — runs a CLI in the runner
- `POST /api/export` — spawns a CLI in the runner
- `POST /api/session/erase` — needs the runner half of the machine

A stub returning `{}` would look like a working route with an empty result. A 501
says the flow is incomplete, and the guards ahead of it — CSRF, Origin, framing,
the runner-bound check — all run first, so those properties hold even in the
unwired state.

## Three things in here that are controls, not wiring

**No body parser is reachable from anywhere.** Fastify registers JSON and
`text/plain` parsers at construction, and they run *before* any route handler and
before any route-scoped opt-out. Leaving them in place makes "this route does not
parse its body" true only until somebody adds a global hook. `server.ts` calls
`removeAllContentTypeParsers()` and installs one catch-all that hands the handler
the raw stream, so each route parses its own bytes with its own cap. The
credential route therefore has nothing that could parse a password.

**Cross-origin checks run in `onRequest`.** That hook fires before body parsing,
so Origin, the CSRF token and the credential `Content-Length` cap are all settled
before a single byte is read. A stream that starts and is then 403'd is worse
than one that never starts — the runner may already have acted on a prefix.

**The client address never comes from a header.** `trustProxy` is off; the
address is the socket peer, with the rightmost `X-Forwarded-For` entry consulted
only for a configured proxy (§3.5).

## Must never

- **Touch the Docker socket.** No mount, no CLI, no `dockerode`, no `DOCKER_HOST`.
  Asserted by inspecting the running container — `T-X1`.
- **Read `vault/`.** No mount of that tree. This is what lets Caddy hold a
  read-only artifact mount and nothing else — §2.2.
- **Reach the internet.** `internal: true` network, no published port — `T-N1`.
- **Log a body.** `onSend` sets `no-store` on everything; the credential route's
  audit fields carry request shape and never content.

## Cross-origin

`SameSite=None` on `__Host-msout`, because the two origins are cross-site. `Lax`
would break the app, and moving to `None` without noticing the CSRF implication
is the failure §3.3 exists to prevent — so the `X-CSRF-Token` check is not
optional.

## Dependency note

`undici` moved from the scaffold's 7.3.0 to 8.11.2. 7.3.0 carries 23 advisories,
including an HTTP request-smuggling issue and a `Set-Cookie` `SameSite` downgrade
via permissive substring matching — the latter is directly relevant to a service
whose cross-site cookie handling is load-bearing. `npm audit` is clean at 8.11.2.

SQLite is `node:sqlite` rather than `better-sqlite3`: a native addon means a
compilation step and a prebuilt-binary supply chain in the component that holds
the session secret. The cost is an experimental API, which is why `engines` pins
`>=22.5`.

## Two reconcilers, not one

SQLite is authoritative for sessions. The orchestrator is authoritative for
containers. `db.reconcileRunners` and `pool.Reconcile` are separate functions in
separate processes, and neither trusts the other's view alone — a rule from
PLAN-v2 §2.5 restated for two reconcilers in §2.1.