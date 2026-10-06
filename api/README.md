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
| Pool binding, claim-on-login | done — `PoolBinder` |
| TTL sweepers (10 min / 15 min / 30 min / 12 h) | done |
| Boot reconciliation | done |

`npm test` → 422 tests. `npm run typecheck` clean under `exactOptionalPropertyTypes`
and `noUncheckedIndexedAccess`.

## The CSRF token travels in the response body, not a cookie

Worth knowing before you wire a client to this, because it is not the shape a
single-origin design implies.

There is **no `msout_csrf` cookie.** The token is returned in the body of the two
responses a client already reads:

```
POST /api/session       -> { protocol, expiresAt, csrfToken }
GET  /api/session/status -> { ...snapshot, csrfToken }
```

`status` is called on every mount (§7.5's restore flow), so a refresh re-arms the
header from there. The token is derived, not rotating, so a tab that read it a
moment earlier still has a valid one.

Why not a readable cookie: a cookie set by this origin is host-only to this origin,
and the frontend is on a different host — `document.cookie` there cannot see it.
That was a real bug, found in review: every mutating route 403'd on a token no page
could read. PLAN-v3 §3.3 is amended to record it.

Why body delivery is safe: an attacker page *can* cause `GET /api/session/status`
and the `SameSite=None` session cookie rides along, but it cannot *read* the
response, because `ACAO` is emitted only for an allowlisted origin and is never
reflected. The token carries no authority without the `HttpOnly` session cookie.

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

## Two traps this code hit, kept here so they are not re-introduced

**Path matching uses `request.routeOptions.url`, never `request.url`.** The latter
carries the query string, so a `Set.has(request.url)` test fails for
`/api/public/version?cb=123`. That 401'd the version handshake on a cache-buster
and — worse — skipped the credential route's framing checks in the same hook. The
handler independently re-checks framing and applies `capStream`; that redundancy is
load-bearing, and there is a test saying so.

**Authentication runs before routing, so an unknown path returns 401, not 404** —
byte-identical to a real path, because a 404 would be a path oracle for a caller
that has proved nothing. The log distinguishes them at a filterable level: an
unmatched request logs `no such route`, since `routeOptions.url` is undefined
exactly when no route matched.

There is also no option to exempt a path from authentication. An earlier version
had `testOnlyAuthExemptPaths` for tests, which was an auth bypass in production
code guarded only by a comment. It is gone; the parser tests assert the property
against a bare instance instead.

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
whose cross-site cookie handling is load-bearing. `npm audit --omit=dev` is clean
with `undici` removed: it was declared but never imported, so it was a CVE
surface and a version to track in the component that holds the session secret.

SQLite is `node:sqlite` rather than `better-sqlite3`: a native addon means a
compilation step and a prebuilt-binary supply chain in the component that holds
the session secret. The cost is an experimental API, which is why `engines` pins
`>=22.13.0` — the release where `node:sqlite` stopped being behind
`--experimental-sqlite`, rather than the 22.5.0 release that introduced it.

## Two reconcilers, not one

SQLite is authoritative for sessions. The orchestrator is authoritative for
containers. `db.reconcileRunners` and `pool.Reconcile` are separate functions in
separate processes, and neither trusts the other's view alone — a rule from
PLAN-v2 §2.5 restated for two reconcilers in §2.1.

`sweep()` applies four independent TTLs (10 min unclaimed, 15 min login in
progress, 30 min idle, 12 h absolute). An exporting session gets **no** idle
deadline — §2.1 says the absolute cap only. A session in `erasing` is never
touched: the erase machine owns it, and deleting the row mid-machine would strand
the vault.