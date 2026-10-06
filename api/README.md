# api

Fastify + TypeScript. The public entry point, and the only component in this
repository that a browser can address.

## Owns

- **SQLite as authoritative state** (WAL). Labels are for recovery only, never
  the other way round — PLAN-v2 §2, carried forward.
- Pool manager with an **atomic slot claim** — PLAN-v2 §2.4.
- Idle-TTL sweeper and orphan sweep — PLAN-v2 §2.1–2.3.
- The **SSE hub**: ring buffer, replay via `Last-Event-ID`, keepalive,
  multi-tab fan-out — PLAN-v2 §7, now cross-origin.
- The **credential raw-stream forwarder**. No JSON body parser on that route,
  no buffering, no accumulation, `Content-Length` checked before proxying with
  a hard cap around 4 KB, stream destroyed immediately past the cap. This is
  the hot path of the whole service — PLAN-v3 §3.1.
- CORS allowlist, CSRF verification, session cookie verification, artifact
  authorisation, rate limiting — PLAN-v3 §3.3, §3.5, §5, §10.

## Must never

- **Touch the Docker socket.** No `/var/run/docker.sock` mount, no docker CLI,
  no `dockerode`, no `DOCKER_HOST`. A CI test asserts the socket is absent from
  the running container — `T-X1`.
- **Read `vault/`.** It has no mount of that tree and cannot read a cookie jar
  even if it wanted to. This is what lets Caddy hold a read-only mount of the
  artifact tree only — §2.2.
- **Reach the internet.** `internal: true` network, no published port. Asserted
  by attempting a TCP connect from inside the container — `T-N1`.

That is the whole point of the split in §2.1: no process in this design holds
two of {Docker socket, credential bytes, vault read, egress}. A single Fastify
RCE used to yield root on the host.

## Cross-origin

The browser reaches this component directly, on its own origin, and the
frontend origin is a different origin entirely. Three things follow, and all
three are v1 requirements rather than hardening:

- `SameSite=None` on `__Host-msout` cookies, because the two origins are
  cross-site. `Lax` would break the app, and the resulting "fix" of going to
  `None` without noticing the CSRF implication is exactly the failure §3.3
  exists to prevent.
- `X-CSRF-Token` on **every** non-`GET`. A custom header is not
  CORS-safelisted, so the browser must preflight, and a non-allowlisted origin
  therefore cannot cause a request body to be transmitted at all.
- Client IP derived from the **socket peer**, not from headers — §3.5. Without
  this, every per-IP rate limit in PLAN-v2 §10 is decorative, because an
  attacker behind the proxy can claim any address. This is specified before the
  rate limiter is built, not retrofitted.

The API is fully usable with **no frontend deployed at all** (`T-C7`). CORS is
not an access control and is never treated as one; it constrains browsers, not
`curl`. Every authorisation decision lives here.

## Not implemented yet

This directory is a placeholder. See `PLANNING/PLAN-v3.md` §12 step 5.
