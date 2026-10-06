# infra

Caddy, compose, and the host paths. Everything that is not application code.

## Topology

```
Caddy ──► api ──► orchestrator ──► runner-1 … runner-N
  │        │          (internal)      (restricted egress)
  │        └── SQLite, vault paths, rate limits
  └── /srv/msout/artifacts (read-only)
```

Two Docker networks:

- `msout-control` — `internal: true`. Carries Caddy↔`api` and `api`↔`orchestrator`.
- `msout-runner` — restricted egress. Carries `api`/`orchestrator`↔runners.

`orchestrator` is on the control network only. Caddy is on the control network
only and has no route to the runner network.

## Host paths

```
/srv/msout/vault/<guid>/          auth.json, notebook cache, logs   (orch rw, runner rw)
/srv/msout/artifacts/<artifactId>/ finalised zip, partial marker    (orch rw, runner rw, caddy ro)
```

Split, not shared. v2 mounted one tree and let Caddy `file_server` it, which
meant Caddy could also read `auth.json` — a live Microsoft cookie jar. Keeping
them apart means the component in the credential path (Caddy) and the component
that decides who may download (`api`) can *neither* read session data. That is a
genuine improvement over v2 and the split is what makes it cheap (§2.2).

## Caddy

- TLS, HSTS, **no body logging anywhere**.
- `/files/*` → `forward_auth` to `api`, then `file_server` with `sendfile` and
  `Range`. Multi-gigabyte downloads never pass through Node.
- Downloads are `GET /files/<artifactId>` where the id is
  `crypto.randomBytes(32)` → base64url, mapped to a path in SQLite. **No GUID
  and no notebook name in any URL** — v2 leaked the GUID into Caddy access logs
  and the notebook name into any `Referer`. The notebook name goes in
  `Content-Disposition`, which is not logged.
- Partial vaults are labelled **server-side**: `X-Artifact-Partial: 1` and a
  `.partial.zip` suffix. A partial vault must not be mistakable for a complete
  one, and that must not depend on the UI being correct.
- `forward_auth` hits `/internal/authorize-download`, which is bound to the
  internal network, is not a public endpoint, and never appears in CORS.

## Client IP

Caddy sets `X-Forwarded-For` itself and **appends** to any existing value; `api`
takes the **rightmost** entry — the address Caddy actually saw. It never takes
the leftmost and never trusts a bare `X-Real-IP`. Stripping inbound headers
would be correct but brittle, because it is one Caddy directive a future config
edit can silently drop; rightmost-plus-known-peer is checkable in CI (§3.5).

## Not implemented yet

This directory is a placeholder. See `PLANNING/PLAN-v3.md` §12 step 6.
