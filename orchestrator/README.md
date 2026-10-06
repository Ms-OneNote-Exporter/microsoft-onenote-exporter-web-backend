# orchestrator

The **only** holder of `/var/run/docker.sock`. ~1k LOC, and deliberately
boring.

## Owns

A **fixed verb set**, and nothing else:

| Verb | Does |
|---|---|
| `claim` | take a pool slot, start a runner container |
| `release` | return a slot, stop and remove a runner |
| `recycle` | replace a runner that has outlived its 5-minute budget |
| `remove` | delete a container and its volumes |
| `stat` | report `{exists, size}` for an artifact path — the download authoriser's only question |

`stat` is why the orchestrator exists as a separate process rather than a
library call inside `api`: it lets `api` decide authorisation from SQLite while
never touching the filesystem — §2.2.

## Must never

- **Accept a command, image, flag, mount, network name or path from a caller.**
  Runner argv is built from a template in this component's own code. Full
  compromise of this API therefore buys the attacker the fixed runner
  invocation and nothing more. Deny by default: an unknown method or path is
  `404`, never a default branch — `T-I5`, `T-X3`.
- **Reach the internet.** `internal: true` network, no published port, not a
  member of the runner network, no volume — `T-X2`. Asserted by attempting a
  TCP connect *and* a DNS query from inside the container, because a policy that
  only blocks TCP still leaks through DNS — `T-N2`.

## Caller authentication

A bare bearer token is not enough: the threat is a *replayed* request to an
endpoint that can create containers. Every call from `api` carries:

```
X-Msout-TS:  <unix ms>
X-Msout-Sig: base64url(HMAC-SHA256(secret, TS + "\n" + METHOD + "\n" + path + "\n" + sha256hex(body)))
```

- **60 s replay window.** A timestamp outside it is rejected outright, which
  absorbs ordinary clock skew without needing a nonce table. A hard failure on
  real skew is preferable to a silent accept.
- **Audience and path binding are inside the signature**, so a signature
  captured for `GET /stats` cannot be replayed as `POST /release` — `T-I3`.
- **The body digest is signed**, so a signed `GET` cannot be re-pointed at a
  `POST` with a body — `T-I4`.
- **Constant-time comparison** — `T-I7`.
- The secret arrives as a **Docker secret**, never an env var and never a file
  in a bind mount a runner can read. `api` holds it; nothing else on the host
  does. This component **refuses to start** when it is absent rather than
  falling back to open access — `T-I6`.

## Boot reconciliation

A second reconciler, alongside the one in `api`, and it does not trust the other
alone: this component reconciles containers against their labels, `api`
reconciles sessions against SQLite. Neither resurrects an expired session
(§2.5, §2.1).

## Open decision: language

§2.1 says "Go or Node". Go gives a small static binary with no `node_modules`
to audit, which suits a component whose entire job is to hold the socket and
refuse everything else. Node shares the toolchain and the test runner with the
rest of the repository. Either is defensible; **the fixed verb allowlist is the
part that must not move.**

## Not implemented yet

This directory is a placeholder. See `PLANNING/PLAN-v3.md` §12 step 4 — it is
built first, standalone, driven by `curl`, because it is the component with the
most authority and `api` cannot be tested end-to-end without it.
