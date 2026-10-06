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

## Language: Go

§2.1 said "Go or Node". **Go**, and C++ was considered and rejected.

The deciding argument is that this is the **root-equivalent component**, and
§2.1's whole case for it is that its security rests on the code being small and
fixed — nothing a caller sends ever reaches a dangerous operation. If the
control is "these ~1k lines have no bugs", the language has to make the
dangerous bug classes unreachable rather than merely unlikely. A buffer overrun
or an integer overflow in a length calculation is a host-root compromise that
the verb allowlist never sees, because it happens before the allowlist runs.
Go removes that class entirely; C++ concentrates it in the one process where a
bug is catastrophic.

And Go does not give that up for the "small static binary, nothing to audit"
property that makes C++ look attractive here. With `CGO_ENABLED=0` the binary
is static with no libc, and the Docker Engine API is HTTP over a unix socket,
so `net/http` plus a custom dialer covers it. Everything else needed is stdlib:

| Need | Go, stdlib |
|---|---|
| HTTP server, unix-socket client | `net/http`, `net.Dialer` |
| JSON | `encoding/json` |
| HMAC over `TS + "\n" + METHOD + "\n" + path + "\n" + sha256hex(body)` | `crypto/hmac`, `crypto/sha256` |
| Constant-time comparison (`T-I7`) | `crypto/subtle.ConstantTimeCompare` |
| Refuse to start without the secret (`T-I6`) | ordinary startup check |

So the orchestrator can have **zero third-party dependencies** — no lockfile, no
transitive tree, nothing to audit but our own source. C++ reaches the same
"no runtime" place only by pulling libcurl, OpenSSL and libstdc++ into a
root-equivalent process, which is *more* third-party code in the least trusted
place, not less.

C++ also breaks the plan's own budget: ~1k LOC is realistic for Go and Node,
but a C++ version needs an HTTP server, a JSON codec and an HMAC implementation
before any of the five verbs are written, and hand-rolled HTTP parsing is
exactly the code §2.1's auditability argument depends on being able to read.

Performance is not a factor. This is a control plane handling a handful of HTTP
calls per export session; it computes nothing.

**Node** was the credible alternative — it shares the toolchain, the lockfile
discipline and the test runner with the rest of the repository, and it is
fewer lines. Its cost is a `node_modules` tree inside the only container that
holds the Docker socket, and §2.1's `T-X3` ("no endpoint accepts a command,
image, flag, mount, network or path — asserted by enumerating its request
schema") is a much stronger claim when the schema is validated by hand-written
Go structs than when it is validated by a framework that also parses the body
for you.

If that trade ever flips — if the orchestrator outgrows a fixed verb set and
needs real request routing — Node becomes the better choice, because at that
point schema validation is no longer the primary control.

## Implemented

PLAN-v3 §12 step 4. Built first, standalone, driven by `curl`, because it is the
component with the most authority and `api` cannot be tested end-to-end without it.

`make check` → vet + 92 tests, green under `-race`. `make deps-zero` fails the
build if `go.mod` ever grows a `require` block or a `vendor/` directory appears,
and `Dockerfile` re-checks the module graph so the property survives a container
build.

Three design decisions worth a reviewer's attention, because two of them are
security choices rather than conveniences:

- **An idle runner holds no vault mount** — a tmpfs at `/data`, not
  `vault/<guid>`. An idle pool one claim away from `auth.json` is the wrong shape,
  so a claim *creates* a bound container rather than relabelling an idle one.
- **Recycle and claim replace the container** rather than mutating it: Docker fixes
  mounts at create time, and a released container must not carry browser state
  into the next session.
- **Reconcile replaces an over-age container** rather than adopting it. The plan
  names only the expired-session rule; the age bound is enforced alongside it,
  because adopting one would attach a fresh 5-minute budget to a browser process
  tree that has been running for days.

Boot reconciliation is tested against an in-memory fake daemon rather than a mock
with expectations: the property under test is the *decision* made about a given set
of containers, which a fake models and a mock cannot. It was also smoke-tested
against a real unix socket with real signatures, which caught `/containers/json`
being modelled as a bare array when the Engine wraps it — the class of defect a
mocked test cannot see.

## Not implemented yet

The compose service and Caddy config that give it a socket and a network
(§12 step 6, `infra/`).
