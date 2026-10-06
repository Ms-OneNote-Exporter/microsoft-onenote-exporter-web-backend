# PLAN-v3 — `microsoft-onenote-exporter-web`, two-component deployment

Revision of [`PLAN-v2.md`](./PLAN-v2.md). Same security posture, **two** deployment
components instead of one.

---

## 0. Summary

PLAN-v2 is a single VPS: Caddy + one Fastify app + runner pool. v3 splits it into
two independently operated components:

| | Component A | Component B |
|---|---|---|
| Host | Hostinger Web App | Dedicated VPS |
| Holds | React build, security headers, nothing else | Caddy, `api`, `orchestrator`, runner pool, SQLite, session data |
| Runtime | static, or a stateless file server | long-lived containers |
| Trust | **untrusted for secrets** | the only trusted component |
| Deployed by | hPanel git push | GHCR + `compose pull && up` |

The security verdict is not "the same, roughly". It is:

- **Credential path: byte-identical to v2 §4.** Component A serves `GET` for JS
  and CSS. The credential `POST` goes cross-origin straight to Component B.
  Nothing in between parses, buffers or logs it. This is the single most
  important property of the split and it is enforced, not hoped for.
- **Blast radius: strictly smaller.** In v2, one Fastify process held the
  Docker socket *and* proxied credentials *and* served the UI. In v3, three
  separate processes with three separate capabilities, none of which holds two
  of them at once.
- **One new class of attack: cross-origin.** CSRF and CORS are new. They are
  fully compensated, and one of them becomes load-bearing for the credential
  route (§3.3).
- **v2 §13.1's "GUID-only auth" pre-launch blocker is now a v1 requirement.**
  Under v1 it was deferred because the app was same-origin. Cross-origin removes
  that excuse.

### 0.1 What changed at a glance

| # | Change from v2 | Driver |
|---|---|---|
| 1 | Frontend moved to a separate origin, cross-origin | request |
| 2 | GUID + 256-bit secret promoted to v1 | cross-origin makes GUID-only untenable |
| 3 | CSRF defence moved from "pre-launch" to v1 | `SameSite=None` cookie |
| 4 | `api` split from `orchestrator`; socket moves out of `api` | request; removes a v2 weakness |
| 5 | Vault and artifacts split onto separate host paths | lets Caddy serve files without being able to read `auth.json` |
| 6 | Artifact URLs are opaque 256-bit ids | v2 leaked notebook name in the download path |
| 7 | `apiProtocol` version handshake between the two deploys | independent deploy skew |
| 8 | CI attests the deployed frontend bundle byte-for-byte | Hostinger runs *your* `npm install` and build |
| 9 | Layered "load-bearing CORS" controls (§3.3) | CORS is now a security control, not just hygiene |
| 10 | Component A is forbidden from proxying `/api/*` | preserves the credential-path property |
| 11 | §0.2 — MSAL/Graph rejected with upstream citations | the packages are the contract; the alternatives are unavailable |
| 12 | §3.5 — client IP derived from socket peer | a proxy in front of `api` would silently void PLAN-v2 §10's rate limits |
| 13 | §2.1 — HMAC-signed internal calls, 60 s replay window | the orchestrator can create containers; a bare bearer token is replayable |
| 14 | §2.1 — per-container egress policy as a test table | "no egress" was a claim; the metadata service was unaddressed |

Everything else in PLAN-v2 is carried forward unchanged. §8 is the
preserve/strengthen/new-compensate ledger; §9 lists the invariants restated as
testable assertions.

### 0.2 Why MSAL / Graph API is not an option here

Raised in review: an OAuth delegated flow would remove the credential path, the
MFA branch, the consent checkbox and the Playwright sandbox problem in one move.
It is rejected on grounds that are documented upstream, not on preference.

1. **No consumer-facing OneNote export surface.** The Microsoft Q&A thread
   preserved as `docs/graphapi-sharepoint-notebook-limit-evidence.pdf` in
   `microsoft-onenote-export-notebook` records the operative limitation: Graph
   API page access fails on large SharePoint-backed notebooks — the
   approximately-50-page ceiling quoted in that thread. A partial export is not
   the product. `microsoft-onenote-export-notebook`'s own README states the
   position directly: *"NO GraphAPI, no limitation."*
2. **No admin rights over the user's tenant.** Graph API requires an Entra
   administrator to grant rights. The service authenticates arbitrary personal
   Microsoft accounts it has no administrative relationship with, so this is not
   a deployment detail to be solved later — it does not apply to the user
   population at all.
3. **The packages are the specified contract.** `@msout/microsoft-webauth`,
   `@msout/microsoft-onenote-list-notebooks` and
   `@msout/microsoft-onenote-export-notebook` are consumed from npm and are not
   forked (§14). `microsoft-webauth` is explicitly *"NO GraphAPI"* and derives
   auth from browser navigation to `onenote.cloud.microsoft`; `storageState` is the
   interchange format between the three. Replacing that with MSAL would mean
   forking or replacing all three, which §14 excludes.
4. **A "do nothing" export path already exists.** `microsoft-onenote-exporter`
   is untouched by this plan (PLAN-v2 §6.4) and already produces the same
   Obsidian-flavoured vault locally, with no password leaving the machine.
   Anyone unwilling to hand a password to a browser-automation service has a
   supported alternative, and the frontend is told to say so — see §10 T11.
5. **The OneNote web app is the export surface.** Even ignoring the page-count
   ceiling, fidelity is the reason the three packages exist: the exporter walks
   the live OneNote frame and scrapes sections, pages, attachments and internal
   links into Obsidian wikilink Markdown. That output shape is a scraping
   artefact. A Graph/MSAL rewrite would have to re-derive it against a different
   data model, and `microsoft-onenote-export-notebook` already has a
   diagnostics-first design for exactly this fragility (`diagnose-notebook.js`,
   `diagnose-notebook-newpage.js`).

The residual objection is real and is recorded rather than dismissed: this design
does ask users to type Microsoft passwords into a web service that logs in on
their behalf, and it trains a habit that phishing thrives on. §9.3's consent
checkbox, §3.2's exact privacy wording, and §10 T11's honesty requirement are the
mitigations available **without** changing the architecture. The objection stands
as a product-level decision, not a technical one, and belongs to the operator.

Two consequences that follow from the package reality and are new in v3:

- **Interstitial screens are an accepted, documented behaviour, not a bug.**
  `microsoft-webauth` auto-accepts updated Terms of Use, declines the passkey
  prompt, keeps existing security-info methods, and accepts Microsoft consent
  pages, by matching a fixed set of button labels. Accepting the Services
  Agreement **is a real change to the user's account**, and the upstream README
  says so. The consent text in §9.3 must reflect that the service may change
  account terms and security state during login — it currently says only that it
  accepts Terms of Use and security prompts, which understates it.
- **`--dodump` and `--screenshot` must stay unreachable** (v2 §5.6, restated in
  §9.2). Upstream is explicit that a dump contains authenticated DOM with live
  cookies and tenant hostnames, and that a **screenshot cannot redact credential
  fields** because it is a bitmap, while showing the number-match MFA code. A
  screenshot in this service is a credential artefact, so the "no debug
  override" rule is a security control and not a tidiness preference.

---

## 1. Component A — Hostinger

### 1.1 Role

Serve the React build. That is the whole job.

**Component A holds no session state, no secret, no credential, and no
authorisation logic.** It is not a tier in the trust chain. If it is fully
compromised, the attacker gains the ability to serve arbitrary JavaScript to
visitors, and nothing else — because the session secret is `HttpOnly` and every
capability is re-checked server-side (§4.2).

### 1.2 Why not the Node runtime for real logic

Hostinger's own documentation, "Process handling":

> Node.js apps on Hostinger run on demand. After a period without incoming
> traffic, your app's process is stopped automatically… The next request… starts
> it again.

This makes the Node runtime unusable for anything stateful or long-lived:

| Candidate job | Verdict |
|---|---|
| SSE hub | **No.** The connection must outlive an idle window. §7.2 replay and §7.4 reconnect would fire on every pause, and the process can be stopped mid-stream. |
| Session state, rate-limit counters | **No.** In-memory state dies with the process; the filesystem is not a substitute under a platform that redeploys to a new `hbuilds/versions/{id}` directory per build. |
| Credential proxy | **No.** §3.1. |
| Rate limiting | **No.** A limiter the attacker can bypass by hitting Component B directly is not a control. The real limits stay in `api` (§10, T5). |
| Static file server to set headers | **Yes**, conditionally — see §1.3. |

So: **no entry file.** Hostinger's own build settings state that leaving the
entry file empty deploys the build as a static site and no Node server runs.
That is the intended configuration, and it is the one to ship.

### 1.3 The one legitimate use of the Node process

If `.htaccess` cannot set the headers in §1.5 — `Header always set` needs
`mod_headers`, and this must be verified, not assumed — then run a
**stateless file server on Component A whose only non-static job is emitting
security headers.**

Constraints on that process, all of them non-negotiable:

- Serves `dist/`. Nothing else.
- **Never proxies, rewrites or forwards `/api/*`.** Proven by test (§13, T-A3).
- No env vars except the build id. No database. No sessions. No upstream fetch.
- No `@msout` packages. It is not "the API minus the risky bits".
- Statelessness is a feature here: the on-demand lifecycle is harmless for a
  file server, because a cold start costs one request.

This is a real answer to "Hostinger can host Node", and it is the *only* one
that does not cost security. It also means a cold start is acceptable — which
is exactly why the same process could not host the SSE hub.

### 1.4 Deploy

CI pushes to the connected GitHub branch; hPanel builds; static output is synced
to `public_html`. Two consequences that need handling:

1. **Hostinger runs `npm install` and your build script on their
   infrastructure.** The bytes served are not necessarily the bytes CI
   produced. Mitigation in §7.1.
2. **hPanel users have file-level write access to `public_html`.** A tampered
   bundle does not require a code change. This makes the attestation check a
   *scheduled* job, not just a post-deploy gate (§7.1).

Set the build to: framework `vite` (or `react`), Node LTS, build script
`npm ci && npm run build`, output `dist`, **entry file empty**.

### 1.5 Headers

Identical policy to v2 §9.4, with two additions forced by the split:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self' https://api.<domain>; form-action 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
Cache-Control: no-store
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

**`connect-src` is the control that makes Component A safe to type a password
into.** Without it, an attacker who can inject a script into the frontend can
exfiltrate the credential to any host. With it, exfiltration requires
`connect-src` to be relaxed. This single directive carries more weight in v3
than in v2, and it is enforced on Component A, which is the origin that handles
the password form.

Practical notes:

- **No inline scripts.** With a strict CSP and no nonce support in static
  hosting, an inline `<script>` in `index.html` breaks the page. Common Vite
  templates ship one (theme flash prevention). A small Vite plugin computes the
  SHA-256 of each emitted inline script and injects the corresponding
  `'sha256-…'` sources into the CSP at build time. CI asserts the served CSP
  matches the built HTML.
- `form-action 'none'` removes form-based exfiltration.
- `Referrer-Policy: no-referrer` on both origins, so no cross-origin `Referer`
  ever carries a path.
- Hostinger must not inject anything. A CDN fronting Component A is acceptable;
  it must not cache `index.html` (§1.5 headers) and must not touch the API
  origin. CI asserts the served HTML contains no external `<script>`, `<iframe>`
  or `<link>` and no inline script lacking a matching CSP hash.

### 1.6 Prototype-pollution / supply chain of the bundle

`npm ci` on Hostinger resolves from the lockfile. The lockfile is committed and
hash-checked in CI (v2 §12.5, unchanged). No `postinstall` beyond what CI runs.
The four `@msout` packages are **not** dependencies of the frontend — the
frontend talks HTTP only. Assert this in CI.

---

## 2. Component B — the Docker server

```
┌──────────────────────────────────────────────────────────────────────┐
│ Caddy                                                                │
│  • TLS, HSTS                                                         │
│  • NO body logging anywhere                                          │
│  • /files/*  forward_auth → api, then file_server, sendfile, Range  │
└───────────────┬──────────────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│ api  (Fastify, TypeScript)                    ◄── no Docker socket  │
│  • SQLite authoritative state (WAL)                                  │
│  • pool manager + atomic slot claim                                  │
│  • idle-TTL sweeper + orphan sweep                                   │
│  • SSE hub: ring buffer, replay, keepalive, multi-tab fan-out       │
│  • credential raw-stream forwarder (no parsing)   ◄── the hot path   │
│  • CORS allowlist + CSRF + session cookie verification              │
│  • artifact authorisation (asks orchestrator to stat)                │
│  • rate limiter                                                      │
└───────────────┬──────────────────────────────────────────────────────┘
                │  msout-control network (internal: true)
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│ orchestrator  (Go or Node, ~1k LOC)          ◄── ONLY socket holder  │
│  • /var/run/docker.sock                                              │
│  • allowlisted verbs: claim · release · recycle · remove · stat      │
│  • NO request field ever reaches a docker argv                       │
│  • NO egress                                                           │
└───────────────┬──────────────────────────────────────────────────────┘
                │  msout-runner network (restricted egress)
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│ runner-1 … runner-N                                                  │
│  • Fastify sidecar + @msout packages + Playwright Chromium           │
│  • rw mount: vault/<guid>  and  artifacts/<id>                       │
│  • /healthz, SSE events, abort, streaming zip                        │
└──────────────────────────────────────────────────────────────────────┘
```

Host paths:

```
/srv/msout/vault/<guid>/          auth.json, notebook cache, logs   (orch rw, runner rw)
/srv/msout/artifacts/<artifactId>/ finalized zip, partial marker     (orch rw, runner rw, caddy ro)
```

### 2.1 The `api` / `orchestrator` split

v2 gave one process the Docker socket, the credential path and the UI. That
means a single Fastify RCE yields root on the host. v3 separates the
capabilities:

| Capability | api | orchestrator | Caddy | runner |
|---|:--:|:--:|:--:|:--:|
| Docker socket | — | **only** | — | — |
| Sees credential bytes | yes | **no** | yes | yes |
| Reads `auth.json` | **no** | yes | **no** | yes |
| Reaches the internet | no | **no** | no | yes |
| Browser-reachable | yes | **no** | no | **no** |

Rules that make this real rather than aspirational:

- `api` has **no** `/var/run/docker.sock` mount, no docker CLI, no
  `dockerode`. A CI test asserts the socket is absent from the `api` container
  and that no `DOCKER_HOST` is set.
- `api` has **no** mount of `/srv/msout/vault`. It cannot read a cookie jar
  even if it wants to. This is what lets §2.2 give Caddy a read-only mount of
  the artifact tree only.
- `orchestrator` is on an `internal: true` network. It has no route to the
  internet and no published port.
- The orchestrator's HTTP surface is a **fixed verb set**. Runner argv is built
  from a template in orchestrator code. There is no endpoint that accepts a
  command, an image, a mount, a flag, a network name or a path from a caller.
  Full compromise of the orchestrator's API therefore buys the attacker the
  fixed runner invocation and nothing else.

#### `api` → `orchestrator` authentication

A bearer token alone is not enough, because the threat is a *replayed* request to
an endpoint that can create containers. Requirements:

- **Signed, not bare.** Every call carries
  `X-Msout-TS: <unix ms>` and `X-Msout-Sig: base64url(HMAC-SHA256(secret, …))`
  where the signed string is
  `TS + "\n" + METHOD + "\n" + path + "\n" + sha256hex(body)`.
- **Replay window: 60 s.** A timestamp older or newer than the window is
  rejected outright. A 60 s window accepts a clock skew up to 60 s, which is
  acceptable and does not need a nonce table.
- **Audience and path binding are in the signature**, so a signature captured for
  `GET /stats` cannot be replayed as `POST /release` on another path. A body
  digest is included so a signed GET cannot be re-pointed at a POST.
- **Deny by default.** The verb set is an explicit allowlist in orchestrator
  config. An unknown method or path is `404`, never a default branch.
- **Constant-time comparison**, and the secret comes from a Docker secret —
  never an env var, never a file inside a bind mount the runner can read.
- `api` holds this secret; nothing else on the host does. `orchestrator` refuses
  to start if the secret is missing rather than falling back to open access.

CI assertion: replaying a captured request with the same signature after 61 s
fails; a request with no signature fails; a signed `stats` call replayed as
`release` fails.
- Orchestrator restart must reconcile against SQLite (§4, boot reconciliation)
  without resurrecting an expired session. It is a second reconciler, so the
  rules in v2 §2.5 are stated for both processes and split: `orchestrator`
  reconciles containers against labels; `api` reconciles sessions against
  SQLite. Neither trusts the other's view alone.

#### Egress, made testable

§2's diagram asserts `orchestrator` has **no egress** and runners have
**restricted egress**. Both are claims until a test tries to leave. Enforcement
plus assertion:

| Container | Egress policy | Enforcement | Assertion |
|---|---|---|---|
| `api` | none | `internal: true` network, no published port | TCP connect to an external host fails, from inside the container |
| `orchestrator` | none | `internal: true` network, no published port | same, **and** an outbound DNS query fails |
| `runner` | restricted, to Microsoft only | egress proxy or firewall allowlist on the host | connection to a non-Microsoft host fails; connection to `login.microsoft.com` succeeds |
| Caddy | to `api` only | network membership | no route to the runner network |

The runner row is the one that matters and the one most likely to be wrong:
runners legitimately need `login.microsoft.com`, `onenote.cloud.microsoft`,
SharePoint hosts and asset CDNs that are **tenant-specific and not enumerable in
advance**. So the allowlist is dynamic — derived from hosts observed during a
real login — and the control that must hold regardless is the *deny* direction:
a runner cannot reach the Docker socket, the internal networks, or the metadata
service. Assert both, and treat an expanding allowlist as a review event rather
than a silent config change.

**Metadata service and private ranges are denied by default on every container**
(`169.254.169.254`, `10/8`, `172.16/12`, `192.168/16`, plus the host gateway).
On a cloud VPS that is a credential-theft path, and it is cheap to close.

Egress tests run in CI against production-like flags, and a nightly job re-runs
them against the live configuration, because an allowlist that only CI can see is
not the one the daemon uses.

### 2.2 Vault / artifact split

v2 mounted one tree and let Caddy `file_server` it, which meant Caddy could
also read `auth.json` — a live Microsoft cookie jar. v3 separates them:

- `orchestrator` performs the artifact `stat` for the download authoriser, so
  `api` needs no filesystem access to decide authorisation.
- `api` decides authorisation from SQLite (session valid, artefact belongs to
  it, not expired). `orchestrator` only reports `{exists, size}`.
- Caddy gets `/srv/msout/artifacts` **read-only** and nothing else.

Net effect: the component in the credential path (Caddy) and the component that
decides who may download (api) can *neither* read session data. This is a
genuine improvement over v2, and the split is what makes it cheap.

Cost: the streaming zip is written by the runner into its artifact dir and
finalised under an `artifactId` by the orchestrator. Slightly more moving
parts, worth it.

### 2.3 About the socket proxy

A `docker-socket-proxy` sidecar is **not** in this design. It would need
`POST=1` to create runners, and `POST` on the containers API is root-equivalent,
so it would reduce nothing. Being honest about that is better than shipping a
control that only looks like one. If rootless Docker or Podman becomes
desirable, that is a real containment upgrade — tracked as v2 work in §11,
alongside the caveat that it interacts with the Chromium sandbox (v2 §5.2).

---

## 3. The credential path

### 3.1 Unchanged, and now cross-origin

The browser holds the password. It `POST`s to the **Component B** origin
directly. Component A is not in the path and cannot be, because the SPA makes
this call with `fetch` against an absolute API URL.

Enforcement, carried from v2 §4.2, plus the split-specific ones:

- No JSON body parser on the credential route in `api`.
- `undici` streaming; no buffering, no accumulation.
- `Content-Length` checked before proxying; hard cap ~4 KB.
- Stream destroyed immediately past the cap.
- `X-CSRF-Token` header **required** (§3.3), which forces a CORS preflight —
  so the browser will not transmit the body unless CORS approves the origin.
- Body logging off in Caddy and `api`, asserted in CI (§13).
- `Authorization` never logged. Only cookies reach this route.
- Component A never sees this request — asserted by test, and by the `.htaccess`
  / static config having no `/api` route at all.
- `Cache-Control: no-store` set on the response, and the route is never
  prefetched. A credential response is not cacheable anywhere in the chain.

**Why the cross-origin call is not a new leak.** The obvious objection is that
sending a password to a *different* host is riskier than sending it to the same
one. It is not, here, and the reason is worth stating because it is the whole
point of the split:

- The request goes to Component B over TLS, exactly as it would in the single-host
  design. No new hop was inserted into the credential path — the front end was
  never in it, in either plan.
- The front end cannot read the response, cannot observe the request, and cannot
  be substituted into the path, because it is a different origin and the browser
  enforces that. In the single-host design a compromise of the Fastify process
  yielded both the credential path and the UI; §2.1 removes that.
- The one genuinely new exposure is **a hostile bundle on Component A could try to
  phish the password rather than route it to the API**. `connect-src` (§1.5)
  and `form-action 'none'` bound that: the credential must leave for the API
  origin, so a substituted bundle can at worst redirect a user who retypes it
  somewhere, which is a visible social-engineering outcome rather than a silent
  programmatic capture. This is a real weakening relative to a single
  operator-controlled origin, it is bounded, and §13 T-F6 is the test for it.

### 3.2 Privacy wording

v2 §4.3 wording stands **unchanged**. It is already accurate and the split does
not alter it, because Component A is not an intermediary.

> Credentials are transmitted over TLS and are proxied to your isolated session
> container **without parsing, logging, or persistence** by the application
> server. Only the runner container processes the credential. It is never
> written to disk, and it is gone when you erase your session.

Do not add "and the frontend host never sees them" to the user-facing text
without also stating that the frontend and the API are different servers — the
sentence is more reassuring, not less accurate, but it invites the question and
the answer should be on the page.

### 3.3 CORS and CSRF are now load-bearing

This is the part of the split that is genuinely new. Four independent layers,
each of which alone blocks classic CSRF, so no single failure is fatal:

1. **`X-CSRF-Token` on every non-`GET`.** A custom header is not
   CORS-safelisted, so the browser must preflight. The preflight only succeeds
   for an allowlisted `Origin`. **A non-allowlisted origin cannot cause the
   browser to transmit a state-changing request body at all.** This is the
   structural layer, and it covers the credential route as well as
   `export` / `abort` / `erase`.

   Token derivation: `csrf = base64url(HMAC-SHA256(csrf_key, session_id))`,
   where `csrf_key` is per-session, generated server-side, and stored alongside
   the session row. The token is delivered in a **readable** cookie
   `msout_csrf`; the browser echoes it in the header. `api` requires
   `timingSafeEqual` on the match. Not a random value stored per request —
   derived, so there is no server-side token table to keep consistent.

2. **`Origin` allowlist, checked server-side, on every non-`GET`.** If `Origin`
   is present and not in `ALLOWED_ORIGINS`, reject. Independent of layer 1:
   protects any future route that forgets the header.

3. **`Content-Type` pinning.** All mutating routes except the credential route
   require `application/json`. The credential route is covered by layers 1 and
   2; it deliberately accepts whatever the client sends, because pinning a
   content type on a body we refuse to parse is theatre.

4. **Cookie hardening.** `__Host-msout` (which forbids a `Domain` attribute, so
   a compromised sibling subdomain cannot shadow it), `Secure`,
   `HttpOnly`, `SameSite=None` (required — the two origins are cross-site),
   `Path=/`. `SameSite=Lax` is **not** sufficient here: `Lax` cookies are not
   sent on cross-site `fetch`, so the whole app breaks, and "fix" it by going to
   `None` without noticing the CSRF implication is exactly the failure this
   section exists to prevent.

Startup assertions, so a bad environment fails loudly rather than silently
opening the service:

- `ALLOWED_ORIGINS` non-empty; every entry `https:`; no `*`; no `null`; no
  trailing slash; no entry with a path.
- Reflection of `Origin` only from the allowlist — never a blanket reflect.

CI and runtime tests:

- `ACAO` **absent** for a foreign `Origin`, on success, on `4xx`, on `5xx`, and
  on the preflight. Error handlers setting global headers is the classic way
  this leaks.
- `Vary: Origin` on every CORS-managed response.
- A cross-origin `POST` from an unlisted origin with a valid-looking cookie
  returns `403` and changes no state.
- `Access-Control-Allow-Credentials: true` appears **only** alongside a
  non-wildcard `ACAO`.

**CORS is not an access control.** It constrains browsers, not `curl`. Every
authorisation decision is server-side. The backend is fully usable with no
frontend at all, and must stay so — that is the honest boundary, and §10 T5
treats direct-to-backend traffic as the normal abuse case, not an edge case.

### 3.5 Client IP and rate limiting

PLAN-v2 §10 imposes layered per-IP limits (3 sessions/hour per IPv4, 3–5 per
IPv6 `/48`, plus global caps) and §10 T5 says direct-to-API traffic is the normal
abuse case. Both are only meaningful if `api` knows who the caller is. Under the
split the caller is behind a proxy it does not control, so this has to be stated
mechanically or the entire abuse-control layer of v2 is decorative.

**`api` derives the client address from the socket peer, not from headers.**

- Caddy is the only reverse proxy in front of `api`, and it is **not** in front
  of `api` for public traffic — Caddy and `api` sit on the same host on an
  internal compose network. Traffic reaches `api` either directly (a user hitting
  `api.<domain>`) or through Caddy.
- Caddy sets `X-Forwarded-For` itself and **appends** to any existing value;
  `api` takes the **rightmost** entry, which is the address Caddy actually saw.
  It never takes the leftmost, and never trusts a bare `X-Real-IP`.
- On the internal network path, where a request cannot have come from the
  internet, the peer address is authoritative and no header is consulted.
- A deployment that puts a CDN or load balancer in front of Caddy must update
  this rule explicitly. The default is fail-closed: if the peer is not a known
  proxy, the peer address is used as-is.

Why the rightmost, and why not simply "strip inbound headers": stripping is
correct but brittle, because it is a Caddy directive that a future config edit
can silently drop. Rightmost-plus-known-peer is checkable in CI.

Additional rules:

- Retain only truncated or hashed addresses for limiting (v2 §10), and keep the
  raw value in memory no longer than the current request.
- Rate-limit on **session and account identity as well as IP**. Direct-to-`api`
  access means an attacker with one IP can burn many sessions; the global caps
  are the backstop, and the per-session export cap still binds.
- **Reject a request whose `X-Forwarded-For` chain is longer than the number of
  known proxies**, rather than guessing. A spoofed chain is a strong signal.

CI assertions (§13): a request with a forged `X-Forwarded-For` from an unlisted
proxy is limited as its real peer; a forged chain from a listed proxy resolves to
the rightmost hop; `X-Real-IP` alone changes nothing.

### 3.4 What is deliberately not done

Browser-side credential encryption (ECDH + AES-GCM) stays deferred, as in v2
§13.3. The split does not change the argument: it defends against passive log
inspection, which §3.1 covers, and a compromised `api` can substitute keys
regardless. Note that a compromised **Component A** is a *new* argument
against it, since a hostile frontend could substitute the ephemeral key — so
this deferral is a real decision with a real cost, and it is revisited if
Component A is ever hosted somewhere the operator does not control equally.

---

## 4. Session auth

v2 §13.1's pre-launch blocker becomes a **v1 requirement**. Not optional, not
deferred, because the split removes the same-origin justification.

- GUID stays the identifier. Never in a URL path. The SPA route is a generic
  `/session`; the GUID lives in the session cookie's server-side lookup and in
  the SPA's in-memory store.
- The operator supplies a 256-bit secret, client-generated:
  `crypto.getRandomValues(new Uint8Array(32))` → base64url, 43 chars. GUID:
  `crypto.randomUUID()`, 122 bits, never shortened.
- The API **mechanically rejects** anything that is not exactly 43 base64url
  characters. Weak-secret rejection does not rely on the frontend being honest.
  CI also asserts the generation module's implementation.
- `api` stores `sha256(secret)` and compares with `timingSafeEqual`. It never
  stores or logs the secret.
- Cookie attributes per §3.3. CSRF key per §3.3.
- Everything is erased with the session (§11), including the CSRF key.

Client-side generation is *better* in this split, not worse: Component A
generates the secret and posts it to Component B, so **the frontend host never
sees the secret even in transit**. The tradeoff is that a compromised Component A
could generate a weak secret — which is why the API validates length rather than
trusting the client.

`apiProtocol` (§7.2) is part of this handshake: a `417`-style version mismatch
on session restore renders a "reload" prompt rather than a broken page.

Auth-expiry preflight remains deferred (v2 §13.2), with the re-login
affordance on export failure. Unchanged. The split does not alter it, and the
failure mode is still ambiguous — the plan should not pretend otherwise.

---

## 5. Artifacts

Unchanged mechanics, three v3-specific changes.

1. **Opaque artifact ids.** v2's `file_server root /srv/msout/sessions` implied
   download paths containing the session GUID and the notebook name. Both leak:
   the GUID into Caddy access logs, the notebook name into any `Referer`. v3
   downloads are `GET /files/<artifactId>` where `artifactId` is
   `crypto.randomBytes(32)` → base64url, mapped to a path in SQLite. No GUID,
   no notebook name, no hint in the URL. Notebook name goes in
   `Content-Disposition`, which is not logged.
2. **Partial labelling is server-enforced.** The response carries
   `X-Artifact-Partial: 1` and the filename is suffixed `.partial.zip`. A
   partial vault must not be mistakable for a complete one, and that must not
   depend on the UI being correct.
3. **Direct authorised serving.** Unchanged: `forward_auth` to `api`, then
   `file_server` with `sendfile` and `Range`. Multi-gigabyte downloads never
   pass through Node. Because the download is a top-level navigation from the
   frontend origin, the `SameSite=None` cookie is sent — which is correct and is
   another reason `SameSite=None` is unavoidable rather than chosen.

```caddy
handle /files/* {
  forward_auth api:3000 {
    uri /internal/authorize-download
    copy_headers Cookie
  }
  file_server {
    root /srv/msout/artifacts
  }
}
```

`/internal/authorize-download` is bound to the internal network only. It is not
a public endpoint and never appears in CORS.

---

## 6. Frontend changes beyond hosting

v2 §9 holds, with these deltas:

- **API base URL is build-time configuration**, validated at boot: must be
  `https://`, must be an exact origin, and is checked against the version
  handshake (§7.2). No user-supplied base URL — that would be an open proxy
  from the operator's origin.
- **Refresh restore** (v2 §7.5) now restores against a cookie-authenticated API
  on another origin. `EventSource` needs `withCredentials: true`; without it
  every reconnect silently 401s and the UI shows "reconnecting…" forever. This
  is the single most likely v3 bug — test it explicitly (§13, T-S4).
- **`connect-src` includes the API origin only.** No other cross-origin
  destination, ever.
- `SSE` goes cross-origin: it needs `ACAO` + `ACAC` on the events route, and
  `Last-Event-ID` is CORS-safelisted so no extra allowed header is required.
- All user and Microsoft-supplied strings render as text. No
  `dangerouslySetInnerHTML`. Unchanged, and now more load-bearing, since
  notebook names and log lines are rendered on an origin we do not fully
  control.

---

## 7. Two deploys, two failure modes

Independent deploys are the point of the split, and they introduce a class of
bug v2 did not have: **skew**.

### 7.1 Bundle attestation

Hostinger builds the frontend (§1.4), so the served bytes are not guaranteed to
be the reviewed bytes. And hPanel users can edit `public_html` directly, so
tampering needs no code change either.

- CI produces `dist/ASSETS.sha256` (sorted, path + digest) and the CSP hash
  list.
- A post-deploy job fetches the live `index.html` and every asset it references
  and compares digests. Mismatch fails the deploy.
- The same check runs **on a schedule** (hourly), not only at deploy, because
  of direct filesystem write access.
- The job also asserts the served response carries the §1.5 headers, the
  expected CSP `connect-src`, and no external `<script>`/`<iframe>`/inline
  script lacking a hash.
- Optionally, the digest set is published as a signed release attestation
  (Sigstore or a cosign key) so the check is not merely "what the server
  currently claims is true" versus "what the server currently serves".

### 7.2 Protocol version handshake

```ts
// api
GET /api/public/version  ->  { protocol: 3, build: "…" }
// frontend, at boot
if (remote.protocol !== EXPECTED_PROTOCOL) → hard fail with "reload"
```

Rationale: a mismatched pair should say so. Without this, a v3 frontend against
a v2 API produces a confusing `404` or a silently missing SSE field, and the
natural reaction is to debug the wrong component.

`api` must not depend on the frontend being present. Nothing server-side reads
Component A.

### 7.3 Failure matrix

| Failure | User-visible | Security effect | Handling |
|---|---|---|---|
| Component A down | blank page / failed asset load | **none** — API is fully usable | Independent deploy is the mitigation; A carries no state so it cannot lose any |
| Component B down | page loads, actions fail, SSE reconnects | none | Retry + clear message; the SPA is static, so it still loads |
| Skew, A newer | version-mismatch screen | none | §7.2 |
| Skew, B newer | version-mismatch screen | none | §7.2 |
| A compromised | attacker-controlled JS in visitors' browsers | frontend XSS — see §10 T3 | CSP `connect-src` blocks credential exfiltration; `HttpOnly` blocks secret theft; every action re-checked server-side |
| A tampered (not code) | same as A compromised | same | §7.1 attestation |
| B compromised | full loss, by definition | total | Out of scope; it is the trusted component |
| Direct API access, no frontend | works | — | Expected; rate limits and all authorisation are server-side |
| Metadata service reachable from a container | none visible | cloud credential theft | denied by default on every container (§2.1), asserted in CI |
| Clock skew across `api` and `orchestrator` | `401` on internal calls, exports stall | availability, not exposure | NTP on both hosts; the 60 s replay window absorbs ordinary skew, and a hard failure is preferable to a silent accept |

---

## 8. Ledger — v2 control → v3 status

| v2 control | Status in v3 |
|---|---|
| §4 raw-stream credential forward | **preserved**, now cross-origin, plus mandatory preflight |
| §4.3 privacy wording | **preserved verbatim** |
| §2 SQLite authoritative, labels recovery only | **preserved**, plus `orchestrator` as a second reconciler |
| §2.1–2.3 TTLs, bind/rebind, 5-min recycle | **preserved unchanged** |
| §2.4 atomic slot claim | **preserved** |
| §2.5 boot reconciliation | **preserved**, split across two processes |
| §2.6 pool exhaustion messaging | **preserved** |
| §5 runner flags, no `--no-sandbox`, userns requirement | **preserved unchanged** — untouched by the split |
| §5.3 sandbox integration test | **preserved**, still the gate for everything after it |
| §5.5 memory watchdog, §5.6 no dumps | **preserved** |
| §6 package changes | **preserved unchanged** |
| §7 SSE contract, ring buffer, replay, keepalive, multi-tab | **preserved**, now cross-origin with `withCredentials` |
| §8.1 concurrency, 409/429 | **preserved** |
| §8.2 abort preserves partial | **preserved** |
| §8.3 streaming zip, quota, disk guard | **preserved** |
| §8.3 direct serving | **strengthened** — opaque ids, Caddy cannot read `auth.json` |
| §9 CSP / headers / no third-party JS | **strengthened** — `connect-src` and `form-action` are load-bearing |
| §10 layered rate limits, MS-block detection | **preserved, now specified** — enforcement in `api`, and client IP is derived from the socket peer (§3.5) so the per-IP layers are not decorative |
| §11 erase state machine | **preserved**, slightly simpler — vault and artifact deletion are independent and both orchestrator-owned |
| §12 health, drain, log retention, quotas | **preserved**, with `api` and `orchestrator` health separate |
| §12.5 supply chain, GHCR by digest | **strengthened** by §7.1 attestation |
| §13.1 GUID + 256-bit secret | **promoted to v1** |
| §13.2 no auth-expiry preflight | **deferred, unchanged** |
| §13.3 no browser-side credential encryption | **deferred, unchanged** |
| §16 acceptance tests | **extended** — §13 |

---

## 9. Invariants restated as assertions

These hold in v3 and should be stated once, in one place, so they can be
grepped and tested rather than re-derived from prose.

1. Credential bytes are handled only by: the browser, TLS, Caddy, `api`'s
   socket, the runner. Never by Component A, never by `orchestrator`.
2. `api` cannot reach the Docker socket, and cannot read `/srv/msout/vault`.
3. `orchestrator` cannot reach the internet and accepts no caller-supplied
   command, image, flag, mount, network or path.
4. Caddy cannot read `/srv/msout/vault`.
5. The session secret is `HttpOnly` and is never in a URL, a log line, or the
   frontend bundle.
6. Every state-changing API route requires a valid CSRF token **and** passes
   the `Origin` allowlist.
7. No CORS-managed response carries `Access-Control-Allow-Origin` for a
   non-allowlisted origin, in any status class.
8. No download URL contains a GUID or a notebook name.
9. A frontend compromise yields no credential and no session secret, only the
   ability to act as the user within that user's own 12-hour session.
10. Component A never proxies, and never holds secrets or state.
11. The client IP used for rate limiting is derived from the socket peer, and a
    request cannot influence it by sending headers.
12. No container can reach the cloud metadata service, the Docker socket, or an
    internal network other than the one it is attached to.
13. No `--dodump` or `--screenshot` code path is reachable from the service.

---

## 10. Threat deltas

New in v3. Each with the control that answers it.

| # | Threat | Control |
|---|---|---|
| T1 | **CSRF** — `SameSite=None` cookie is sent on cross-site requests | §3.3, four independent layers. Layer 1 makes it structurally impossible for a browser to send the body at all |
| T2 | **CORS foot-gun** — wildcard or reflect-everything, or ACAO leaking on error responses | Exact allowlist, no reflection, `Vary: Origin`, CI asserts ACAO absent for foreign origins in **all** status classes (§13) |
| T3 | **Frontend XSS / compromise** — the origin that displays the password form is on someone else's box | `HttpOnly` secret (no theft); `connect-src` limited to the API (no exfiltration); `form-action 'none'`; `frame-ancestors 'none'`; every action re-checked server-side; 12h absolute cap bounds the damage |
| T4 | **Frontend bundle tampering** — Hostinger runs the build; hPanel can write `public_html` | §7.1 digest attestation, scheduled, plus strict CSP that blocks injected script execution by anything not `'self'` |
| T5 | **Direct-to-API access bypassing the frontend** | CORS is not an access control and is never treated as one. All rate limits, authorisation and validation in `api`. The API is complete and usable standalone |
| T6 | **Deploy skew** | §7.2 `apiProtocol` handshake |
| T7 | **Erasure must span two hosts** | v2 §11 state machine, extended: the *directory* is on Component B, but the *cookie* is on the browser. Erase must invalidate the server row **and** set an expired cookie, or a stale tab keeps a live-looking session. Add this step to the machine |
| T8 | **Privacy claims drift** — "we never see your password" is now a claim about two servers | §3.2 wording unchanged and audited; no new claim added without naming both servers |
| T9 | **Secret generation now client-side** | API validates 256-bit length mechanically; CI asserts the generator |
| T10 | **Two origins, two TLS/HSTS/PKI configurations** | HSTS `includeSubDomains` on both; TLS versions pinned; a CI probe checks both origins' chains, since a broken chain on Component A is a credential-form failure that looks like a user error |
| T11 | **Password phishing / habit training** — the service logs users in by replaying credentials, which normalises handing Microsoft passwords to websites | §0.2 records this as a product decision with the technical reasons it cannot be an OAuth flow here. Controls: PLAN-v2 §9.3 consent text **extended** to say the service may change account terms and security state during login; §3.2's exact privacy wording; and the frontend must state that a fully local alternative exists (`microsoft-onenote-exporter`) and that this service is unofficial |
| T12 | **Rate-limit evasion by header forgery** — `api` behind a proxy cannot tell a real IP from a claimed one | §3.5: socket peer is authoritative, rightmost-`XFF` only from a known proxy, chain-length rejection, per-session and global caps as backstop. Without this, PLAN-v2 §10's per-IP layers are unenforced |
| T13 | **Replay against the container-creating endpoint** — the orchestrator can spawn containers | §2.1: HMAC over timestamp + method + path + body digest, 60 s window, constant-time compare, deny-by-default verb allowlist, secret from a Docker secret |
| T14 | **Egress from a container** — stated as policy, unproven | §2.1 egress table: per-container allow/deny, metadata service and RFC1918 denied by default, asserted in CI and nightly against the live config |

---

## 11. Known limitations of v3

| Limitation | Consequence | Fix |
|---|---|---|
| CSRF defence is load-bearing | Removing the CSRF header check, or relaxing CORS, silently opens a full session-takeover path on a service handling Microsoft credentials | §13 tests fail the build; §3.3 is quoted in the security section of the README |
| Component A is outside operator control | hPanel compromise, or an `.htaccess` rewrite, serves hostile JS | Bounded by T3; attestation detects it. Not fixable, only contained |
| Hostinger builds the bundle | Not reproducible to the byte by construction | §7.1 attestation is detection, not prevention |
| `SameSite=None` is required | Ambient credential exists for cross-site requests; correctness depends on CSRF being right | Accepted deliberately. `Bearer` auth would remove the class but breaks `EventSource` and refresh-restore (v2 §7.5) |
| `api` restart drops SSE connections | Clients reconnect and replay from the ring buffer | v2 §7.4 already specifies this; now also triggered by Component A being irrelevant to it |
| Rootless Docker not used | Docker socket is root-equivalent, held by one process | v2; see §2.3 for why the socket proxy was not used |
| No auth-expiry preflight | Ambiguous export errors | v2 §13.2, v1.1 |
| Erase is `rm -rf` + best-effort shred | Not a cryptographic erase | v2 §11, LUKS in v2 |
| Runner egress allowlist is dynamic | A tenant-specific SharePoint host cannot be enumerated in advance, so the allowlist grows during a real login | Deny direction is the enforceable control (§2.1); growth is a review event (T-N5). A future build could resolve hosts per-export instead |
| Credentials are replayed, not delegated | The service trains users to hand Microsoft passwords to a web app; phishing thrives on the habit | §0.2, T11. Cannot be fixed inside this architecture without replacing the three packages |
| Consent text must describe account changes | `microsoft-webauth` auto-accepts updated Terms of Use and consent pages, which **changes the user's account** | §0.2 and T-F7: the consent copy states it. The v2 §9.3 wording understates it |

---

## 12. Work sequence delta

PLAN-v2 §15, reordered. Steps 1–4 are unchanged and still first — the package
changes and the sandbox test remain the risky part, and the split does not
reduce them.

1. **Package changes with tests** *(v2 §15.1, unchanged)*
2. **Runner sidecar + hardened container** *(unchanged)*
3. **Chromium sandbox integration test** *(unchanged — still blocks everything)*
4. **Orchestrator**, standalone, driven by `curl`. First, because it is now
   independently testable and it is the component with the most authority.
   Includes the HMAC auth (T-I1…T-I7) and the egress policy (T-N1…T-N6), since
   both are properties of this component and are cheaper to get right before
   anything depends on it.
5. **`api` without the orchestrator** — SQLite, pool manager, claim, sweepers,
   boot reconciliation.
6. **Caddy + compose + GHCR + CI deploy** for Component B, with the socket
   absence assertions.
7. **Credential path** with CI log-grep assertions across the sinks.
8. **SSE hub**, cross-origin, with `withCredentials` reconnect tests.
9. **Artifact pipeline** — streaming zip, quota, disk guard, opaque ids, direct
   download, vault/artifact split.
10. **CORS + CSRF + cookie**, with the full foreign-origin test matrix.
11. **Client IP resolution** (§3.5) with T-P1…T-P5. Before rate limiting, not
    after — retrofitting it means finding every call site that read the wrong
    field.
12. **React UI** — landing, session page, export flow, refresh restore.
13. **Component A on Hostinger** — build, inline-CSP-hash plugin, headers,
    static serving (or the §1.3 header-only process).
14. **Bundle attestation** job, then `apiProtocol` handshake.
15. **Rate limits + Microsoft-block detection.**
16. **Erase state machine**, including the two-host step (T7), plus orphan
    sweep tests.

Note on ordering: step 11 precedes step 15 deliberately. The rate limiter is
only correct if the client address is, and building it first means the limiter
consumes one well-defined input instead of a header someone may have trusted.

Moving the orchestrator to step 4 is the only real reordering, and it is
forced: `api` cannot be tested end-to-end without it, and testing it with a
mock would validate the wrong boundary.

---

## 13. New acceptance tests

In addition to all of PLAN-v2 §16, which still applies.

### Credential path
- **T-A1** The credential request is issued to the Component B origin. A test
  asserts Component A's configuration exposes no `/api` route and returns `404`
  for `/api/*`.
- **T-A2** Log-grep for a canary password across Caddy access, Caddy error,
  `api`, `orchestrator`, runner, host, **and the frontend build logs**.
- **T-A3** The §1.3 file-server process, if used, makes zero outbound requests.
  Assert with an egress log, not by inspection.
- **T-A4** No code path in the frontend sends a credential to any origin other
  than the API. Asserted by grepping the built bundle for request targets, and
  by a browser-level test that fails on any request to a non-API host while the
  login form is submitted.
- **T-A5** The credential response carries `Cache-Control: no-store`, and the
  route is absent from any prefetch configuration.

### CORS / CSRF
- **T-C1** Foreign `Origin` → no `ACAO`, on `200`, `400`, `403`, `429`, `500`
  and on preflight.
- **T-C2** Valid cookie from a foreign origin, `POST /export` → `403`, and the
  export does not start.
- **T-C3** `POST` without `X-CSRF-Token` → `403`.
- **T-C4** Mismatched CSRF token → `403`, compared in constant time.
- **T-C5** `SameSite=None`, `Secure`, `HttpOnly`, `Path=/`, and **no `Domain`
  attribute** (the `__Host-` requirement).
- **T-C6** Startup fails loudly on an `ALLOWED_ORIGINS` value containing `*`,
  `null`, a non-`https` entry, a path or a trailing slash.
- **T-C7** `api` is fully usable with no frontend deployed at all.

### Frontend
- **T-F1** Served CSP `connect-src` contains the API origin and nothing else.
- **T-F2** No external `<script>`, `<iframe>` or unhashed inline script in the
  served HTML.
- **T-F3** `ASSETS.sha256` matches the live deployment; the scheduled job
  catches a manual `public_html` edit.
- **T-F4** All §1.5 headers present on both origins; HSTS `includeSubDomains`.
- **T-F5** Protocol mismatch renders the version-mismatch screen, not a
  broken page.
- **T-F6** A test injects a script tag into the built bundle and asserts CSP
  blocks its execution. This is the assertion behind T3; do not skip it.
- **T-F7** The consent text shown before the password field states that login may
  change account terms and security state, names the service as unofficial, and
  mentions that a fully local alternative exists. Asserted against the rendered
  string, because this is a claim to the user rather than a mechanism.

### SSE
- **T-S4** `EventSource` is constructed with `withCredentials: true`;
  disconnect and reconnect across origins replays missed events.
- **T-S5** A stale `Last-Event-ID` yields a snapshot.

### Capability separation
- **T-X1** The `api` container has no Docker socket and no
  `/srv/msout/vault` mount, asserted by inspecting the running container.
- **T-X2** `orchestrator` has no published port and no route off-host. Also
  assert it is not a member of the `msout-runner` network and holds no volume.
- **T-X3** No orchestrator endpoint accepts a command, image, flag, mount,
  network or path from a caller. Asserted by enumerating its request schema.
- **T-X4** Caddy cannot read a vault path; asserted by an actual request
  through the download route with a crafted filename.
- **T-X5** The runner image exposes no debug surface: `--dodump` and
  `--screenshot` are unreachable from the sidecar's HTTP API, asserted by
  enumerating sidecar routes. This is the operational form of PLAN-v2 §5.6 and
  of invariant 13.

### `api` → `orchestrator` authentication
- **T-I1** An unsigned call to any orchestrator endpoint fails.
- **T-I2** A captured, correctly signed request replayed after 61 s fails.
- **T-I3** A signature captured for `GET /stats` replayed as `POST /release`
  fails (path/method binding).
- **T-I4** A signature over an empty body replayed with a body fails (body
  digest binding).
- **T-I5** An unknown method or path is `404`; there is no default branch.
- **T-I6** `orchestrator` refuses to start when the secret is absent.
- **T-I7** Signature comparison is constant-time (asserted by code inspection
  plus a timing smoke test with a loose threshold).

### Egress
- **T-N1** `api` cannot open a TCP connection to an external host from inside
  the container.
- **T-N2** `orchestrator` cannot, and an outbound DNS query from it fails.
- **T-N3** `runner` cannot reach a non-Microsoft host, and **can** reach
  `login.microsoft.com` — the deny direction and the allow direction are both
  tested, because an allowlist that blocks everything passes T-N3's first half.
- **T-N4** No container can reach `169.254.169.254`, the Docker socket, or
  `172.17.0.1`.
- **T-N5** The runner's dynamic host allowlist is a visible config change, not a
  silent growth: widening it fails CI unless the diff is reviewed.
- **T-N6** A nightly job re-runs T-N1…T-N4 against live configuration.

### Client IP (§3.5)
- **T-P1** A forged `X-Forwarded-For` from an unlisted proxy is rate-limited as
  its real socket peer.
- **T-P2** A request from a listed proxy with a multi-hop chain resolves to the
  rightmost hop.
- **T-P3** `X-Real-IP` alone changes nothing.
- **T-P4** An `X-Forwarded-For` chain longer than the known-proxy count is
  rejected, not guessed.
- **T-P5** Retained rate-limit keys are truncated or hashed; a raw address does
  not appear in logs or in SQLite.

### Erasure
- **T-E1** Erase invalidates the server row **and** expires the cookie, in
  both orders, including when the row is already gone.

---

## 14. Licence

Unchanged: MIT, consistent with the family. Consumes the four packages from npm;
does not fork them. The frontend does not depend on them at all (§1.6).

The three packages consumed by the runner are `@msout/microsoft-webauth`,
`@msout/microsoft-onenote-list-notebooks` and
`@msout/microsoft-onenote-export-notebook`. §0.2 records why the Graph API and
MSAL alternatives are unavailable for this use case, with the upstream
documentation as the source.

Upstream licensing note, carried from `microsoft-webauth`'s own README: the
Microsoft Q&A page preserved in
`microsoft-onenote-export-notebook/docs/graphapi-sharepoint-notebook-limit-evidence.pdf`
is **Microsoft's content, not this project's**, and is quoted as evidence outside
the MIT licence. Nothing in that file is vendored into this repository.
