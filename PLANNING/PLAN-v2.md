# PLAN-v2 — microsoft-onenote-exporter-web

Revision of [`PLAN.md`](./PLAN.md) after consolidated review
([`reviews/PLAN-REVIEW-byQWEN3.8.md`](./reviews/PLAN-REVIEW-byQWEN3.8.md)).

Three review findings forced architectural changes: the credential path was not
implementable as written, the number-matching MFA model was factually wrong, and
the fixed 12-hour container hold was a self-inflicted denial of service. All
three are corrected below.

Two review recommendations were **deliberately declined** and are recorded in
§14 as accepted risk. §13 explains why.

---

## 0. What changed from PLAN.md

| # | Change | Driver |
|---|---|---|
| 1 | Credential path → Fastify **raw-stream forward**, no body parsing | PLAN.md's Caddy dynamic route was not implementable |
| 2 | Privacy wording corrected — no longer claims the app never sees bytes | overclaim |
| 3 | **Number-matching MFA corrected** to a single passive number | PLAN.md was factually wrong; verified against `auth.js:1459-1482` |
| 4 | **Container lifetime decoupled** from session lifetime; idle TTLs added | 12h hold was a DoS |
| 5 | SQLite is authoritative for state; Docker labels are recovery metadata only | slot-claim races |
| 6 | MFA failures must not be swallowed; structured error codes added | silent failures hang containers |
| 7 | SSE contract specified: event IDs, ring buffer, `Last-Event-ID`, keepalive | unspecified |
| 8 | Artifact pipeline: streaming zip, quotas, disk guard, direct serving | disk exhaustion |
| 9 | Runner hardening expanded: `--init`, `--shm-size`, tmpfs, watchdog | container crashes |
| 10 | CSP, CORS, security headers, self-hosted React added | missing |
| 11 | Layered rate limits, Microsoft-block detection added | abuse |
| 12 | Erase became a state machine with orphan sweep | partial-failure data leaks |
| 13 | Acceptance tests added per subsystem | untestable plan |
| 14 | **GUID-only auth deferred to a named pre-launch blocker** | declined for v1 |
| 15 | **Auth-expiry preflight declined** | declined for v1 |

---

## 1. Decisions

| Area | Decision |
|---|---|
| Credentials | Browser POSTs to Fastify; **raw-stream forwarded, never parsed** |
| Privacy wording | "proxied without parsing, logging or persistence" |
| MFA | Injectable prompt; **stdin retained as CLI fallback** |
| Number-match MFA | **Single number, passive approval on device** |
| Isolation | One container per active session, dynamically assigned |
| Container lifetime | Idle TTL / post-export recycle. **Data lifetime stays 12h** |
| Session secret | **GUID only in v1.** GUID + 256-bit secret = pre-launch blocker |
| Hosting | Single VPS, `docker compose` + Caddy, 48 GB |
| Packages | Extended in place, versions bumped |
| New code | This repo. TypeScript, Fastify + React, self-hosted |
| State store | **SQLite (WAL) authoritative.** Docker labels = recovery only |
| Auth validity | `auth.json` existence trusted. **Expiry preflight declined** — §14 |
| Download | Streaming zip, quota + disk guard, direct authorized serving |
| Long export | Live SSE with replay, interrupt button |
| Concurrency | One export per session; global cap; `409`/`429` |
| Protected sections | Skipped, placeholders preserved |
| Erase | State machine, best-effort secure delete, orphan sweep |
| Abuse | Layered IP / IPv6-subnet / global limits, Microsoft-block detection |
| Deploy | Public repo, GHCR, CI runs `compose pull && up` |

---

## 2. Lifetime model

The core correction. **Session data and container lifetime are independent.**

### 2.1 TTLs

| State | TTL |
|---|---:|
| GUID created, no login started | 10 min |
| Login in progress | 15 min |
| Authenticated, idle | 30 min |
| Export running | no idle kill; absolute 12h cap applies |
| Export complete | container recycled after 5 min |
| Session data + artifacts | up to 12 h |
| Absolute session age | 12 h |

### 2.2 Consequences

- A session that exports in 10 minutes releases its ~1.5 GB within minutes,
  not hours.
- An attacker claiming 12 sessions and closing their tabs holds nothing for more
  than 10 minutes.
- Throughput is bounded by **concurrency**, not by 12h holds.
- The user-visible "12h session" is unchanged: data, artifacts and the countdown
  all persist for 12h.

### 2.3 Bind / rebind

1. GUID created → **session row only**. No container.
2. Login requested → atomic claim of an idle runner, session volume mounted.
3. Idle TTL hit → container removed or recycled, session row retained.
4. Activity again → new runner claimed, **same session volume remounted**, so
   `auth.json`, notebook cache and artifacts are all still there.
5. Absolute 12h cap → session row destroyed, volume deleted.

### 2.4 State authority

SQLite in WAL mode is the **only** live source of truth.

```sql
PRAGMA journal_mode = WAL;

CREATE TABLE runners (
  id              TEXT PRIMARY KEY,
  container_id    TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN
                    ('idle','claimed','active','draining','dead')),
  health          TEXT NOT NULL DEFAULT 'unknown',
  last_health_at  INTEGER,
  session_guid    TEXT
);

CREATE TABLE sessions (
  guid             TEXT PRIMARY KEY,
  runner_id        TEXT,
  state            TEXT NOT NULL,
  auth_state       TEXT NOT NULL DEFAULT 'none',
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  idle_expires_at  INTEGER,
  last_activity_at INTEGER NOT NULL,
  notebook         TEXT
);
```

Atomic claim, then verify `changes() > 0` before creating the session row:

```sql
BEGIN IMMEDIATE;

UPDATE runners
SET status = 'claimed', session_guid = :guid
WHERE id = (
  SELECT id FROM runners
  WHERE status = 'idle'
  ORDER BY RANDOM()
  LIMIT 1
);

COMMIT;
```

Docker labels (`msout.session.guid`, `.expires`, `.state`) are **recovery,
inspection and boot-reconciliation metadata only**. They are never the lock.

### 2.5 Boot reconciliation

On start: compare SQLite against `docker ps`.

- Adopt live containers whose labels match a valid session.
- Destroy orphaned containers and orphaned session directories.
- Mark sessions whose runner vanished as needing rebind.
- Never resurrect an expired session.

### 2.6 Pool exhaustion

When no runner is idle, the waiting page shows the earliest of
(`session.idle_expires_at`, `session.expires_at`) minus now. If all sessions are
active exports, say so plainly rather than showing a countdown that will not
move.

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────┐
│ Browser  • self-hosted React  • SSE with replay            │
└───────────────────────────┬────────────────────────────────┘
                            │ HTTPS
                            ▼
┌────────────────────────────────────────────────────────────┐
│ Caddy                                                     │
│  • TLS termination, HSTS                                  │
│  • static assets                                          │
│  • NO request/response body logging                       │
│  • forward_auth for protected downloads                   │
│  • file_server for artifacts (Range, sendfile)            │
└───────────────────────────┬────────────────────────────────┘
                            ▼
┌────────────────────────────────────────────────────────────┐
│ App — Fastify + TypeScript                                │
│  • SQLite authoritative state (WAL)                       │
│  • pool manager + atomic slot claim                       │
│  • idle-TTL sweeper + orphan sweep                        │
│  • SSE hub with ring buffer and replay                    │
│  • credential raw-stream forwarder (no parsing)            │
│  • artifact authorization                                 │
│  • rate limiter                                           │
│  • Docker manager via restricted socket                   │
└───────────────────────────┬────────────────────────────────┘
                            │ internal Docker network
                            ▼
┌────────────────────────────────────────────────────────────┐
│ Runner pool — runner-1 … runner-N                         │
│  • Fastify sidecar                                        │
│  • @msout packages                                        │
│  • Playwright Chromium                                    │
│  • host-mounted session volume                            │
│  • /healthz, SSE events, abort, streaming zip             │
└────────────────────────────────────────────────────────────┘
```

---

## 4. Credential path

### 4.1 Correction to PLAN.md

PLAN.md claimed:

> Caddy routes `POST /s/:guid/cred` straight to the runner.

This is not implementable as a static Caddyfile. There are N runners with a
runtime GUID→runner mapping; a static config cannot know it, and driving Caddy's
admin API per session is race-prone. **That claim is withdrawn.**

PLAN.md also claimed credentials are "never seen by application code". Under any
proxying design, the proxy and the app touch the bytes. **That claim is
withdrawn as technically false.**

### 4.2 Chosen design — raw-stream forward

Browser POSTs to Fastify. Fastify **does not parse the body** and streams the
raw request to the assigned runner, which parses it inside the container.

Enforcement, all of it mechanical rather than aspirational:

- No JSON body parser attached to the credential route.
- `undici` streaming client; no buffering, no accumulation.
- `Content-Length` checked before proxying; hard cap (~4 KB).
- Stream destroyed immediately if the cap is exceeded.
- Request timeout.
- Body logging disabled in Caddy **and** Fastify, asserted in CI.
- Redacted headers; `Authorization` never logged.
- Source comments in both configs marking the route as never-log.

### 4.3 Privacy wording

Use exactly this, on the page and in the privacy note:

> Credentials are transmitted over TLS and are proxied to your isolated session
> container **without parsing, logging, or persistence** by the application
> server. Only the runner container processes the credential. It is never
> written to disk, and it is gone when you erase your session.

Never claim it "never exists in RAM". A proxy necessarily holds it briefly.

### 4.4 Deferred hardening

Browser-side encryption to a per-session runner keypair (ECDH P-256 + AES-GCM via
WebCrypto) so intermediaries see only ciphertext. Deferred: it defends mainly
against passive log inspection, which §4.2 already covers, and a compromised app
can still substitute keys. Revisit only if a hosting arrangement makes Caddy or
the app less trusted than they are here.

---

## 5. Runner image and runtime contract

### 5.1 Flags

```sh
docker run \
  --init \
  --shm-size=1g \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=512m,uid=1000,gid=1000 \
  --tmpfs /home/node/.cache:rw,noexec,nosuid,size=512m,uid=1000,gid=1000 \
  -v /srv/msout/sessions/<guid>/data:/data:rw \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=512 \
  --memory=2560m --memory-swap=2560m \
  --cpus=2 \
  --user=node \
  --network=<restricted-runner-network> \
  runner-image
```

Rationale for each non-obvious flag:

- `--init` — Node as PID 1 will not reap zombie Chromium processes.
- `--shm-size=1g` — Docker's 64 MB default crashes Chromium.
- `--tmpfs` — the writable set under a read-only rootfs: `/tmp` and the
  Playwright cache. Nothing else may be written.
- `--pids-limit=512` — must be validated against real Chromium; too low breaks
  the browser.
- `--memory=2560m` — 2 GB proved tight in review; validate against a real large
  notebook and raise if needed.
- `--memory-swap` pinned equal to `--memory` so a runaway cannot silently swap.

### 5.2 Chromium sandbox

**Do not pass `--no-sandbox`.** It is the tempting container default and it
disables the renderer sandbox — the reason for isolating untrusted notebook
content in a browser in the first place.

Required host settings, documented in the README and verified by a CI test:

```
kernel.unprivileged_userns_clone=1        # where applicable
kernel.apparmor_restrict_unprivileged_userns=0
```

Host OS and kernel versions are pinned in the README. Kernel support for
unprivileged user namespaces is not uniform across distributions, so this is
stated as a requirement, not an assumption.

### 5.3 Sandbox integration test

Must run in CI against production-like flags:

1. Launch the hardened container.
2. Start Playwright Chromium.
3. Load a local harmless page.
4. Assert the renderer process is sandboxed.
5. Assert `/dev/shm` is sufficient for a multi-tab load.
6. Assert clean exit with no zombies.

### 5.4 Documented fallback

If user namespaces cannot be enabled on the host, `--no-sandbox` is permitted
**only** with all of: no docker socket, no host network, no privileged mounts,
restricted egress, non-root user, read-only rootfs, tight memory and PID limits,
and no access to internal management APIs. This fallback is documented and
revisited; it is never applied silently.

### 5.5 Memory watchdog

The sidecar samples browser and Node RSS. Above ~80% of the container limit it
aborts the export gracefully, marks the artifact partial, restarts the browser,
and emits a user-visible event — so the OOM killer is a last resort, not the
primary mechanism.

### 5.6 Never enable dumps

`--dodump` and `--screenshot` are unreachable from the service. Per the
export-notebook README, dumps contain authenticated DOM with live cookies and
tenant hostnames. No debug override exists.

`ONENOTE_EXPORT_LOG_DIR=/data/logs`.

---

## 6. Package changes

All additive, backwards compatible, released before the service needs them.

### 6.1 `microsoft-webauth` 0.1.8 → 0.2.0

```ts
login({
  email, password, authFile,
  promptCode?,   // (challenge) => Promise<string>; absent ⇒ stdin fallback
  onEvent?,
  signal?,
})
```

#### Challenge model — corrected

PLAN.md's `{ kind: 'number-match', numbers: [n1, n2] }` with a sidecar-tapped
**Accept** button was **wrong**. Verified against `auth.js:1459-1482`: number
matching shows a single number, the user approves in Microsoft Authenticator, and
the page waits passively for the element to disappear. There is no Accept button
to click, and `promptUser` is never called on that branch.

```ts
type Challenge =
  | { kind: 'code'; label: string; timeoutMs: number }
  | { kind: 'number-match'; code: string; timeoutMs: number };
```

Sidecar behaviour for number-match: emit `challenge`, then **wait passively** for
navigation or element-hide. Emit `challenge-seen`, `challenge-expired`,
`login-success`, `login-failed`, `login-cancelled`.

#### Events

```ts
type WebAuthEvent =
  | { type: 'progress'; message: string }
  | { type: 'challenge'; challenge: Challenge }
  | { type: 'challenge-expired' }
  | { type: 'captcha-required' }
  | { type: 'microsoft-blocked'; reason: string }
  | { type: 'success' }
  | { type: 'failed'; code: string; message: string };
```

Error codes: `bad_credentials`, `mfa_timeout`, `mfa_rejected`, `captcha_required`,
`account_locked`, `network_error`, `selector_changed`, `aborted`, `unknown`.

#### Errors must not be swallowed

`auth.js:1502-1504` currently wraps the whole MFA block in
`catch { logger.debug('…skipped or failed') }`. A swallowed challenge is a
**hang** in a container, not an error. The new paths must reject or emit
`failed`, never return quietly.

**Compatibility constraint:** `entrypoint.sh` in export-notebook deliberately
exits 0 so partial exports survive. Strict rejection is scoped to the new
`signal` / `onEvent` paths; the CLI's existing tolerant behaviour is preserved.

#### Selector robustness

Prefer ARIA labels, roles and text matching. Do not add brittle CSS selectors
tied to current Microsoft markup. If an expected screen is not found, emit a
structured error rather than hanging.

### 6.2 `microsoft-onenote-export-notebook` 0.3.7 → 0.4.0

```ts
runExport({
  authFile, notebook | notebookLink, outputDir,
  signal?,     // abort traversal, KEEP what is on disk
  onEvent?,    // page | section | group | asset | done | partial, with counts
})
```

- On abort: stop traversal, preserve partial output, mark artifact partial.
- Emit counts so the UI can render a real progress bar.
- Emit quota/disk errors cleanly rather than throwing raw `ENOSPC`.
- Reuse unchanged: `--non-interactive`, exit codes `0/1/2/3`,
  `ONENOTE_EXPORT_LOG_DIR`, log rotation.

### 6.3 `microsoft-onenote-list-notebooks`

- Add `signal` support — **required, not optional**, so cancel is prompt.
- Abort promptly and report cleanly.

### 6.4 `microsoft-onenote-exporter`

Untouched.

---

## 7. SSE contract

```
GET /api/session/events
```

Authorised by session cookie. Every event carries a monotonically increasing
`id:`. The server honours `Last-Event-ID`.

### 7.1 Event types

```
session-status   auth-state      login-started   challenge
challenge-expired login-success  login-failed    auth-expired
notebooks-listed export-queued   export-started  export-progress
export-log       export-aborted  export-done     export-partial
error            keepalive
```

### 7.2 Buffer

Bounded ring buffer per session: last **500 events** or **2 MB**, whichever is
hit first. If `Last-Event-ID` has fallen out of the buffer, send a `snapshot`
event with current state rather than a gap.

### 7.3 Keepalive

SSE comment `: keepalive` every **15 s**, to survive proxy and mobile idle
timeouts.

### 7.4 Reconnect and multi-tab

`EventSource` reconnects automatically; on reconnect, replay from the buffer or
send a snapshot. The UI shows **reconnecting…** while the stream is down.

Multiple tabs share one fan-out. Mutating actions are **server-authorised** — if
one tab starts an export, all tabs see it; if one aborts, all tabs update.

### 7.5 Frontend restore

On mount: `GET /api/session/status`, then connect SSE. Restore auth state,
notebook list, active export, progress, log tail, download availability and the
expiry countdown. **A refresh mid-export must not require restarting it.**

```json
{
  "session":  { "state": "active", "expiresAt": "…", "idleExpiresAt": "…" },
  "auth":     { "state": "valid", "lastCheckedAt": "…" },
  "notebooks":{ "state": "loaded", "items": ["Personal", "Work"] },
  "export":   { "state": "running", "id": "export-123",
                "progress": { "pages": 120, "sections": 8, "assets": 340 },
                "partial": false },
  "artifact": { "available": false, "partial": false }
}
```

Expiry is ISO-8601 absolute; the client computes remaining time and derives a
clock offset from server time.

---

## 8. Concurrency, abort, artifacts

### 8.1 Concurrency rules

**Per session:** one active export. A second `POST /export` returns
`409 Conflict`. The UI disables the button while an export runs.

**Global:** hard cap on concurrent exports. Over the cap returns
`429` with retry guidance. No complex global queue in v1.

### 8.2 Abort

Stops traversal, preserves what is on disk, marks the artifact partial, emits
`export-aborted` and `export-partial`, and still offers the partial download
clearly labelled.

### 8.3 Artifact pipeline

1. **Streaming zip** (`archiver`), not system `zip` — avoids a second full copy
   of the data and the disk spike that causes.
2. **Per-session quota** (5–10 GB, tuned to host disk). Exceeding it aborts
   cleanly and marks the export partial with a clear user-facing error.
3. **Host free-space guard** — below threshold, new exports rejected with
   `507 Insufficient Storage`. Never let an export OOM the Docker daemon or the
   host.
4. **Direct authorized serving** — artifacts live on the host-mounted session
   directory; the app authorises via cookie, then Caddy serves with `sendfile`
   and `Range`. Multi-gigabyte downloads never stream through Node.

```caddy
handle /files/* {
  forward_auth app:3000 {
    uri /internal/authorize-download
    copy_headers Cookie
  }
  file_server {
    root /srv/msout/sessions
  }
}
```

If direct serving proves impossible: `fs.createReadStream` with proper `Range`,
never buffered in memory.

### 8.4 Partial artifacts

Preserve exported files. Finalise a partial zip where possible, otherwise expose
raw files as a separate artefact. Partial downloads are **labelled partial** in
the UI — a partial vault must not be mistaken for a complete one.

---

## 9. Frontend

Fastify serves a React build. **No CDN, no third-party JS, no analytics, no
remote fonts.** Lockfile enforced in CI; dependency audit in CI.

### 9.1 Landing

GUID input plus **generate for me** (`crypto.randomUUID()`, 122 bits — never
shorten it). The generated GUID is shown with a copy button and an explicit
warning that it cannot be recovered.

### 9.2 Page B

Sticky banner: **erase session** (inline confirmation, not a modal route),
**github project** (new tab), **donate**, countdown timer.

Three blocks:

1. **Authenticate** — email + password. ToS consent checkbox (§9.3). On a
   challenge, the block switches to a code input, or to a number-matching view:
   show the number prominently, say *"open Microsoft Authenticator and enter this
   number"*, show a **countdown**, offer **cancel login**. **No Approve button** —
   approval happens on the phone.
2. **List notebooks** — greyed until `auth.json` exists; each name clickable to
   fill block 3.
3. **Export** — name or URL, live SSE log panel, **interrupt**, download link on
   completion.

Multi-tab synchronised via §7.4.

### 9.3 Consent before the password field

Unchecked by default:

> I understand this tool will automatically accept Microsoft's Terms of Use and
> security prompts on my behalf during login.

Also stated: the service is unofficial; credentials go to Microsoft; Microsoft
may request MFA; Microsoft may block automated logins from datacenter IPs.

### 9.4 Headers

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
Cache-Control: no-store
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Strict-Transport-Security: …
```

Log lines, notebook names and Microsoft strings render as **text**. No
`dangerouslySetInnerHTML` anywhere. CORS locked down: runner sidecars are never
browser-reachable, app APIs are same-origin.

---

## 10. Abuse controls

Layered, because per-IP alone is weak — IPv6 gives one user many addresses, and
residential proxies defeat IP limits entirely.

| Limit | Baseline |
|---|---|
| Sessions / hour / IPv4 | 3 |
| Sessions / hour / IPv6 /48 | 3–5 |
| New sessions / hour / global | 20–30 |
| Exports / hour / session | 5 |
| Exports / hour / global | 30–60 |

Tune after observing real traffic. Additionally:

- Exponential backoff on repeated Microsoft login failures; temporary lockout.
- Only truncated or hashed IPs retained for limiting.
- **No passwords, no full GUIDs in logs.**
- Detect CAPTCHA and datacenter-IP blocks; emit `captcha-required` /
  `microsoft-blocked` and tell the user honestly: *"Microsoft has challenged this
  server's IP. Try again later, or use the local CLI exporter."*

No CAPTCHA. Third-party challenge widgets would break the no-third-party-JS
commitment. If abuse becomes a real problem, the consistent option is a
proof-of-work challenge or invite codes during early launch — not Turnstile.

---

## 11. Erase

A state machine, because container removal and directory deletion are two
operations and a partial failure leaks data.

1. Mark session `erasing`.
2. Abort any active login or export.
3. Freeze runner activity.
4. Best-effort secure delete: `auth.json`, exported files, zip artifact, logs.
5. Delete session directory.
6. Remove or recycle the container.
7. Delete or tombstone the SQLite row.
8. Reclaim the runner slot.

Failure handling: directory deletion failure → `erase_failed`, keep a retry
record, sweep periodically, alert on repeats. Container removal failure → force
remove; if still failing, mark the runner unhealthy and quarantine.

`shred -u` / `rm -P` where supported, with the limits of CoW, SSD wear
levelling and overlayfs understood rather than glossed over.

**UI wording:** *"We deleted everything this service stored for this session."*
Never *"nothing remains anywhere."*

---

## 12. Operations

### 12.1 Health

`GET /healthz` per runner reports sidecar alive, browser launch possible, disk
writable, auth state, active jobs. The app polls, drains unhealthy runners,
replaces them, and **never assigns a session to an unhealthy runner**.

### 12.2 Deploy drain

`compose pull && up` can kill active exports. Before deploying: refuse new
sessions, let active exports finish up to a timeout, preserve partial artefacts,
record state for recovery. Minimum for v1: documented that deploys may interrupt
exports, plus a maintenance banner — and do not deploy mid-export when avoidable.

### 12.3 Log retention

50 MB per session max, rotate at 10 MB, keep 3 rotated files, delete with the
session. No passwords, no full GUIDs, no full IPs beyond what limiting needs.

### 12.4 Quotas

Per-session disk quota, max artefact size, host free-space threshold, abort on
exceed.

### 12.5 Supply chain

Lockfile in CI, `npm audit`, images from GHCR pinned by digest. **Donation
addresses committed to the repository** for auditability rather than living only
in environment variables, since env vars are supply-chain mutable.

---

## 13. Where this plan departs from the review

The review recommended all of the following. Three were declined, with reasons.

### 13.1 GUID-only auth in v1 — deferred, tracked as a launch blocker

The review says GUID-in-URL is unacceptable for a service handling Microsoft
credentials, and moves the 256-bit secret to v1. Agreed on the merits — URLs leak
through history, sync, screenshots, extensions, corporate TLS inspection and
misconfigured logs, and entropy does not fix structural leakiness.

Declined for v1 so the simple "enter a GUID, go to your session" UX survives the
first build. **This is a named pre-launch blocker, not a vague future
improvement.** Before any public launch:

- GUID stays the identifier.
- A 256-bit secret authorises, held in `HttpOnly`, `Secure`,
  `SameSite=Strict` cookie, stored server-side as a hash.
- Session UI served from a generic `/session`, not `/session/:guid`.
- CSRF defence on state-changing routes.

### 13.2 No auth-expiry preflight — accepted risk

The review wants `checkAuth()` before listing and exporting. Declined for v1;
`auth.json` existence is trusted for the 12-hour window.

**Known limitation, stated plainly:** Microsoft cookies can expire or be
invalidated. A session that logs in at 10:00 and exports at 12:30 can present an
inscrutable export error. This is worse than it sounds, because
`microsoft-onenote-export-notebook`'s own README documents a crashed OneNote tab
producing the same class of error — so the failure cannot be reliably diagnosed
from the outside, and no user-facing explanation is available.

Mitigating, not fixing: a **re-login affordance appears on any export failure**,
so the user has a way out even when the cause is ambiguous. That is a button,
not a diagnosis.

v1.1 fix: `checkAuth()` preflight before list and export, emitting `auth-expired`
and re-enabling the authentication block while preserving existing artefacts.

### 13.3 No browser-side credential encryption in v1 — deferred

Option B was considered and deferred. It defends primarily against passive log
inspection, which §4.2's enforced no-logging already covers, and a compromised
app can still substitute keys. It adds ECDH and AES-GCM key management to a
project whose dominant risk is Playwright selector fragility against a changing
Microsoft UI.

### 13.4 Accepted, no dissent

The corrected number-matching model, the decoupled container lifetime, SQLite
authority, non-swallowed MFA errors, the SSE contract, streaming zip with quotas,
the expanded runtime contract, CSP, and layered rate limits are all adopted as
recommended.

---

## 14. Known limitations of v1

Deliberate, documented, not oversights.

| Limitation | Consequence | Fix |
|---|---|---|
| GUID is the sole credential | A leaked URL is a full takeover: cookies + exports | §13.1, pre-launch |
| No auth-expiry preflight | Expired sessions present as inscrutable export errors | §13.2, v1.1 |
| Erase is `rm -rf` + best-effort shred | Not a cryptographic erase; CoW/SSD may retain blocks | LUKS, v2 |
| No sandbox fallback exercised | If userns unavailable, `--no-sandbox` weakens isolation | §5.4 |
| Pool capacity is static | Concurrency capped regardless of spare RAM | v2 |
| No session recovery | A lost GUID means a lost session, by design | accepted |
| Deploys can interrupt exports | Drained, not eliminated | §12.2 |

---

## 15. Work sequence

Risk is concentrated in steps 1–4, not 1–2 as PLAN.md claimed.

1. **Package changes with tests** — corrected challenge model, non-swallowed
   errors, `signal`, `onEvent`, error codes. CLI compatibility preserved.
2. **Runner sidecar + hardened container** — curable end to end with `curl`.
3. **Chromium sandbox integration test** under production-like flags.
   Blocks everything after it.
4. **SQLite pool manager + atomic claim + TTL sweeper + boot reconciliation.**
5. **Credential path** with CI log-grep assertions across all four sinks.
6. **SSE hub** with ring buffer, replay, keepalive, multi-tab fan-out.
7. **Artifact pipeline** — streaming zip, quota, disk guard, direct download.
8. **React UI** — landing, page B, export flow, refresh restore.
9. **Caddy + compose + GHCR + CI deploy.**
10. **Rate limits + Microsoft-block detection.**
11. **Erase state machine + orphan sweep tests.**

---

## 16. Acceptance tests

### Slot allocation
- Two concurrent claims never receive the same runner.
- Exhaustion returns the correct countdown.
- Reboot recovers live sessions; orphans and orphan directories are cleaned.

### Credential path
- The app does not parse the credential body.
- Oversized bodies are rejected.
- No password appears in Caddy access logs, Caddy error logs, Fastify logs,
  runner logs, or host logs.
- GUIDs appear only as hashed prefixes.

### Session auth
- Session APIs reject requests without a valid credential.
- The secret is never present in a URL path or query.
- Refresh restores UI state.
- Erase invalidates the session.

### MFA
- Code challenge renders an input.
- Number-match renders **one** number and a countdown, with **no Approve
  button**.
- Expiry emits `challenge-expired`.
- Cancellation aborts cleanly.
- Failure returns a structured error and never resolves successfully.

### Export
- Progress events carry counts.
- Abort preserves partial output; partial is labelled partial.
- A second concurrent export returns `409`.
- The global cap is enforced; low disk rejects new exports.

### SSE
- Disconnect and reconnect replays missed events.
- A stale `Last-Event-ID` yields a snapshot.
- Keepalive survives proxy timeouts.
- Multiple tabs receive identical events.
- Refresh during export restores progress.

### Container runtime
- Chromium starts under production flags with the sandbox verified.
- `/dev/shm` is sufficient.
- Zombies are reaped.
- Read-only rootfs does not break Playwright.
- The watchdog fires before OOM.

### Artifacts
- Downloads support Range.
- Large downloads do not buffer in Node.
- One session cannot download another's artefact; expired sessions cannot
  download at all.

---

## 17. Licence

MIT, consistent with the rest of the family. Consumes the four packages from npm;
does not fork them.