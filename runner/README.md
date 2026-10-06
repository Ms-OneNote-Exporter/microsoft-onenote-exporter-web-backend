# runner

Fastify sidecar + the unmodified `@msout` packages + Playwright Chromium. One
container per export session, started and destroyed by the orchestrator.

This is the only component that **sees the credential bytes** and the only one
that **reads `auth.json`**.

## Owns

- `POST` the credential, straight into `microsoft-webauth`. No JSON parser, no
  buffering — the `api` forwards it as a raw stream and the runner consumes it
  the same way.
- The three `@msout` packages, consumed from npm and **not forked**:
  `microsoft-webauth`, `microsoft-onenote-list-notebooks`,
  `microsoft-onenote-export-notebook`. `storageState` is the interchange format
  between them.
- The **streaming zip** into its artifact directory, finalised under an
  `artifactId` by the orchestrator — §2.2, §5.
- `/healthz`, SSE events, abort, quota and disk guard — §8.2, §8.3.

## Must never

- Expose a debug surface. `--dodump` writes a DOM dump containing
  authenticated cookies and tenant hostnames; `--screenshot` **cannot redact
  credential fields** because it is a bitmap, and it shows the number-match MFA
  code. In a hosted service either one is a credential artefact. Both are
  unreachable from the sidecar's HTTP API, asserted by enumerating its routes
  — `T-X5`, §9 invariant 13. **"No debug override" is a security control here,
  not a tidiness preference.**
- Reach the Docker socket, an internal network it is not attached to, or the
  cloud metadata service — `T-N4`.

## Chromium sandbox

The renderer sandbox stays on. `--no-sandbox` exists as a single named flag for
a host that cannot enable unprivileged user namespaces, and the **sandbox
integration test is the gate for everything after it** in the §12 build order.
Runner hardening is otherwise carried forward unchanged from v2 — the split
does not touch it: memory watchdog, TTLs, 5-minute recycle, PID and shm limits.

## Egress is restricted, and the allowlist is dynamic

Runners legitimately need `login.microsoft.com`,
`onenote.cloud.microsoft`, SharePoint hosts and asset CDNs that are
**tenant-specific and not enumerable in advance**. So the allowlist is derived
from hosts observed during a real login, and it is a **visible config change,
not a silent growth** — widening it fails CI unless the diff is reviewed
(`T-N5`).

The control that must hold regardless is the **deny** direction: a runner cannot
reach the Docker socket, the internal networks, `169.254.169.254`, the host
gateway, or RFC1918 ranges. Both directions are tested, because an allowlist
that blocks everything would pass the deny half of `T-N3` while breaking the
product. Metadata service and private ranges are denied on every container —
on a cloud VPS that is a credential-theft path, and it is cheap to close.

Egress tests run in CI against production-like flags, and a **nightly job
re-runs them against the live configuration**, because an allowlist that only CI
can see is not the one the daemon uses (`T-N6`).

## Not implemented yet

This directory is a placeholder. See `PLANNING/PLAN-v3.md` §12 steps 1–2. The
working prototype is in the archived POC repository; §5.6 of that design
carries forward unchanged, including the prohibition on dumps.
