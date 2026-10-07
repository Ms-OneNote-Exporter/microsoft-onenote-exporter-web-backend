/**
 * The runner's health check.
 *
 * ## Why this exists
 *
 * The orchestrator's create request already named it, before it existed:
 * `Test: []string{"CMD", "node", "/app/dist/healthcheck.js"}` in
 * `internal/pool/runner.go`. Nothing in this package provided it.
 *
 * The consequence was not a missing file. Docker starts the container, the CMD
 * runs, and the health check **fails every time** — so the container never
 * becomes healthy, the pool never binds it, and a login sits forever waiting for
 * a slot that the orchestrator correctly refuses to hand out. That reads as
 * "the pool is broken" from the api and as nothing at all from the orchestrator,
 * because every one of its own checks passed.
 *
 * So this file is the seam made explicit: one side had already decided what the
 * other side had to provide, and nothing compared them.
 *
 * ## What it reports
 *
 * Only what the daemon can act on. Docker uses the exit code and nothing else —
 * there is no output to parse and no port for the daemon to reach into — so the
 * body here exists for a human reading `docker inspect`, not for the runner
 * itself.
 */

const PORT = Number(process.env.PORT ?? 3100);

/** How long the probe may take before it counts as a failure. */
const TIMEOUT_MS = 4_000;

async function main(): Promise<void> {
  const url = `http://127.0.0.1:${PORT}/healthz`;

  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!response.ok) {
      process.stderr.write(`unhealthy: /healthz answered ${response.status}\n`);
      process.exit(1);
    }

    const body = (await response.json()) as { ok?: unknown };
    if (body.ok !== true) {
      process.stderr.write(`unhealthy: /healthz did not report ok\n`);
      process.exit(1);
    }

    // Deliberately terse. Docker discards stdout for a CMD health check, and a
    // line written here on every probe is a line in nobody's log.
    process.exit(0);
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    process.stderr.write(`unhealthy: ${detail}\n`);
    process.exit(1);
  }
}

void main();
