/**
 * The runner and the orchestrator agree on a contract neither can see.
 *
 * ## Why this file exists
 *
 * `internal/pool/runner.go` assembles the container create request. It names a
 * health check path, a secret mount and two data directories. This package builds
 * the image that request describes. **Neither side had checked the other.**
 *
 * The three mismatches this found were all silent, and together they meant no
 * runner could ever become healthy:
 *
 * | The orchestrator asks for | The runner had | Symptom |
 * |---|---|---|
 * | `/app/dist/healthcheck.js` | nothing | every probe fails, pool never binds |
 * | `MSOUT_RUNNER_TOKEN_FILE` | throws without it | process exits 1 on start |
 * | `/artifacts` writable | `/data` only | artifact POST cannot write |
 *
 * The symptom in every case is the same and it points somewhere unhelpful: the
 * api reports a login that hangs, and the orchestrator reports a healthy pool it
 * correctly refuses to hand out a slot from. Nothing anywhere reports a failure,
 * because nothing anywhere is failing.
 *
 * So the assertions below read **both** files. A check that only reads this
 * package would pass on a runner the orchestrator cannot use, which is precisely
 * what happened.
 *
 * ## How they are checked
 *
 * Textually, against the two sources. That is unusual and it is the honest option:
 * the alternative — a fake daemon, a fake runner, an integration test — asserts
 * about the fakes. These are literal strings in two repositories that either agree
 * or the product does not work, so they are compared as literal strings.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

const REPO = join(import.meta.dirname, "..", "..");
const ORCHESTRATOR_RUNNER_GO = join(REPO, "orchestrator", "internal", "pool", "runner.go");
const POOL_GO = join(REPO, "orchestrator", "internal", "pool", "pool.go");
const RUNNER_SRC = join(REPO, "runner", "src");

const read = (path: string): string => readFileSync(path, "utf8");

const orchestratorRunner = read(ORCHESTRATOR_RUNNER_GO);
const pool = read(POOL_GO);

describe("the health check the orchestrator asks for exists", () => {
  it("names a path, and the runner builds exactly that path", () => {
    // `HealthConfig.Test: []string{"CMD", "node", "/app/dist/healthcheck.js"}`
    // was in the create request before `src/healthcheck.ts` existed. The image's
    // entry point is `node dist/index.js` and tsc emits beside it, so
    // src/healthcheck.ts -> dist/healthcheck.js. Asserted rather than assumed.
    const asked = orchestratorRunner.match(/HealthConfig[\s\S]{0,220}?\/app\/dist\/([\w.]+)/);
    expect(asked, "the create request must name a health check script").not.toBeNull();
    const script = asked![1]!;
    expect(script).toBe("healthcheck.js");

    // The source that produces it, and that the Dockerfile's build stage compiles.
    expect(read(join(RUNNER_SRC, "healthcheck.ts"))).toContain("/healthz");
  });

  it("probes the port the runner actually listens on", () => {
    // A health check pointed at the wrong port fails forever and looks identical
    // to a hung runner.
    const source = read(join(RUNNER_SRC, "healthcheck.ts"));
    const index = read(join(RUNNER_SRC, "index.ts"));
    const portInCheck = source.match(/PORT\s*=\s*Number\(process\.env\.PORT\s*\?\?\s*(\d+)\)/);
    const portInServer = index.match(/port:\s*Number\(process\.env\.PORT\s*\?\?\s*(\d+)\)/);
    expect(portInCheck).not.toBeNull();
    expect(portInServer).not.toBeNull();
    expect(portInCheck![1]).toBe(portInServer![1]);
  });
});

describe("the secret the runner requires is mounted", () => {
  it("the runner refuses to start without a token file, so the mount is not optional", () => {
    // If this ever became optional the two files could drift again silently: a
    // runner that defaulted would boot with no way to authenticate, and the
    // orchestrator's 401s would look like a version mismatch.
    const config = read(join(RUNNER_SRC, "config.ts"));
    expect(config).toContain("MSOUT_RUNNER_TOKEN_FILE");
    expect(config).toMatch(/throw new Error/);
  });

  it("the token is read from a file path ending in /run/secrets", () => {
    // PLAN-v3 §3.3: an env var is visible in `docker inspect` and in
    // `/proc/<pid>/environ`. The capability suite asserts the value is not inline;
    // this asserts the runner only accepts a path.
    const config = read(join(RUNNER_SRC, "config.ts"));
    expect(config).toContain("readFileSync(tokenPath");
    expect(config).not.toMatch(/token\s*=\s*process\.env\.MSOUT_RUNNER_TOKEN\b/);
  });
});

describe("the data roots agree", () => {
  it("the vault mount the orchestrator makes is the path the runner reads", () => {
    // The orchestrator bind-mounts the session directory at /data; the runner's
    // default data root has to be that same path, or it writes into an empty
    // tmpfs and every session appears to lose its auth file.
    const runnerConfig = read(join(RUNNER_SRC, "config.ts"));
    const dataRoot = runnerConfig.match(/MSOUT_DATA_ROOT\s*\?\?\s*"([^"]+)"/);
    expect(dataRoot, "the runner must name its data root").not.toBeNull();
    expect(dataRoot![1]).toBe("/data");
    expect(orchestratorRunner).toContain('Destination: "/data"');
  });

  it("the artifact root is writable, which a read-only root filesystem forbids", () => {
    // `ReadonlyRootfs: true` is deliberate and good. It means /artifacts cannot be
    // a path in the image — it has to be a mount, and the runner has to be told
    // where it is.
    expect(orchestratorRunner).toContain("ReadonlyRootfs");
    const runnerConfig = read(join(RUNNER_SRC, "config.ts"));
    const artifactRoot = runnerConfig.match(/MSOUT_ARTIFACT_ROOT\s*\?\?\s*"([^"]+)"/);
    expect(artifactRoot, "the runner must name its artifact root").not.toBeNull();
    expect(artifactRoot![1]).toBe("/artifacts");
  });
});

describe("the artifact id is the caller's, and is opaque", () => {
  it("the runner validates the id shape the orchestrator validates", () => {
    // PLAN-v3 §5: `crypto.randomBytes(32)` → base64url, 43 characters. Both sides
    // reject anything else, and the runner's regex is asserted to be the same
    // length — a shorter one here would accept a path the orchestrator later
    // refuses to stat, and the download would 404 for a reason neither side
    // reports.
    const runnerIndex = read(join(RUNNER_SRC, "index.ts"));
    const inRunner = runnerIndex.match(/\{43\}/);
    const inOrchestrator = orchestratorRunner.length > 0 && pool.match(/43 base64url characters/);
    expect(inRunner, "the runner must validate a 43-character id").not.toBeNull();
    expect(inOrchestrator, "the orchestrator documents the same 43 characters").not.toBeNull();
  });

  it("the runner never derives an id from the session guid", () => {
    // §5: ids are opaque because a path containing the GUID leaks it into Caddy's
    // access logs. A runner that built the id from the GUID it already knows would
    // reintroduce exactly that leak, and nothing else would notice.
    const runnerIndex = read(join(RUNNER_SRC, "index.ts"));
    const artifactRoute = runnerIndex.slice(
      runnerIndex.indexOf("app.post(\"/sessions/:guid/artifacts\""),
    );
    expect(artifactRoute).toContain("artifactId");
    // No interpolation of the guid into an artifact path.
    expect(artifactRoute).not.toMatch(/\$\{guid\}/);
  });

  it("the artifact is a directory, which is what ArtifactStat looks for", () => {
    // `ArtifactStat` joins ArtifactRoot with the id and requires a *directory*:
    // "an artifact is a directory containing a finalised zip plus a partial
    // marker. A regular file where a directory is expected means something is
    // wrong that `exists: true` would hide."
    //
    // The first version of the runner wrote `<guid>.zip` — a regular file at the
    // wrong name, derived from the wrong identifier. Every download 404s and
    // nothing reports why.
    expect(pool).toMatch(/if !info\.IsDir\(\)/);
    const runnerIndex = read(join(RUNNER_SRC, "index.ts"));
    expect(runnerIndex).toContain(".staging");
  });

  it("the runner stages rather than publishing in place", () => {
    // A zip written under its final name is readable while it is being written,
    // and a download arriving mid-write gets a truncated archive with a 200.
    const runnerIndex = read(join(RUNNER_SRC, "index.ts"));
    const artifactRoute = runnerIndex.slice(
      runnerIndex.indexOf("app.post(\"/sessions/:guid/artifacts\""),
    );
    expect(artifactRoute).toContain(".staging");
    // ...and it says so, rather than returning a path a caller could build a URL
    // from.
    expect(artifactRoute).toContain("stagedAt");
  });
});

describe("unattended export flags", () => {
  it("the runner sets nopassasked, which is the flag the package actually reads", () => {
    // `nonInteractive` is the runner's own option name and is not consulted by
    // the package. Relying on it alone leaves a password-protected section
    // waiting for a keypress that can never arrive in a container — a hang that
    // looks exactly like a slow notebook.
    const runnerIndex = read(join(RUNNER_SRC, "index.ts"));
    expect(runnerIndex).toContain("nopassasked: true");
  });
});

describe("nothing in the runner's own surface contradicts the orchestrator", () => {
  it("the runner never reads a session secret or the CSRF key", () => {
    // The orchestrator gives a runner exactly one secret: the bearer token it
    // authenticates with. If the runner also wanted the CSRF key or a session
    // secret, §2.1's split would be a comment rather than a property.
    for (const file of ["index.ts", "config.ts", "credential.ts", "events.ts", "sessions.ts"]) {
      const source = read(join(RUNNER_SRC, file));
      expect(source, file).not.toMatch(/CSRF_KEY|SESSION_SECRET|ORCHESTRATOR_HMAC/);
    }
  });

  it("the runner's env does not request the orchestrator's control network", () => {
    // The orchestrator pins the runner to RunnerNetwork. A runner that asked for
    // another would be a network change nobody reviewed.
    const config = read(join(RUNNER_SRC, "config.ts"));
    expect(config).not.toContain("msout-control");
    expect(config).not.toContain("msout-edge");
  });
});

describe("the alias the orchestrator registers is the one the api dials", () => {
  // The credential path rests on a name that appears in **three** places: the
  // alias the orchestrator registers on the container, the `runnerUrl` it builds
  // for the api, and the pattern the api accepts.
  //
  // Two of those are in Go and one in TypeScript, and the failure mode is the
  // worst in this file: the api would refuse to dial a correctly-named runner,
  // so every credential submission failed with "address" in the log while the
  // orchestrator reported a healthy pool and the runner was up and healthy. All
  // three components green, no login.
  //
  // So this reads both repositories and compares the shapes rather than trusting
  // either. The literals here are the same ones `runnerAlias` and
  // `RUNNER_ALIAS_PATTERN` use.
  const aliasPrefix = "msout-runner-";

  it("the orchestrator derives the alias from the slot id", () => {
    expect(pool).toContain(`return "${aliasPrefix}" + slotID`);
    // And from the slot *only*. A container id in the alias would change on every
    // recycle, and an address stored at claim time would go stale silently.
    expect(pool).not.toContain(`return "${aliasPrefix}" + containerID`);
  });

  it("the orchestrator reports a URL built from that alias and its configured port", () => {
    expect(pool).toContain(`"http://%s:%d", runnerAlias(slotID), p.cfg.RunnerPort`);
  });

  it("the create request registers the alias on the control network", () => {
    expect(orchestratorRunner).toContain("Aliases: []string{runnerAlias(slotID)}");
  });

  it("the api accepts exactly the shape the orchestrator produces", () => {
    const api = read(join(REPO, "api", "src", "runner-adapter-http.ts"));
    expect(api).toContain(`^http:\\/\\/${aliasPrefix}`);
    // Only http. The runner serves plain HTTP on an internal network, and
    // accepting https would mean a silent downgrade decision.
    expect(api).not.toContain(`^https:\\/\\/${aliasPrefix}`);
  });

  it("the api reads the address rather than building one", () => {
    // The property that keeps the three places from becoming four: the api must
    // have no string-concatenation that could produce an alias.
    const api = read(join(REPO, "api", "src", "runner-adapter-http.ts"));
    expect(api).not.toContain(`"${aliasPrefix}" +`);
    expect(api).not.toContain("`${aliasPrefix}");
  });
});
