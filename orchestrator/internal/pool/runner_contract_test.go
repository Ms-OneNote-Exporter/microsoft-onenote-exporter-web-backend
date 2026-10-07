package pool

// The runner's required environment and mounts.
//
// These exist because the orchestrator and the runner are two implementations of
// one contract that cannot see each other. `internal/pool/runner.go` builds the
// create request; the runner's image reads its environment and expects certain
// mounts. Nothing in either repository compared the two, so three requirements
// were simply absent and **all three fail silently**: the container starts, then
// the pool never binds it, and a login waits on a slot that is never handed out.
// Every check in the orchestrator passes throughout.
//
// The counterpart test is runner/tests/contract.test.ts, which reads both files.
// This one is the orchestrator's half, and it asserts the properties directly
// against a built request rather than by reading source.

import (
	"strings"
	"testing"
	"time"
)

// A runner that cannot pass its health check never binds, so the health check the
// create request names has to be a file this repository can expect the image to
// have. The image builds `src/healthcheck.ts` to `dist/healthcheck.js`, and
// tsconfig emits beside the entry point.
func TestCreateRequestNamesAHealthCheckTheImageActuallyHas(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.HealthConfig == nil || len(req.HealthConfig.Test) == 0 {
		t.Fatal("no health check in the create request; a runner would be bound blind")
	}

	joined := strings.Join(req.HealthConfig.Test, " ")
	if !strings.Contains(joined, "/app/dist/healthcheck.js") {
		t.Errorf("health check = %q, want a probe of /app/dist/healthcheck.js", joined)
	}
	// The start period has to be *long* enough to cover a Chromium launch, which
	// is tens of seconds on a cold container. An earlier version of this asserted
	// the opposite — start period must be shorter than the interval — which is
	// simply wrong: a slow-starting runner would be failed and recycled during the
	// one window it is allowed to come up in.
	if req.HealthConfig.StartPeriod < req.HealthConfig.Interval {
		t.Errorf("start period %v is shorter than the %v interval; a runner "+
			"still booting would be failed rather than given room",
			req.HealthConfig.StartPeriod, req.HealthConfig.Interval)
	}
	if req.HealthConfig.Retries < 2 {
		t.Errorf("retries = %d; a single transient probe failure would mark a "+
			"working runner unhealthy", req.HealthConfig.Retries)
	}
}

// The runner refuses to start without a token file. That is deliberate on its
// side — a default token would accept requests from anything that can reach the
// container, and this process holds credential bytes — which makes the
// environment entry and the mount a hard requirement rather than a nicety.
func TestCreateRequestSuppliesTheRunnerToken(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "MSOUT_RUNNER_TOKEN_FILE=/run/secrets/runner_token"
	if !containsEnv(req.Env, want) {
		t.Errorf("env = %v, want it to contain %q", req.Env, want)
	}

	token := mountFor(req, "/run/secrets/runner_token")
	if token == nil {
		t.Fatal("no runner_token mount; the runner exits 1 at startup")
	}
	if !token.ReadOnly {
		t.Error("the token mount must be read-only; a writable secret is a writable secret")
	}
	// A *file* source. A directory source would let a compromised runner replace
	// the token it is presented, which defeats the point of presenting one.
	if token.Type != "bind" {
		t.Errorf("token mount type = %s, want bind", token.Type)
	}
	if token.Source != cfg.RunnerTokenFile {
		t.Errorf("token source = %q, want the configured %q — a runner presented "+
			"a token from anywhere else is a token the orchestrator does not know",
			token.Source, cfg.RunnerTokenFile)
	}
}

// The token is a *path* in the environment, never the value. An env var is
// visible in `docker inspect` and in /proc/<pid>/environ to anything that can read
// the container's config — including a container with no business knowing it.
func TestRunnerTokenIsNeverInlinedIntoTheEnvironment(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, entry := range req.Env {
		if strings.HasPrefix(entry, "RUNNER_TOKEN=") || strings.Contains(entry, "RUNNER_TOKEN=ghcr") {
			t.Errorf("env carries an inline token: %q", entry)
		}
	}
}

// The root filesystem is read-only, which is deliberate. It means /artifacts has
// to be a mount: without one the runner completes an export and then fails at the
// last step with nowhere to put the archive, which is the worst possible time to
// discover it.
func TestCreateRequestMountsTheArtifactRoot(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	artifacts := mountFor(req, "/artifacts")
	if artifacts == nil {
		t.Fatal("no /artifacts mount; a read-only rootfs leaves the runner nowhere to write an archive")
	}
	if artifacts.Source != cfg.ArtifactRoot {
		t.Errorf("artifact source = %q, want %q — the runner and ArtifactStat must read the same tree",
			artifacts.Source, cfg.ArtifactRoot)
	}
	if artifacts.ReadOnly {
		t.Error("/artifacts must be writable; the runner streams the zip into it")
	}
}

// The artifact tree must not be reachable from a runner that is not bound to a
// session... except that it is, deliberately: an idle runner holds it empty. What
// must never happen is a *vault* mount on an idle runner, which is asserted in
// TestIdleRunnerHoldsNoVaultMount. This one pins the narrower invariant that the
// artifact mount never becomes a vault mount by accident.
func TestArtifactMountIsNeverTheVault(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	for _, guid := range []string{"", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"} {
		req, err := p.buildCreateRequest("slot-1", "c-1", guid, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		artifacts := mountFor(req, "/artifacts")
		if artifacts == nil {
			t.Fatalf("no /artifacts mount for guid %q", guid)
		}
		if strings.HasPrefix(artifacts.Source, cfg.VaultRoot) {
			t.Errorf("artifact mount points into the vault: %q", artifacts.Source)
		}
	}
}

// Unattended export: a password-protected section waits for a keypress that can
// never arrive in a container, so the flag that skips it is a hard requirement
// rather than a preference.
func TestRunnerRunsUnattended(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The log directory has to be inside the session tree, or an erase leaves the
	// packages' HTML dumps — which contain live cookies — on the host forever.
	logDir := envValue(req.Env, "ONENOTE_EXPORT_LOG_DIR")
	if logDir == "" {
		t.Fatal("no ONENOTE_EXPORT_LOG_DIR; dumps would land outside the session")
	}
	if !strings.HasPrefix(logDir, "/data") {
		t.Errorf("log dir = %q, want it under /data so erase takes it with the session", logDir)
	}

	// Notheadless would put a browser window nobody can reach on a headless host.
	for _, entry := range req.Env {
		if strings.Contains(strings.ToUpper(entry), "NOTHEADLESS") {
			t.Errorf("env sets %q; a runner must be headless", entry)
		}
	}
}

// A bound runner holds exactly one vault mount, its own session's. Counted by
// source rather than by total, so the artifact and token mounts are a non-event
// for the property this protects.
func TestBoundRunnerHoldsOnlyItsOwnSessionVault(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	other := "11111111-2222-3333-4444-555555555555"

	req, err := p.buildCreateRequest("slot-1", "c-1", guid, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var vaultMounts []string
	for _, m := range req.Mounts {
		if strings.HasPrefix(m.Source, cfg.VaultRoot) {
			vaultMounts = append(vaultMounts, m.Source)
		}
	}
	if len(vaultMounts) != 1 {
		t.Fatalf("bound runner has %d vault mounts, want exactly 1: %v", len(vaultMounts), vaultMounts)
	}
	if !strings.Contains(vaultMounts[0], guid) {
		t.Errorf("vault mount = %q, want this session's %q", vaultMounts[0], guid)
	}
	// And it is not the other session's, which is the property a second mount
	// would be trying to satisfy.
	if strings.Contains(vaultMounts[0], other) {
		t.Errorf("vault mount points at another session: %q", vaultMounts[0])
	}
}

func containsEnv(env []string, want string) bool {
	return envValue(env, strings.SplitN(want, "=", 2)[0]) == strings.SplitN(want, "=", 2)[1]
}

func envValue(env []string, name string) string {
	for _, entry := range env {
		if strings.HasPrefix(entry, name+"=") {
			return strings.TrimPrefix(entry, name+"=")
		}
	}
	return ""
}
