package pool

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/dockerapi"
)

// testConfig returns a config rooted in a temp dir, with the pool sized for the
// test at hand.
func testConfig(t *testing.T, poolSize int) *config.Config {
	t.Helper()
	root := t.TempDir()
	return &config.Config{
		DockerSocket:         filepath.Join(root, "docker.sock"),
		HMACSecret:           []byte(strings.Repeat("a", 64)),
		ReplayWindow:         time.Minute,
		VaultRoot:            filepath.Join(root, "vault"),
		ArtifactRoot:         filepath.Join(root, "artifacts"),
		RunnerImage:          "ghcr.io/ms-one-note-exporter/runner:test",
		RunnerNetwork:        "msout-runner",
		RunnerControlNetwork: "msout-runner-api",
		RunnerPort:           3100,
		RunnerTokenFile:      filepath.Join(root, "runner_token"),
		PoolSize:             poolSize,
		RunnerTTL:            5 * time.Minute,
		SlotIdleTimeout:      30 * time.Minute,
		RequestTimeout:       time.Second,
	}
}

// mountFor returns the mount at a destination, or nil.
//
// A lookup rather than an index, because a runner's mount list is no longer a
// fixed shape: it carries the session vault, the artifact tree and the bearer
// token, and which of those are present depends on whether the slot is bound.
// Tests that assert "the mount at index 0" were asserting the length of an
// unrelated list.
func mountFor(req dockerapi.CreateRequest, destination string) *dockerapi.CreateMount {
	for i := range req.Mounts {
		if req.Mounts[i].Destination == destination {
			return &req.Mounts[i]
		}
	}
	return nil
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// noDockerPool returns a pool with no Docker client. Every test here inspects
// requests that are built before any Docker call, or that fail at the client —
// which is itself the assertion, since a nil client panicking would mean the
// code path reached Docker when it should not have.
func noDockerPool(t *testing.T, cfg *config.Config) *Pool {
	t.Helper()
	return New(cfg, nil, discardLog())
}

// The runner flag set is the security contract of the runner container
// (PLANNING/PLAN-v2.md §5.1). Each field below is asserted because dropping one
// silently changes the containment, not because a compiler would notice.
func TestRunnerRequestCarriesTheHardenedFlagSet(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hc := req.HostConfig

	if hc.NetworkMode != "msout-runner" {
		t.Errorf("network = %q, want msout-runner", hc.NetworkMode)
	}
	if hc.ReadonlyRootfs == nil || !*hc.ReadonlyRootfs {
		t.Error("rootfs must be read-only")
	}
	if hc.Init == nil || !*hc.Init {
		t.Error("--init must be set; Node as PID 1 does not reap zombie Chromium processes")
	}
	if hc.ShmSize != 1<<30 {
		t.Errorf("shm size = %d, want 1GiB; Docker's 64MB default crashes Chromium", hc.ShmSize)
	}
	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Errorf("cap drop = %v, want [ALL]", hc.CapDrop)
	}
	if len(hc.SecurityOpt) != 1 || hc.SecurityOpt[0] != "no-new-privileges" {
		t.Errorf("security opt = %v, want [no-new-privileges]", hc.SecurityOpt)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 512 {
		t.Errorf("pids limit = %v, want 512", hc.PidsLimit)
	}
	if hc.Memory != 2560<<20 {
		t.Errorf("memory = %d, want 2560MiB", hc.Memory)
	}
	// Pinned equal, so a runaway is OOM-killed visibly rather than swapping
	// silently.
	if hc.MemorySwap != hc.Memory {
		t.Errorf("memory swap = %d, want equal to memory %d", hc.MemorySwap, hc.Memory)
	}
	if hc.RestartPolicy.Name != "no" {
		t.Errorf("restart policy = %q, want no; a self-restarting runner re-acquires its vault mount", hc.RestartPolicy.Name)
	}
	if req.User != "node" {
		t.Errorf("user = %q, want node", req.User)
	}

	// The tmpfs set is the entire writable surface under a read-only rootfs.
	wantTmpfs := map[string]string{
		"/tmp":              "rw,noexec,nosuid,size=512m,uid=1000,gid=1000",
		"/home/node/.cache": "rw,noexec,nosuid,size=512m,uid=1000,gid=1000",
	}
	if len(hc.Tmpfs) != len(wantTmpfs) {
		t.Fatalf("tmpfs set = %v, want exactly %v", hc.Tmpfs, wantTmpfs)
	}
	for path, opts := range wantTmpfs {
		if hc.Tmpfs[path] != opts {
			t.Errorf("tmpfs %s = %q, want %q", path, hc.Tmpfs[path], opts)
		}
	}

	// Container logs are capped: unbounded runner logs are a disk exhaustion
	// path on a host whose free space also gates new exports.
	if hc.LogConfig.Config["max-size"] == "" {
		t.Error("runner log size must be capped")
	}
}

// The runner is pinned to exactly two networks, and what they are matters more
// than the count.
//
// It is no longer one. The credential has to reach a runner, and there was no
// path for it: the runner was on the egress network, where `api` cannot be, and
// nowhere else. So the runner joins one more — an internal one whose only other
// member is `api`.
//
// The property this test actually guards is the negative one, and it is worth
// stating precisely because both halves have plausible ways to regress:
//
//   - NOT on msout-control. That would put the credential path one hop from the
//     only process holding the Docker socket.
//   - NOT on the egress network alone. That would mean `api` had joined the
//     egress network, which is §2.1's prohibition, and nothing else would say
//     so — the deployment would work.
func TestRunnerIsOnTheControlAndEgressNetworksAndNothingElse(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Networking == nil {
		t.Fatal("networking config must be pinned, not left to the daemon default")
	}

	want := map[string]bool{"msout-runner": false, "msout-runner-api": false}
	if len(req.Networking.EndpointsConfig) != len(want) {
		t.Fatalf("runner is on %d networks, want %d: %v",
			len(req.Networking.EndpointsConfig), len(want), req.Networking.EndpointsConfig)
	}
	for name := range req.Networking.EndpointsConfig {
		if _, ok := want[name]; !ok {
			t.Errorf("runner is on unexpected network %q; it must not reach the "+
				"control network that the orchestrator and api share", name)
			continue
		}
		want[name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("runner is not on %q", name)
		}
	}
	// No static address: a predictable address would be a usable mount target
	// or rate-limit key.
	for name, ep := range req.Networking.EndpointsConfig {
		if ep != nil && ep.IPAMConfig != nil && ep.IPAMConfig.IPv4Address != "" {
			t.Errorf("network %s has a static address", name)
		}
	}
}

// The control network's alias is what `api` dials, so it is derived from the
// slot and nothing else — and the reason is that it must survive a recycle.
//
// A container IP would look fine here and then fail silently in production: the
// api stores an address once at claim time, `recycle` replaces the container,
// and every later call to that runner fails with a transport error while the
// orchestrator reports a healthy pool. Nothing anywhere says "stale address".
func TestRunnerAliasIsDerivedFromTheSlotAndSurvivesRecycle(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	first, err := p.buildCreateRequest("slot-7", "c-old", "", time.Time{})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	// A recycled container: same slot, new container id.
	second, err := p.buildCreateRequest("slot-7", "c-new", "", time.Time{})
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	control, ok := first.Networking.EndpointsConfig[cfg.RunnerControlNetwork]
	if !ok || control == nil || len(control.Aliases) != 1 {
		t.Fatalf("control network endpoint = %#v, want exactly one alias", control)
	}
	// The alias is the same name the orchestrator tells the api to dial.
	if got, want := control.Aliases[0], "msout-runner-slot-7"; got != want {
		t.Errorf("alias = %q, want %q", got, want)
	}
	if first.Networking.EndpointsConfig[cfg.RunnerControlNetwork].Aliases[0] !=
		second.Networking.EndpointsConfig[cfg.RunnerControlNetwork].Aliases[0] {
		t.Error("alias changed with the container id; an address stored at claim " +
			"time would go stale on every recycle")
	}

	// And the URL the api receives names that alias, on the configured port.
	url := p.RunnerURL("slot-7")
	if url != "http://msout-runner-slot-7:3100" {
		t.Errorf("RunnerURL = %q, want http://msout-runner-slot-7:3100", url)
	}
	if !strings.HasPrefix(url, "http://"+control.Aliases[0]+":") {
		t.Errorf("RunnerURL %q does not use the alias the create request registered (%q)",
			url, control.Aliases[0])
	}

	// A slot id is not interpolated into the URL unchecked: it is this
	// component's own, but an empty one must not produce a bare "http://:3100"
	// that would resolve somewhere surprising.
	if got := p.RunnerURL("  "); got != "" {
		t.Errorf("RunnerURL(blank) = %q, want empty", got)
	}
}

// An idle runner is reachable by the same alias a bound one is, because a slot's
// address cannot depend on whether a session is using it: `api` stores the URL
// it was given at claim time and reuses it for the whole session.
func TestIdleAndBoundRunnersShareTheSameAlias(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	idle, err := p.buildCreateRequest("slot-9", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("idle: %v", err)
	}
	bound, err := p.buildCreateRequest("slot-9", "c-2", testGUID, time.Now())
	if err != nil {
		t.Fatalf("bound: %v", err)
	}

	a := idle.Networking.EndpointsConfig[cfg.RunnerControlNetwork].Aliases
	b := bound.Networking.EndpointsConfig[cfg.RunnerControlNetwork].Aliases
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Errorf("alias differs by bind state: idle %v, bound %v", a, b)
	}
}

// An idle runner must not hold a credential-bearing mount. This is the
// difference between "a container waiting for a session" and "a container one
// claim away from auth.json".
//
// The mount *count* is no longer one. The artifact tree and the bearer token are
// mounted unconditionally, because the root filesystem is read-only and the
// runner refuses to start without the token. What the test now pins is the
// property rather than the total: no mount may come from the vault, and the
// /data mount must be writable or the sidecar cannot start.
func TestIdleRunnerHoldsNoVaultMount(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, m := range req.Mounts {
		if strings.HasPrefix(m.Source, cfg.VaultRoot) {
			t.Errorf("idle runner has a vault mount: %+v", m)
		}
	}
	data := mountFor(req, "/data")
	if data == nil {
		t.Fatalf("idle mounts = %+v, want a /data mount", req.Mounts)
	}
	if data.Type != "tmpfs" {
		t.Errorf("idle /data is a %s mount; a tmpfs is what makes an idle slot "+
			"carry no credential", data.Type)
	}
	if data.ReadOnly {
		t.Error("the idle /data must be writable or the sidecar cannot start")
	}

	// The two mounts every runner carries, asserted rather than left implicit.
	// Both are new since this test was written, and both were found by the
	// runner refusing to start: the token is required, and the artifact tree is
	// unwritable without it under a read-only rootfs.
	if mountFor(req, "/artifacts") == nil {
		t.Error("no /artifacts mount; the runner cannot write an archive without it")
	}
	token := mountFor(req, "/run/secrets/runner_token")
	if token == nil {
		t.Fatal("no runner_token mount; the runner refuses to start without it")
	}
	if !token.ReadOnly {
		t.Error("the token mount must be read-only")
	}
}

// A bound runner holds exactly the session's vault, read-write, and nothing else
// from the vault tree. The artifact and token mounts are shared with the idle
// case and are asserted there.
func TestBoundRunnerHoldsOnlyTheSessionVault(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	req, err := p.buildCreateRequest("slot-1", "c-1", guid, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Exactly one mount may come from the vault, and it must be this session's.
	// Counting by source rather than by total is what makes the new mounts a
	// non-event for the property this test exists to protect.
	fromVault := 0
	for _, mt := range req.Mounts {
		if strings.HasPrefix(mt.Source, cfg.VaultRoot) {
			fromVault++
			if !strings.Contains(mt.Source, guid) {
				t.Errorf("bound runner mounts another session's vault: %+v", mt)
			}
		}
	}
	if fromVault != 1 {
		t.Errorf("bound runner has %d vault mounts, want exactly 1: %+v", fromVault, req.Mounts)
	}

	m := mountFor(req, "/data")
	if m == nil {
		t.Fatalf("bound mounts = %+v, want a /data mount", req.Mounts)
	}
	if m.ReadOnly {
		t.Error("the session vault must be rw: it holds auth.json, which login writes")
	}
	want := filepath.Join(cfg.VaultRoot, guid)
	if m.Source != want {
		t.Errorf("mount source = %q, want %q", m.Source, want)
	}

	// The bind label must be present, because after a restart the label is all
	// the reconciler has.
	if req.Labels["msout.session.guid"] != guid {
		t.Errorf("session label = %q, want %q", req.Labels["msout.session.guid"], guid)
	}
	if req.Labels["msout.expires"] == "" {
		t.Error("expires label missing")
	}
}

// An idle runner must not carry bind labels. A label that says "bound" on an
// idle container is what would make reconciliation delete or adopt wrongly.
func TestIdleRunnerCarriesNoBindLabels(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, key := range []string{"msout.session.guid", "msout.expires"} {
		if v, ok := req.Labels[key]; ok {
			t.Errorf("idle runner carries %s=%q", key, v)
		}
	}
	if req.Labels["msout.role"] != "runner" {
		t.Errorf("role label = %q, want runner", req.Labels["msout.role"])
	}
}

// The session guid is joined to a host path. A traversal attempt must be
// rejected before the path is built, not sanitised afterwards.
func TestBindSessionRejectsTraversalInGuid(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	for _, guid := range []string{
		"../../etc",
		"../../../tmp/escape",
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301/../../../etc",
		"..",
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301\x00/../etc",
	} {
		if _, err := p.bindSession(guid); err == nil {
			t.Errorf("guid %q was accepted", guid)
		}
	}

	// Nothing may have been created outside the vault root.
	entries, err := os.ReadDir(filepath.Dir(cfg.VaultRoot))
	if err != nil {
		t.Fatalf("read vault root parent: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "vault" {
			t.Errorf("unexpected entry created next to the vault root: %s", e.Name())
		}
	}
}

// The vault directory holds auth.json, a live Microsoft cookie jar, so its mode
// is part of the security boundary and must survive a permissive umask.
func TestVaultDirectoryIs0700(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	oldMask := setPermissiveUmask(t)
	defer oldMask()

	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	if _, err := p.bindSession(guid); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(filepath.Join(cfg.VaultRoot, guid))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("vault mode = %04o, want 0700", perm)
	}
}

// setPermissiveUmask sets umask 0 for the duration of the test, proving the
// mode is applied explicitly rather than inherited from the umask.
func setPermissiveUmask(t *testing.T) func() {
	t.Helper()
	old := setUmask(0)
	return func() { setUmask(old) }
}

// A failed claim must return the slot to the pool rather than stranding it
// bound to a session that never got a container. A stranded slot reduces pool
// capacity for the life of the process, and nothing would ever release it.
func TestFailedClaimReturnsTheSlotToThePool(t *testing.T) {
	cfg := testConfig(t, 1)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}
	// Fail the container creation the claim depends on.
	d.failNext("remove", fmt.Errorf("daemon refused"))

	_, err := p.Claim(t.Context(), "3f2504e0-4f89-11d3-9a0c-0305e82c3301", time.Now().Add(time.Hour), "")
	if err == nil {
		t.Fatal("expected an error when the daemon fails mid-claim")
	}

	for _, s := range p.Slots() {
		if s.State == StateBound {
			t.Errorf("slot %s left bound after a failed claim: %+v", s.ID, s)
		}
		if s.SessionGUID != "" {
			t.Errorf("slot %s kept session %q after a failed claim", s.ID, s.SessionGUID)
		}
	}
}

// A successful claim replaces the idle container rather than reusing it. The
// idle container holds only a tmpfs at /data, and a bound one must hold the
// session's vault — Docker mounts are fixed at create time, so the two cannot be
// the same container.
func TestClaimReplacesTheIdleContainerWithABoundOne(t *testing.T) {
	cfg := testConfig(t, 1)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}
	if d.count() != 1 {
		t.Fatalf("idle pool has %d containers, want 1", d.count())
	}

	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	slot, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	// The old idle container is gone; exactly one container remains.
	if d.count() != 1 {
		t.Errorf("after claim there are %d containers, want 1 (the old one destroyed)", d.count())
	}

	// The new container carries the session's vault and the bind labels.
	lbls := d.labels(slot.ContainerID)
	if lbls["msout.session.guid"] != guid {
		t.Errorf("claimed container session label = %q, want %q", lbls["msout.session.guid"], guid)
	}
	if lbls["msout.expires"] == "" {
		t.Error("claimed container has no expiry label")
	}

	req, ok := d.lastCreate()
	if !ok {
		t.Fatal("no container in the fake daemon")
	}
	foundVault := false
	for _, m := range req.Mounts {
		if m.Source == filepath.Join(cfg.VaultRoot, guid) {
			foundVault = true
		}
	}
	if !foundVault {
		t.Errorf("claimed container mounts = %+v, want the session vault", req.Mounts)
	}

	// And the slot is bound with the identity `api` will read.
	if slot.State != StateBound {
		t.Errorf("slot state = %q, want bound", slot.State)
	}
	if slot.SessionGUID != guid {
		t.Errorf("slot session = %q, want %q", slot.SessionGUID, guid)
	}
}

// A claim must never leave two sessions sharing one container. The re-check
// under the lock is the control, so this drives concurrent claims at a
// single-slot pool.
func TestConcurrentClaimsCannotShareAContainer(t *testing.T) {
	cfg := testConfig(t, 1)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}

	const attempts = 8
	results := make(chan string, attempts)
	errs := make(chan error, attempts)

	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			guid := fmt.Sprintf("3f2504e0-4f89-11d3-9a0c-%012d", i)
			slot, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour), "")
			if err != nil {
				errs <- err
				return
			}
			results <- slot.ContainerID
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		if !errors.Is(err, ErrNoSlot) {
			t.Errorf("unexpected error from a concurrent claim: %v", err)
		}
	}

	// At most one claim can succeed against a one-slot pool.
	granted := 0
	seen := map[string]bool{}
	for id := range results {
		granted++
		if seen[id] {
			t.Errorf("two sessions were handed the same container %s", id)
		}
		seen[id] = true
	}
	if granted > 1 {
		t.Errorf("%d claims succeeded against a 1-slot pool, want at most 1", granted)
	}

	// And exactly one session is bound.
	bound := 0
	for _, s := range p.Slots() {
		if s.State == StateBound {
			bound++
		}
	}
	if bound != granted {
		t.Errorf("%d slots bound but %d claims granted", bound, granted)
	}
}

// Recycle keeps the slot and the session, replacing only the container. The
// vault is remounted so auth.json survives, which is the entire reason recycle
// exists separately from release (PLAN-v2 §2.3).
func TestRecycleKeepsTheSessionAndTheSlot(t *testing.T) {
	cfg := testConfig(t, 1)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}

	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	expires := time.Now().Add(time.Hour)
	claimed, err := p.Claim(t.Context(), guid, expires, "")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	if err := p.Recycle(t.Context(), claimed.ID, "runner ttl"); err != nil {
		t.Fatalf("recycle: %v", err)
	}

	slots := p.Slots()
	if len(slots) != 1 {
		t.Fatalf("recycle changed the pool to %d slots, want 1", len(slots))
	}
	s := slots[0]
	if s.State != StateBound {
		t.Errorf("recycled slot state = %q, want bound", s.State)
	}
	if s.SessionGUID != guid {
		t.Errorf("recycled slot session = %q, want %q preserved", s.SessionGUID, guid)
	}
	if s.ContainerID == claimed.ContainerID {
		t.Error("recycle did not replace the container")
	}
	if d.count() != 1 {
		t.Errorf("after recycle there are %d containers, want 1", d.count())
	}
	// The replacement carries the session mount, so the login survives.
	lbls := d.labels(s.ContainerID)
	if lbls["msout.session.guid"] != guid {
		t.Errorf("recycled container lost its session label: %v", lbls)
	}
}

// Release destroys the container and frees the slot, but the slot id stays
// reserved so a claim before the refill does not create a second runner for the
// same position.
func TestReleaseFreesTheSlotWithoutDeletingIt(t *testing.T) {
	cfg := testConfig(t, 1)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	claimed, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	if err := p.Release(t.Context(), claimed.ID); err != nil {
		t.Fatalf("release: %v", err)
	}

	slots := p.Slots()
	if len(slots) != 1 {
		t.Fatalf("release removed the slot; pool is now %d slots", len(slots))
	}
	if slots[0].ContainerID != "" {
		t.Errorf("released slot still holds container %s", slots[0].ContainerID)
	}
	if slots[0].SessionGUID != "" {
		t.Errorf("released slot still holds session %q", slots[0].SessionGUID)
	}
	if d.count() != 0 {
		t.Errorf("release left %d containers behind", d.count())
	}
}

// EnsurePool refills a slot that release emptied, so pool capacity returns
// without an operator restarting anything.
//
// **This test asserted the opposite of its name.** It checked `d.count() == 1` — one
// live container in a pool of two, after the refill tick. That is the *absence* of a
// refill, and it passed because `EnsurePool` counted slots rather than containers: the
// released slot was still in the map, so `need` came out 0. The claim at the end then
// succeeded on the *other* slot, which is why it looked healthy.
//
// So every release shrank the pool by one, permanently, and after `PoolSize` logins
// the pool was empty while `/stats` reported `size: 2`. Found on a real host, four
// minutes of `byState: {starting: 1}` with no top-up activity. See `StateVacant`.
func TestEnsurePoolRefillsAfterRelease(t *testing.T) {
	cfg := testConfig(t, 2)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	claimed, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := p.Release(t.Context(), claimed.ID); err != nil {
		t.Fatalf("release: %v", err)
	}

	// Release destroyed the container, so the pool is genuinely one short — and
	// reports itself that way, which is what distinguishes this from a full pool.
	if got := d.count(); got != 1 {
		t.Fatalf("after release there are %d containers, want 1; the pool should be "+
			"one short until the refill", got)
	}

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("refill: %v", err)
	}
	if d.count() != 2 {
		t.Errorf("after refill there are %d containers, want 2 — the slot release "+
			"emptied was never refilled, so capacity does not return", d.count())
	}
	if idle := p.Stats().ByState[string(StateIdle)]; idle != 2 {
		t.Errorf("idle = %d after refill, want 2: %+v", idle, p.Stats().ByState)
	}
	// And the refilled runner is claimable again.
	if _, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour), ""); err != nil {
		t.Errorf("claim after refill failed: %v", err)
	}
}

// A claim against an exhausted pool is ErrNoSlot, which the HTTP layer turns
// into 503 with a wait estimate.
func TestClaimOnExhaustedPoolIsErrNoSlot(t *testing.T) {
	cfg := testConfig(t, 2)
	p := New(cfg, nil, discardLog())

	p.slots["slot-1"] = &Slot{ID: "slot-1", State: StateBound, SessionGUID: "a"}
	p.slots["slot-2"] = &Slot{ID: "slot-2", State: StateBound, SessionGUID: "b"}

	_, err := p.Claim(t.Context(), "3f2504e0-4f89-11d3-9a0c-0305e82c3301", time.Now().Add(time.Hour), "")
	if err != ErrNoSlot {
		t.Fatalf("claim on exhausted pool = %v, want ErrNoSlot", err)
	}
}

// A starting or draining slot is not claimable. Claiming one would hand `api` a
// container id that is not yet running, or is being destroyed.
func TestClaimSkipsNonIdleSlots(t *testing.T) {
	cfg := testConfig(t, 3)
	p := New(cfg, nil, discardLog())

	p.slots["slot-1"] = &Slot{ID: "slot-1", State: StateStarting}
	p.slots["slot-2"] = &Slot{ID: "slot-2", State: StateDraining, ContainerID: "c-2"}
	p.slots["slot-3"] = &Slot{ID: "slot-3", State: StateDead}

	_, err := p.Claim(t.Context(), "3f2504e0-4f89-11d3-9a0c-0305e82c3301", time.Now().Add(time.Hour), "")
	if err != ErrNoSlot {
		t.Fatalf("claim with no idle slot = %v, want ErrNoSlot", err)
	}
}

// Release on a slot that does not exist is ErrUnknownSlot, a caller error rather
// than a transient condition, so the HTTP layer answers 409.
func TestVerbsOnUnknownSlotAreErrUnknownSlot(t *testing.T) {
	cfg := testConfig(t, 1)
	p := New(cfg, nil, discardLog())
	ctx := t.Context()

	if err := p.Release(ctx, "nope"); err != ErrUnknownSlot {
		t.Errorf("Release = %v, want ErrUnknownSlot", err)
	}
	if err := p.Recycle(ctx, "nope", "test"); err != ErrUnknownSlot {
		t.Errorf("Recycle = %v, want ErrUnknownSlot", err)
	}
	if err := p.Remove(ctx, "nope"); err != ErrUnknownSlot {
		t.Errorf("Remove = %v, want ErrUnknownSlot", err)
	}
}

// Recycle on a draining or dead slot is ErrNotBound: the verb would be racing
// another operation on the same container.
func TestRecycleOnDrainingSlotIsErrNotBound(t *testing.T) {
	cfg := testConfig(t, 1)
	p := New(cfg, nil, discardLog())
	p.slots["slot-1"] = &Slot{ID: "slot-1", State: StateDraining, ContainerID: "c-1"}

	if err := p.Recycle(t.Context(), "slot-1", "test"); err != ErrNotBound {
		t.Fatalf("Recycle on draining = %v, want ErrNotBound", err)
	}
}

// Stats reports the shape `api` and /healthz read.
func TestStatsShape(t *testing.T) {
	cfg := testConfig(t, 3)
	p := New(cfg, nil, discardLog())
	p.slots["slot-1"] = &Slot{ID: "slot-1", State: StateIdle}
	p.slots["slot-2"] = &Slot{ID: "slot-2", State: StateBound}
	p.slots["slot-3"] = &Slot{ID: "slot-3", State: StateBound}

	s := p.Stats()
	if s.Size != 3 {
		t.Errorf("size = %d, want 3", s.Size)
	}
	if s.ByState["idle"] != 1 || s.ByState["bound"] != 2 {
		t.Errorf("byState = %v, want idle=1 bound=2", s.ByState)
	}
	if s.RunnerTTLSeconds != 300 {
		t.Errorf("runnerTtlSeconds = %d, want 300", s.RunnerTTLSeconds)
	}
}

// Sweep removes an idle slot past the idle TTL. That is what releases a
// container's memory without touching a session row — the whole point of the
// idle-TTL rule in PLAN-v2 §2.1.
func TestSweepRemovesIdleSlotsPastTTL(t *testing.T) {
	cfg := testConfig(t, 2)
	cfg.SlotIdleTimeout = time.Minute

	d := newFakeDaemon()
	p := New(cfg, d, discardLog())
	now := time.Now()
	old := now.Add(-2 * time.Minute)
	p.now = func() time.Time { return now }

	stale := d.add("stale", true, map[string]string{"msout.slot.id": "slot-1"})
	fresh := d.add("fresh", true, map[string]string{"msout.slot.id": "slot-2"})
	p.slots["slot-1"] = &Slot{ID: "slot-1", State: StateIdle, ContainerID: stale.id, CreatedAt: old}
	p.slots["slot-2"] = &Slot{ID: "slot-2", State: StateIdle, ContainerID: fresh.id, CreatedAt: now}

	if err := p.Sweep(t.Context()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if _, ok := p.slots["slot-1"]; ok {
		t.Error("idle slot past TTL survived the sweep")
	}
	if _, ok := p.slots["slot-2"]; !ok {
		t.Error("idle slot inside TTL was swept")
	}
	// The container must be gone, not just the slot record: the point of the
	// idle TTL is releasing ~1.5 GB, not un-bookkeeping it.
	if _, err := d.InspectContainer(t.Context(), stale.id); err == nil {
		t.Error("swept idle slot's container still exists")
	}
	if _, err := d.InspectContainer(t.Context(), fresh.id); err != nil {
		t.Errorf("in-TTL idle container was removed: %v", err)
	}
}

// Sweep must not touch a bound slot past the idle TTL. A session's container is
// recycled on the runner budget, not removed for being idle, because the vault
// it holds is the session's.
func TestSweepLeavesBoundSlotsAloneOnIdleTTL(t *testing.T) {
	cfg := testConfig(t, 1)
	cfg.SlotIdleTimeout = time.Minute
	cfg.RunnerTTL = time.Hour // longer than the age below, so only the idle rule applies

	d := newFakeDaemon()
	p := New(cfg, d, discardLog())
	now := time.Now()
	p.now = func() time.Time { return now }
	ctr := d.add("bound", true, map[string]string{"msout.slot.id": "slot-1"})
	p.slots["slot-1"] = &Slot{
		ID: "slot-1", State: StateBound, ContainerID: ctr.id,
		CreatedAt: now.Add(-2 * time.Minute), SessionGUID: "abc",
	}

	if err := p.Sweep(t.Context()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if _, ok := p.slots["slot-1"]; !ok {
		t.Fatal("bound slot was swept on the idle TTL")
	}
	// The container must survive too: the vault it holds is the session's.
	if _, err := d.InspectContainer(t.Context(), ctr.id); err != nil {
		t.Errorf("bound container was removed on the idle TTL: %v", err)
	}
}

// A bound slot past the runner TTL is recycled, keeping its session. This is the
// 5-minute budget that bounds how long one browser process tree serves one
// session.
// A bound runner is recycled when its **session** expires, never because its
// container reached an age.
//
// The old rule was `now - slot.CreatedAt > RunnerTTL`, and it destroyed work in
// progress: bound runners were being replaced every ~90 seconds on the deployed host,
// killing an export that had already written real notes. A slot binds to whatever
// container happens to be idle, so `CreatedAt` is whatever age that container already
// was - which says nothing about the session using it.
//
// This test is the old one inverted: the container is very old and the session is
// very much alive, and the runner must be left alone.
func TestSweepLeavesABoundRunnerAloneWhileItsSessionIsAlive(t *testing.T) {
	cfg := testConfig(t, 1)
	cfg.RunnerTTL = time.Minute
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

	d := newFakeDaemon()
	p := New(cfg, d, discardLog())
	now := time.Now()
	p.now = func() time.Time { return now }

	old := d.add("old", true, map[string]string{
		"msout.role":         "runner",
		"msout.slot.id":      "slot-1",
		"msout.session.guid": guid,
	})
	p.slots["slot-1"] = &Slot{
		ID: "slot-1", State: StateBound, ContainerID: old.id,
		// Far past the TTL, and far older than any browser tree should live.
		CreatedAt: now.Add(-2 * time.Hour), SessionGUID: guid,
		SessionExpiresAt: now.Add(time.Hour),
	}

	if err := p.Sweep(t.Context()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if got := p.Slots()[0].ContainerID; got != old.id {
		t.Errorf("container = %q, want %q unchanged: a bound runner whose session is "+
			"alive must not be recycled on the container's age", got, old.id)
	}
}

// The session's expiry is still a bound: that is what ends a bound runner's life.
func TestSweepRecyclesBoundSlotsWhenTheSessionExpires(t *testing.T) {
	cfg := testConfig(t, 1)
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

	d := newFakeDaemon()
	p := New(cfg, d, discardLog())
	now := time.Now()
	p.now = func() time.Time { return now }

	old := d.add("old", true, map[string]string{
		"msout.role":         "runner",
		"msout.slot.id":      "slot-1",
		"msout.session.guid": guid,
	})
	p.slots["slot-1"] = &Slot{
		ID: "slot-1", State: StateBound, ContainerID: old.id,
		CreatedAt: now.Add(-time.Minute), SessionGUID: guid,
		// Expired a minute ago, on a container created a minute ago.
		SessionExpiresAt: now.Add(-time.Minute),
	}

	if err := p.Sweep(t.Context()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// The slot survives, still bound to the same session, with a new container:
	// recycle replaces the browser tree, it does not erase the login.
	if _, ok := p.slots["slot-1"]; !ok {
		t.Fatal("recycled slot was removed; recycle must keep the slot")
	}
	s := p.Slots()[0]
	if s.State != StateBound {
		t.Errorf("state after recycle = %q, want bound", s.State)
	}
	if s.SessionGUID != guid {
		t.Errorf("session after recycle = %q, want %q", s.SessionGUID, guid)
	}
	if s.ContainerID == old.id {
		t.Error("recycle did not replace the container")
	}
}

// A bound slot with no recorded expiry is left to `api`, which owns session
// lifetime. Recycling it on container age is what destroyed exports; the error to
// make here is in the unsafe direction.
func TestSweepLeavesABoundSlotWithNoExpiryAlone(t *testing.T) {
	cfg := testConfig(t, 1)
	cfg.RunnerTTL = time.Minute

	d := newFakeDaemon()
	p := New(cfg, d, discardLog())
	now := time.Now()
	p.now = func() time.Time { return now }

	old := d.add("old", true, map[string]string{
		"msout.role":    "runner",
		"msout.slot.id": "slot-1",
	})
	p.slots["slot-1"] = &Slot{
		ID: "slot-1", State: StateBound, ContainerID: old.id,
		CreatedAt: now.Add(-time.Hour),
		// No SessionExpiresAt.
	}

	if err := p.Sweep(t.Context()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if got := p.Slots()[0].ContainerID; got != old.id {
		t.Errorf("container = %q, want it unchanged", got)
	}
}

func TestEnsurePoolIsIdempotent(t *testing.T) {
	cfg := testConfig(t, 2)
	p := New(cfg, nil, discardLog())

	// Seed the pool with two starting slots, as if a previous tick had created
	// them and the image pull were still running.
	p.slots["slot-1"] = &Slot{ID: "slot-1", State: StateStarting}
	p.slots["slot-2"] = &Slot{ID: "slot-2", State: StateStarting}

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool on a full pool: %v", err)
	}
	if len(p.slots) != 2 {
		t.Fatalf("pool grew to %d slots; EnsurePool duplicated starting slots", len(p.slots))
	}
}

// ArtifactStat answers the download authoriser's only question. A missing
// artifact is exists:false, not an error — "not there yet" is a normal answer.
func TestArtifactStat(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	const id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	// Missing.
	st, err := p.ArtifactStat(id)
	if err != nil {
		t.Fatalf("stat missing: %v", err)
	}
	if st.Exists {
		t.Error("missing artifact reported as existing")
	}

	// Present, with a known size.
	dir := filepath.Join(cfg.ArtifactRoot, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vault.zip"), make([]byte, 2048), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	st, err = p.ArtifactStat(id)
	if err != nil {
		t.Fatalf("stat present: %v", err)
	}
	if !st.Exists {
		t.Error("present artifact reported as missing")
	}
	if st.Size != 2048 {
		t.Errorf("size = %d, want 2048", st.Size)
	}
}

// A file where a directory belongs is not an artifact. Reporting exists:true
// would let Caddy try to serve a path that is not one.
func TestArtifactStatRejectsFileAtArtifactPath(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	const id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := os.MkdirAll(cfg.ArtifactRoot, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cfg.ArtifactRoot, id), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	st, err := p.ArtifactStat(id)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Exists {
		t.Error("a regular file was reported as an artifact directory")
	}
}

// dirSize must not follow a symlink out of the artifact tree. A size read is
// harmless, but a traversal read is the shape of the bug this guards.
func TestDirSizeDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "big"), make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	dir := filepath.Join(root, "artifact")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "big"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real"), make([]byte, 10), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := dirSize(dir); got != 10 {
		t.Fatalf("dirSize = %d, want 10; a symlink was followed", got)
	}
}

// dirSize depth is bounded so a pathological tree cannot turn a download
// authorisation into a long-running request.
//
// An exported notebook is a shallow tree — a zip, a partial marker, and a logs
// directory — so the bound costs nothing real and closes the traversal.
func TestDirSizeIsDepthBounded(t *testing.T) {
	root := t.TempDir()
	current := root
	const levels = 10
	for i := 0; i < levels; i++ {
		current = filepath.Join(current, "d")
		if err := os.MkdirAll(current, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(current, "f"), make([]byte, 100), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// walk() runs at depths 0..4 inclusive, so the file at depth 1 through
	// depth 4 is counted and the rest is not: 4 files, 400 bytes.
	const want = 400
	if got := dirSize(root); got != want {
		t.Fatalf("dirSize = %d, want %d (depth bound should exclude levels %d..%d)",
			got, want, 5, levels)
	}
}

// A real artifact tree is shallow and its full size must be counted, so the
// depth bound cannot be hiding a legitimate artifact.
func TestDirSizeCountsAShallowArtifactTree(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "artifact")
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	files := map[string]int{
		filepath.Join(dir, "vault.zip"):     5000,
		filepath.Join(dir, "vault.partial"): 0,
		filepath.Join(logs, "app.log"):      1500,
		filepath.Join(logs, "runner.log"):   250,
	}
	for path, size := range files {
		if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	var want int64
	for _, size := range files {
		want += int64(size)
	}
	if got := dirSize(dir); got != want {
		t.Fatalf("dirSize = %d, want %d; the depth bound hid a real artifact", got, want)
	}
}

// containerName must satisfy the Engine's
// ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ requirement without sanitising, since both parts
// are orchestrator-generated.
func TestContainerNameIsEngineCompatible(t *testing.T) {
	name := containerName("slot-1", "c-slot-1-1700000000000000000")
	if !strings.HasPrefix(name, "msout-") {
		t.Errorf("name = %q, want an msout- prefix", name)
	}
	for i, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-'
		if !ok {
			t.Fatalf("name %q has an engine-invalid character %q at %d", name, r, i)
		}
	}
	if name[0] < 'a' || name[0] > 'z' {
		t.Errorf("name must start alphanumeric, got %q", name[0])
	}
}

// T-I6: /stats must expose the orchestrator's own slot names.
//
// The api stores one of these in sessions.runner_id and passes it back as a slotId
// to release and recycle. Without them the api can only invent ids, and an invented
// id that happens to collide is one session releasing another's container.
func TestStatsExposesSlotIDs(t *testing.T) {
	p := slotIDsPool(t, 3)
	stats := p.Stats()

	if len(stats.SlotIDs) != 3 {
		t.Fatalf("SlotIDs = %d ids, want 3", len(stats.SlotIDs))
	}
	// Distinct and non-empty: an id that repeats would let two sessions bind the
	// same slot name, which is the failure this exists to prevent.
	seen := map[string]bool{}
	for _, id := range stats.SlotIDs {
		if id == "" {
			t.Fatal("a slot id is empty")
		}
		if seen[id] {
			t.Fatalf("slot id %q appears twice", id)
		}
		seen[id] = true
	}
}

// Sorted, so two calls against an unchanged pool are byte-identical. An unstable
// order makes a diff of two /stats responses meaningless and churns the api's view
// for no reason.
func TestStatsSlotIDsAreSorted(t *testing.T) {
	p := slotIDsPool(t, 5)
	first := p.Stats().SlotIDs
	for i := 0; i < 20; i++ {
		next := p.Stats().SlotIDs
		if len(next) != len(first) {
			t.Fatalf("slot count changed between calls: %d then %d", len(first), len(next))
		}
		for j := range first {
			if first[j] != next[j] {
				t.Fatalf("slot order is unstable at %d: %q then %q", j, first[j], next[j])
			}
		}
	}
}

// Slot ids must not carry container identities. §2.1 restricts the api from
// holding a container id it cannot verify; a slot name is how it asks for a slot,
// not a handle it can address a container with.
func TestStatsSlotIDsAreNotContainerIDs(t *testing.T) {
	p := slotIDsPool(t, 2)
	stats := p.Stats()
	for _, s := range p.Slots() {
		if s.ContainerID == "" {
			continue // idle slot, nothing to leak
		}
		for _, id := range stats.SlotIDs {
			if id == s.ContainerID {
				t.Fatalf("slot id %q is also a container id", id)
			}
		}
	}
}

// slotIDsPool builds a pool with n named idle slots, for the Stats tests.
func slotIDsPool(t *testing.T, n int) *Pool {
	t.Helper()
	p := New(testConfig(t, n), nil, discardLog())
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("slot-%d", i)
		p.slots[id] = &Slot{ID: id, State: StateIdle}
	}
	return p
}

// ---- Claim with a named slot -------------------------------------------------
//
// The api names the slot it already claimed in SQLite, because a lock on a row that is
// not the slot holding the container is not a lock. Found on a real host, where
// `slot-1` was recorded active while carrying `slot-2`'s address.

func TestClaimTakesTheNamedSlot(t *testing.T) {
	cfg := testConfig(t, 2)
	p := New(cfg, newFakeDaemon(), nil)
	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}
	ids := slotIDsOf(p)
	if len(ids) != 2 {
		t.Fatalf("slot count = %d, want 2", len(ids))
	}

	// The one that is *not* first, so a random pick landing on it would be luck.
	wanted := ids[1]
	slot, err := p.Claim(t.Context(), "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
		time.Now().Add(time.Hour), wanted)
	if err != nil {
		t.Fatalf("claim of %s: %v", wanted, err)
	}
	if slot.ID != wanted {
		t.Errorf("claimed %q, asked for %q", slot.ID, wanted)
	}
}

// A named slot that is not idle must **conflict**, never be silently substituted.
// Answering 200 with a different slot is the same disagreement in a worse form: the
// caller records a slot it does not own and finds out at release time.
func TestClaimOfANonIdleSlotConflicts(t *testing.T) {
	cfg := testConfig(t, 2)
	p := New(cfg, newFakeDaemon(), nil)
	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}
	ids := slotIDsOf(p)
	taken, err := p.Claim(t.Context(), "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
		time.Now().Add(time.Hour), ids[0])
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}

	// The same slot, a second time.
	again, err := p.Claim(t.Context(), "cccccccc-3333-4333-8333-cccccccccccc",
		time.Now().Add(time.Hour), taken.ID)
	if err != ErrAlreadyBound {
		t.Fatalf("second claim of a bound slot = %v, want ErrAlreadyBound", err)
	}
	if again != nil {
		t.Errorf("a conflicting claim returned slot %q; it must return nothing rather "+
			"than a slot the caller would record as its own", again.ID)
	}
}

// An unknown slot is a disagreement about the pool's own membership, which is what
// `syncPool` exists to prevent — so it is refused rather than treated as "pick another".
func TestClaimOfAnUnknownSlotIsRefused(t *testing.T) {
	cfg := testConfig(t, 1)
	p := New(cfg, newFakeDaemon(), nil)
	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}

	slot, err := p.Claim(t.Context(), "dddddddd-4444-4444-8444-dddddddddddd",
		time.Now().Add(time.Hour), "slot-99")
	if err != ErrUnknownSlot {
		t.Fatalf("claim of an unknown slot = %v, want ErrUnknownSlot", err)
	}
	if slot != nil {
		t.Errorf("a refused claim returned slot %q", slot.ID)
	}
}

// The unnamed form still works, because an api that has not shipped the field must
// keep working during a rolling deploy.
func TestClaimWithoutANamedSlotStillChoosesOne(t *testing.T) {
	cfg := testConfig(t, 2)
	p := New(cfg, newFakeDaemon(), nil)
	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}

	slot, err := p.Claim(t.Context(), "eeeeeeee-5555-4555-8555-eeeeeeeeeeee",
		time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatalf("unnamed claim: %v", err)
	}
	if !slotIDsContain(slotIDsOf(p), slot.ID) {
		t.Errorf("chose %q, which is not one of the pool's slots", slot.ID)
	}
}

func slotIDsContain(haystack []string, needle string) bool {
	for _, id := range haystack {
		if id == needle {
			return true
		}
	}
	return false
}
