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
)

// testConfig returns a config rooted in a temp dir, with the pool sized for the
// test at hand.
func testConfig(t *testing.T, poolSize int) *config.Config {
	t.Helper()
	root := t.TempDir()
	return &config.Config{
		DockerSocket:    filepath.Join(root, "docker.sock"),
		HMACSecret:      []byte(strings.Repeat("a", 64)),
		ReplayWindow:    time.Minute,
		VaultRoot:       filepath.Join(root, "vault"),
		ArtifactRoot:    filepath.Join(root, "artifacts"),
		RunnerImage:     "ghcr.io/ms-one-note-exporter/runner:test",
		RunnerNetwork:   "msout-runner",
		PoolSize:        poolSize,
		RunnerTTL:       5 * time.Minute,
		SlotIdleTimeout: 30 * time.Minute,
		RequestTimeout:  time.Second,
	}
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

// The runner is pinned to exactly one network. Being on msout-control would
// make it reachable from `api` and the orchestrator, which is the direction the
// capability table forbids (PLAN-v3 §2.1).
func TestRunnerIsOnExactlyOneNetwork(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Networking == nil {
		t.Fatal("networking config must be pinned, not left to the daemon default")
	}
	if len(req.Networking.EndpointsConfig) != 1 {
		t.Fatalf("runner is on %d networks, want 1: %v",
			len(req.Networking.EndpointsConfig), req.Networking.EndpointsConfig)
	}
	if _, ok := req.Networking.EndpointsConfig["msout-runner"]; !ok {
		t.Errorf("networks = %v, want msout-runner", req.Networking.EndpointsConfig)
	}
	// No static address: a predictable address would be a usable mount target
	// or rate-limit key.
	for name, ep := range req.Networking.EndpointsConfig {
		if ep != nil && ep.IPAMConfig != nil && ep.IPAMConfig.IPv4Address != "" {
			t.Errorf("network %s has a static address", name)
		}
	}
}

// An idle runner must not hold a credential-bearing mount. This is the
// difference between "a container waiting for a session" and "a container one
// claim away from auth.json".
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
	if len(req.Mounts) != 1 || req.Mounts[0].Destination != "/data" {
		t.Fatalf("idle mounts = %+v, want a single /data", req.Mounts)
	}
	if req.Mounts[0].ReadOnly {
		t.Error("the idle /data must be writable or the sidecar cannot start")
	}
}

// A bound runner holds exactly the session's vault, read-write, and nothing else.
func TestBoundRunnerHoldsOnlyTheSessionVault(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	req, err := p.buildCreateRequest("slot-1", "c-1", guid, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(req.Mounts) != 1 {
		t.Fatalf("bound mounts = %+v, want exactly one", req.Mounts)
	}
	m := req.Mounts[0]
	if m.Destination != "/data" {
		t.Errorf("mount destination = %q, want /data", m.Destination)
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

	_, err := p.Claim(t.Context(), "3f2504e0-4f89-11d3-9a0c-0305e82c3301", time.Now().Add(time.Hour))
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
	slot, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour))
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
			slot, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour))
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
	claimed, err := p.Claim(t.Context(), guid, expires)
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
	claimed, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour))
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
func TestEnsurePoolRefillsAfterRelease(t *testing.T) {
	cfg := testConfig(t, 2)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	claimed, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := p.Release(t.Context(), claimed.ID); err != nil {
		t.Fatalf("release: %v", err)
	}

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("refill: %v", err)
	}
	if d.count() != 1 {
		t.Errorf("after refill there are %d containers, want 1 idle runner", d.count())
	}
	// And the refilled runner is claimable again.
	if _, err := p.Claim(t.Context(), guid, time.Now().Add(time.Hour)); err != nil {
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

	_, err := p.Claim(t.Context(), "3f2504e0-4f89-11d3-9a0c-0305e82c3301", time.Now().Add(time.Hour))
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

	_, err := p.Claim(t.Context(), "3f2504e0-4f89-11d3-9a0c-0305e82c3301", time.Now().Add(time.Hour))
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
func TestSweepRecyclesBoundSlotsPastRunnerTTL(t *testing.T) {
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
		CreatedAt: now.Add(-2 * time.Minute), SessionGUID: guid,
		SessionExpiresAt: now.Add(time.Hour),
	}

	if err := p.Sweep(t.Context()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// The slot survives, still bound to the same session, with a new container.
	// This is the 5-minute budget: the browser process tree is replaced, the
	// login is not.
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
	if _, err := d.InspectContainer(t.Context(), old.id); err == nil {
		t.Error("the old container still exists after recycle")
	}
	if lbls := d.labels(s.ContainerID); lbls["msout.session.guid"] != guid {
		t.Errorf("replacement container lost its session bind: %v", lbls)
	}
}

// EnsurePool is idempotent. A slot that is starting must not be duplicated on
// the next tick, which matters because the pool ticks every ten seconds and an
// image pull can take longer than that.
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
