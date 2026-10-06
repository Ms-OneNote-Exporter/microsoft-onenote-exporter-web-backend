package pool

import (
	"strconv"
	"testing"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/labels"
)

// runnerLabels builds the label set the orchestrator itself would write, so a
// reconcile fixture matches what a real container carries.
func runnerLabels(slotID string, bound bool, createdAt, expires time.Time) map[string]string {
	lbl := labels.Base(slotID, "c-"+slotID, "runner:test")
	lbl[labels.CreatedAt] = strconv.FormatInt(createdAt.UnixMilli(), 10)
	if bound {
		lbl[labels.SessionGUID] = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
		lbl[labels.Expires] = strconv.FormatInt(expires.UnixMilli(), 10)
	}
	return lbl
}

// reconcileFixture is a pool plus a daemon holding a described pre-existing
// state.
type reconcileFixture struct {
	p     *Pool
	d     *fakeDaemon
	cfg   *config.Config
	now   time.Time
	slots []Slot
}

// newReconcileFixture returns a pool with one known slot, ready for
// Reconcile to describe the daemon's containers against.
func newReconcileFixture(t *testing.T, poolSize int, seedSlots ...*Slot) *reconcileFixture {
	t.Helper()
	cfg := testConfig(t, poolSize)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())
	now, _ := nowFixture()
	p.now = func() time.Time { return now }
	for _, s := range seedSlots {
		p.slots[s.ID] = s
	}
	return &reconcileFixture{p: p, d: d, cfg: cfg, now: now}
}

// nothingExpired is the SessionLookup used where expiry is not under test.
func nothingExpired(string) bool { return false }

// Boot reconciliation adopts a live idle runner so a restart does not discard a
// pool that the daemon still has.
func TestReconcileAdoptsALiveIdleRunner(t *testing.T) {
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now.Add(-time.Minute)
	ctr := f.d.add("idle", true, runnerLabels("slot-1", false, created, time.Time{}))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	slots := f.p.Slots()
	if len(slots) != 1 {
		t.Fatalf("slots = %d, want 1", len(slots))
	}
	if slots[0].ContainerID != ctr.id {
		t.Errorf("adopted container = %q, want %q", slots[0].ContainerID, ctr.id)
	}
	if slots[0].State != StateIdle {
		t.Errorf("state = %q, want idle", slots[0].State)
	}
	// The creation time comes from the label, because that is what the recycle
	// budget is measured from.
	if slots[0].CreatedAt.UnixMilli() != created.UnixMilli() {
		t.Errorf("adopted CreatedAt = %v, want %v", slots[0].CreatedAt, created)
	}
}

// A bound runner whose session is still alive is adopted with its session, so a
// restart does not log the user out. This is why the vault survives a deploy.
func TestReconcileAdoptsABoundRunnerWithItsSession(t *testing.T) {
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now.Add(-time.Minute)
	expires := f.now.Add(time.Hour)
	ctr := f.d.add("bound", true, runnerLabels("slot-1", true, created, expires))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	slots := f.p.Slots()
	if slots[0].State != StateBound {
		t.Errorf("state = %q, want bound", slots[0].State)
	}
	if slots[0].SessionGUID != guid {
		t.Errorf("adopted session = %q, want %q", slots[0].SessionGUID, guid)
	}
	if slots[0].ContainerID != ctr.id {
		t.Errorf("adopted container = %q, want %q", slots[0].ContainerID, ctr.id)
	}
	if slots[0].SessionExpiresAt.UnixMilli() != expires.UnixMilli() {
		t.Errorf("adopted expiry = %v, want %v", slots[0].SessionExpiresAt, expires)
	}
}

// The critical rule from PLAN-v2 §2.5: never resurrect an expired session. A
// container bound to a session the caller reports as expired is an orphan, and
// its vault belongs to the erase path rather than to a rebind.
func TestReconcileRemovesARunnerBoundToAnExpiredSession(t *testing.T) {
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now.Add(-time.Minute)
	ctr := f.d.add("expired", true, runnerLabels("slot-1", true, created, f.now.Add(-time.Minute)))

	expired := func(g string) bool { return g == guid }
	if err := f.p.Reconcile(t.Context(), expired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The container must be gone, whatever its own labels claimed.
	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err == nil {
		t.Error("container bound to an expired session survived reconciliation")
	}
	// And the slot must not be reported as serving that session.
	for _, s := range f.p.Slots() {
		if s.SessionGUID == guid {
			t.Errorf("slot %s still claims expired session %s", s.ID, guid)
		}
		if s.State == StateBound {
			t.Errorf("slot %s left bound to an expired session", s.ID)
		}
	}
}

// The reconciler does not trust the session predicate alone: a container whose
// session is alive is adopted, but its *age* is still enforced. A container past
// the runner TTL must be recycled, not adopted, or a long-lived host would
// accumulate unbounded browser process trees per slot.
func TestReconcileRecyclesARunnerPastTheRunnerTTL(t *testing.T) {
	// Relative to the fixture clock, not wall time: the pool's now is pinned and
	// a container stamped "2 hours ago" by time.Now would land in the future.
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now.Add(-2 * time.Hour) // far past the 5-minute budget
	ctr := f.d.add("ancient", true, runnerLabels("slot-1", false, created, time.Time{}))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The identity is adopted...
	slots := f.p.Slots()
	if slots[0].ContainerID == ctr.id {
		t.Error("the over-age container was adopted as-is")
	}
	// ...and the old one is removed.
	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err == nil {
		t.Error("the over-age container still exists after reconciliation")
	}
	// And the fresh replacement is idle and healthy.
	if slots[0].State != StateIdle {
		t.Errorf("replacement state = %q, want idle", slots[0].State)
	}
	if slots[0].ContainerID == "" {
		t.Error("replacement container id is empty")
	}
}

// A runner with no slot label cannot be attributed to a slot. Adopting it would
// guess, and guessing here means possibly mapping one session's container onto
// another's slot.
func TestReconcileRemovesARunnerWithoutASlotLabel(t *testing.T) {
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now
	// Note: no msout.slot.id.
	ctr := f.d.add("unlabelled", true, runnerLabels("", false, created, time.Time{}))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err == nil {
		t.Error("a runner with no slot label survived reconciliation")
	}
}

// A runner naming a slot that no longer exists is an orphan: its session's slot
// was removed by an erase, so the container has nothing to be reconciled into.
func TestReconcileRemovesARunnerForAnUnknownSlot(t *testing.T) {
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now
	ctr := f.d.add("orphan", true, runnerLabels("slot-9", false, created, time.Time{}))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err == nil {
		t.Error("a runner for an unknown slot survived reconciliation")
	}
	// The real slot must be untouched.
	if slots := f.p.Slots(); len(slots) != 1 || slots[0].ID != "slot-1" {
		t.Errorf("slots = %+v, want just slot-1", slots)
	}
}

// A runner missing its creation label has an unknown age, so the recycle budget
// cannot be computed. Adopting it would attach a 5-minute budget to a container
// of unknown vintage, so it must be replaced.
func TestReconcileReplacesARunnerWithoutACreationLabel(t *testing.T) {
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	lbl := labels.Base("slot-1", "c-1", "runner:test")
	delete(lbl, labels.CreatedAt)
	ctr := f.d.add("no-age", true, lbl)

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err == nil {
		t.Error("a runner with no creation label survived reconciliation")
	}
	if slots := f.p.Slots(); len(slots) != 1 || slots[0].ContainerID == ctr.id {
		t.Errorf("slot was not given a replacement container: %+v", slots)
	}
}

// A dead container is not adopted as healthy. Its identity is recorded so the
// slot is known, but the state marks it dead for EnsurePool to replace.
func TestReconcileMarksADeadRunnerDead(t *testing.T) {
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now
	ctr := f.d.add("dead", false, runnerLabels("slot-1", false, created, time.Time{}))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	slots := f.p.Slots()
	if slots[0].State != StateDead {
		t.Errorf("state = %q, want dead", slots[0].State)
	}
	// The container is left for EnsurePool to replace rather than removed here,
	// so its exit code stays available for diagnosis.
	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err != nil {
		t.Errorf("dead container was removed; its exit state should stay inspectable: %v", err)
	}
}

// Reconcile must not act on containers that are not ours. A container without
// our role label is not in the query result at all, which is what keeps an
// operator's own containers on the host safe from a blanket cleanup.
func TestReconcileIgnoresContainersWithoutOurRoleLabel(t *testing.T) {
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	foreign := f.d.add("postgres", true, map[string]string{"com.docker.compose.project": "other"})
	// Even a container that carries a slot label, but not our role, must be
	// ignored rather than removed.
	impersonator := f.d.add("impostor", true, map[string]string{
		"msout.slot.id": "slot-1",
	})

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	for _, id := range []string{foreign.id, impersonator.id} {
		if _, err := f.d.InspectContainer(t.Context(), id); err != nil {
			t.Errorf("container %s was acted on without our role label", id)
		}
	}
}

// A container that vanishes between list and inspect is fine: the only thing
// reconciliation could have wanted from it was to delete it.
func TestReconcileToleratesAContainerVanishingMidScan(t *testing.T) {
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	// Fail the first inspect only.
	f.d.failNext("inspect", errVanished{})

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile must tolerate a vanished container, got: %v", err)
	}
}

// errVanished stands in for a 404 from the daemon.
type errVanished struct{}

func (errVanished) Error() string { return "no such container" }

// A list failure is fatal for reconcile — without the container list there is
// nothing to reconcile against — and must be reported rather than swallowed.
func TestReconcileReportsAListFailure(t *testing.T) {
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	f.d.failNext("list", errDaemonDown{})

	if err := f.p.Reconcile(t.Context(), nothingExpired); err == nil {
		t.Fatal("a failed container list must be reported, not swallowed")
	}
}

type errDaemonDown struct{}

func (errDaemonDown) Error() string { return "daemon unreachable" }

// Reconciliation is idempotent. `api` and the orchestrator both reconcile, and
// reconcile may also be invoked again on a later boot; running it twice must not
// orphan or duplicate anything.
func TestReconcileIsIdempotent(t *testing.T) {
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now.Add(-time.Minute)
	f.d.add("bound", true, runnerLabels("slot-1", true, created, f.now.Add(time.Hour)))

	for i := 0; i < 3; i++ {
		if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
			t.Fatalf("reconcile pass %d: %v", i, err)
		}
	}

	if n := f.d.count(); n != 1 {
		t.Errorf("after 3 reconcile passes there are %d containers, want 1", n)
	}
	slots := f.p.Slots()
	if len(slots) != 1 {
		t.Fatalf("slots = %d, want 1", len(slots))
	}
	if slots[0].State != StateBound || slots[0].SessionGUID != guid {
		t.Errorf("slot drifted across repeated reconcile: %+v", slots[0])
	}
}

// During boot `api` is not yet reachable, so main passes a predicate that
// reports nothing expired. The safe direction is adopting rather than deleting: a
// container that should have been reaped is recoverable, a live session deleted
// is not.
func TestBootPredicateAdoptsRatherThanDeletes(t *testing.T) {
	neverExpire := func(string) bool { return false }
	if neverExpire("3f2504e0-4f89-11d3-9a0c-0305e82c3301") {
		t.Fatal("the boot predicate must report no session as expired")
	}

	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now.Add(-time.Minute)
	ctr := f.d.add("bound", true, runnerLabels("slot-1", true, created, f.now.Add(-time.Hour)))

	// Even with an expires label in the past, the boot predicate must not
	// delete it: the orchestrator has no authoritative session view yet.
	if err := f.p.Reconcile(t.Context(), neverExpire); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err != nil {
		t.Error("a bound runner was deleted during boot; NeverExpire must adopt, not delete")
	}
	if slots := f.p.Slots(); slots[0].SessionGUID != guid {
		t.Errorf("session not adopted: %+v", slots[0])
	}
}
