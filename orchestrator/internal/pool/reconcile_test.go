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
//
// It seeds `p.slots` directly, which means it stands for an **already-established**
// pool — a long-running process that has its slots and is reconciling a container that
// has since lost its slot to an erase. It also marks the pool bootstrapped, so the
// cold-start path in `Reconcile` is not taken.
//
// That is the right default for these tests and it is also how this file managed to be
// green while the pool was being wiped on every restart: seeding slots is exactly the
// condition that does not hold at boot. The boot case is `newColdStartFixture` below,
// and it was written afterwards, once it was clear that no test here could have
// reached it.
func newReconcileFixture(t *testing.T, poolSize int, seedSlots ...*Slot) *reconcileFixture {
	t.Helper()
	cfg := testConfig(t, poolSize)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())
	now, _ := nowFixture()
	p.now = func() time.Time { return now }
	p.bootstrapped = true
	for _, s := range seedSlots {
		p.slots[s.ID] = s
	}
	return &reconcileFixture{p: p, d: d, cfg: cfg, now: now}
}

// newColdStartFixture returns a pool that has just started: no slots, and not
// bootstrapped, which is the state `Reconcile` finds on boot in main.go — it runs
// before `EnsurePool`.
func newColdStartFixture(t *testing.T, poolSize int) *reconcileFixture {
	t.Helper()
	cfg := testConfig(t, poolSize)
	d := newFakeDaemon()
	p := New(cfg, d, discardLog())
	now, _ := nowFixture()
	p.now = func() time.Time { return now }
	if len(p.slots) != 0 || p.bootstrapped {
		t.Fatal("a cold-start pool must have no slots and must not be bootstrapped")
	}
	return &reconcileFixture{p: p, d: d, cfg: cfg, now: now}
}

// ---- cold start: the case that was not being tested at all ------------------
//
// Boot reconciliation ran before `EnsurePool`, so `p.slots` was empty and every runner
// the daemon still had read as an orphan. On a real host that destroyed the pool on
// every restart:
//
//     WARN reconcile: runner for unknown slot, removing  container=329029f8… slot=slot-2
//     INFO boot reconciliation complete  slots:0
//
// The container was bound to a session mid-login, holding a cookie jar in its vault.
// Deleting it is the one outcome boot reconciliation's own comment rules out: "Adopting
// a container is the recoverable error here; deleting a live session is not."

// A runner that survives a restart must be adopted, not deleted. The slot id comes
// from the container's own label, which is the only durable record that it existed.
func TestReconcileAtColdStartAdoptsARatherThanDeletingThePool(t *testing.T) {
	f := newColdStartFixture(t, 1)
	created := f.now.Add(-time.Minute)
	ctr := f.d.add("idle", true, runnerLabels("slot-2", false, created, time.Time{}))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err != nil {
		t.Fatal("boot reconciliation deleted a runner that was still running; " +
			"a restart must not be a wipe")
	}
	slots := f.p.Slots()
	if len(slots) != 1 {
		t.Fatalf("slots = %d, want 1", len(slots))
	}
	// The id must be the one in the label. Renumbering here is what made the api's
	// SQLite rows name slots that did not exist.
	if slots[0].ID != "slot-2" {
		t.Errorf("adopted slot id = %q, want slot-2 from the container label", slots[0].ID)
	}
	if slots[0].ContainerID != ctr.id {
		t.Errorf("adopted container = %q, want %q", slots[0].ContainerID, ctr.id)
	}
	if slots[0].State != StateIdle {
		t.Errorf("state = %q, want idle", slots[0].State)
	}
}

// The vault case: a runner bound to a live session is the one holding a credential, so
// it is the one whose loss is unrecoverable. main.go passes `NeverExpire` at boot
// because `api` is not reachable yet — which must not be read as "expire everything".
func TestReconcileAtColdStartAdoptsABoundRunnerWithItsVault(t *testing.T) {
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	f := newColdStartFixture(t, 1)
	created := f.now.Add(-time.Minute)
	expires := f.now.Add(time.Hour)
	ctr := f.d.add("bound", true, runnerLabels("slot-2", true, created, expires))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err != nil {
		t.Fatal("boot reconciliation deleted a bound runner; its vault held the " +
			"cookie jar for a session in progress")
	}
	slots := f.p.Slots()
	if len(slots) != 1 {
		t.Fatalf("slots = %d, want 1", len(slots))
	}
	if slots[0].State != StateBound || slots[0].SessionGUID != guid {
		t.Errorf("adopted as %q/%q, want bound/%s", slots[0].State, slots[0].SessionGUID, guid)
	}
}

// A boot-detected dead bound container must appear in DeadBoundSlots so the api
// can distinguish "dead and reported" from "never seen."
func TestReconcileAtColdStartReportsADeadBoundRunnerInDeadSlots(t *testing.T) {
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	f := newColdStartFixture(t, 1)
	created := f.now.Add(-time.Minute)
	expires := f.now.Add(time.Hour)
	_ = f.d.add("dead-bound", false, runnerLabels("slot-2", true, created, expires))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	slots := f.p.Slots()
	if len(slots) != 1 {
		t.Fatalf("slots = %d, want 1", len(slots))
	}
	if slots[0].State != StateDead {
		t.Fatalf("state = %q, want dead", slots[0].State)
	}
	if slots[0].SessionGUID != guid {
		t.Fatalf("session = %q, want %q", slots[0].SessionGUID, guid)
	}
	if got := f.p.DeadBoundSlots(); len(got) != 1 || got[0] != "slot-2" {
		t.Fatalf("DeadBoundSlots = %v, want [slot-2]: a boot-detected dead bound "+
			"container must be reported in /stats deadSlots", got)
	}
	if got := f.p.Stats().DeadSlots; len(got) != 1 || got[0] != "slot-2" {
		t.Fatalf("Stats().DeadSlots = %v, want [slot-2]", got)
	}
}

// Adoption and pool filling happen back to back on every boot, so they must not fight.
// `nextSlotSeq` is a process-global starting at 1: without skipping ids already in use,
// filling a pool that adopted `slot-1` overwrote the entry for a container that was
// still running.
func TestEnsurePoolDoesNotOverwriteASlotAdoptedAtColdStart(t *testing.T) {
	f := newColdStartFixture(t, 2)
	created := f.now.Add(-time.Minute)
	ctr := f.d.add("idle", true, runnerLabels("slot-1", false, created, time.Time{}))
	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if err := f.p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}

	slots := f.p.Slots()
	if len(slots) != 2 {
		t.Fatalf("slots = %d, want 2: %+v", len(slots), slots)
	}
	var adopted int
	for _, s := range slots {
		if s.ContainerID == ctr.id {
			adopted++
			if s.ID != "slot-1" {
				t.Errorf("adopted container is now in %q, want slot-1", s.ID)
			}
		}
	}
	if adopted != 1 {
		t.Errorf("the adopted container appears in %d slots, want exactly 1 — "+
			"EnsurePool overwrote it", adopted)
	}
	ids := map[string]bool{}
	for _, s := range slots {
		if ids[s.ID] {
			t.Errorf("duplicate slot id %q", s.ID)
		}
		ids[s.ID] = true
	}
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

// ---- a replace whose create fails must not strand the slot -----------------
//
// `replace` removes the old container *first*, so between the remove and a
// successful create the slot holds nothing. If the create then failed, and the slot
// were left in `StateStarting`, the loss would be permanent rather than temporary:
//
//   - `refillable()` excludes `StateStarting`, because that state means a create is
//     in flight, so `EnsurePool` would never retry it
//   - `EnsurePool` counts a slot it is not refilling as `filled`, so the pool would
//     report itself full
//
// The result is a pool of 2 that can only ever serve 1, with nothing in `/stats` to
// say so — `size: 2`, one runner, and the missing position never coming back for the
// life of the process. This is the same hollow-slot failure `refillable()` was
// written to undo, reached through the one writer that still used the old state.
//
// So a failed create resets the slot to vacant, and the next `EnsurePool` fills it.
// The container count matters as much as the state: a create the Engine half-completed
// would leave a second container behind the one the slot is about to be given, and
// two runners on one `msout.slot.id` is exactly what the reconciler cannot unpick.

// `replace` is private and reached only from Reconcile, so the failure is staged
// through the daemon and the assertion is made on the pool.
func TestReconcileFailedReplaceLeavesTheSlotForEnsurePoolToRetry(t *testing.T) {
	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now.Add(-2 * time.Hour) // past the TTL, so Reconcile replaces it
	ctr := f.d.add("over-age", true, runnerLabels("slot-1", false, created, time.Time{}))
	// The old container is removed before the create, and this fails that create —
	// the Engine rejecting it, as it does for any of the reasons a create is refused.
	f.d.failNext("create", cpuRangeErr())

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	slots := f.p.Slots()
	if len(slots) != 1 {
		t.Fatalf("slots = %d, want 1: %+v", len(slots), slots)
	}
	slot := slots[0]
	// The old container is gone, so the slot must not claim to hold it.
	if slot.ContainerID != "" {
		t.Errorf("container = %q, want empty — the replaced container is already removed", slot.ContainerID)
	}
	if slot.ContainerID == ctr.id {
		t.Error("the slot still points at the container replace removed")
	}
	// The load-bearing assertion. `starting` after a create that is already over is
	// a claim that some create is in flight, and it is what makes the slot
	// unretryable for the rest of the process.
	if slot.State != StateVacant {
		t.Errorf("state = %q, want vacant — `starting` excludes the slot from "+
			"refillable(), so EnsurePool would never fill it again: %+v", slot.State, slot)
	}
	// A nonzero CreatedAt is the age of the container just removed, and `Stats`
	// skips only a zero one — so the slot would report an age and a remaining
	// budget for a container that does not exist.
	if !slot.CreatedAt.IsZero() {
		t.Errorf("CreatedAt = %v, want zero — it is the age of a container that no longer exists", slot.CreatedAt)
	}
	if slot.SessionGUID != "" || !slot.BoundAt.IsZero() {
		t.Errorf("session bookkeeping survived a containerless slot: guid=%q boundAt=%v",
			slot.SessionGUID, slot.BoundAt)
	}
	// The host is the other half of the claim: removed old container, no new one.
	if n := f.d.count(); n != 0 {
		t.Errorf("%d containers on the daemon after a failed replace, want 0 — the failed "+
			"create left one behind that no slot owns", n)
	}
	if stats := f.p.Stats(); stats.SlotAgeSec["slot-1"] != 0 || len(stats.SlotAgeSec) != 0 {
		t.Errorf("SlotAgeSec = %v, want no entry for a slot holding no container", stats.SlotAgeSec)
	}

	// The next tick is what the reset was for. `failNext` cleared itself, so this
	// create succeeds and the slot is back in service without a restart.
	if err := f.p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool after a failed replace: %v", err)
	}
	slots = f.p.Slots()
	if len(slots) != 1 {
		t.Fatalf("slots = %d, want 1", len(slots))
	}
	if slots[0].State != StateIdle {
		t.Errorf("refilled state = %q, want idle — EnsurePool did not retry the slot: %+v",
			slots[0].State, slots[0])
	}
	if slots[0].ContainerID == "" {
		t.Error("refilled slot has no container")
	}
	if slots[0].ID != "slot-1" {
		t.Errorf("refilled into %q, want slot-1 — the id is what sessions.runner_id names", slots[0].ID)
	}
	if n := f.d.count(); n != 1 {
		t.Errorf("%d containers after the refill, want exactly 1", n)
	}
}

// The over-age rule has two inputs and one of them used to be ignored: whether the
// container is bound, and whether its session is still alive. Only the bound-and-
// live cell is new, and it is not an edge case — `main.go` passes `NeverExpire`
// because `api` is not reachable during boot, so on every deploy *every* bound
// runner arrives at this branch looking live. Replacing one killed the browser
// holding the cookie jar of an export in progress.
//
// The other three cells are pinned here too, so the new branch cannot be widened
// by accident: the expired cell is still an orphan (the check above the TTL branch
// removes it, and age is not what decides that), and unbound stays replaced.
func TestReconcileOverAgeAdoptsOnlyABoundRunnerWithALiveSession(t *testing.T) {
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	expired := func(g string) bool { return g == guid }

	cases := []struct {
		name    string
		bound   bool
		session func(string) bool
		want    string // adopted | removed | replaced
	}{
		{
			name:    "bound to a live session is adopted",
			bound:   true,
			session: nothingExpired,
			want:    "adopted",
		},
		{
			name:    "bound to an expired session is removed as an orphan",
			bound:   true,
			session: expired,
			want:    "removed",
		},
		{
			name:    "unbound is replaced",
			bound:   false,
			session: nothingExpired,
			want:    "replaced",
		},
		{
			name:    "unbound is replaced whatever the predicate says",
			bound:   false,
			session: expired,
			want:    "replaced",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
			created := f.now.Add(-2 * time.Hour) // far past the 5-minute budget

			// The expires label is derived from the predicate rather than set per
			// case, so a cell cannot pass on a label that contradicts its own
			// premise.
			expires := f.now.Add(-time.Hour)
			if !tc.session(guid) {
				expires = f.now.Add(time.Hour)
			}

			ctr := f.d.add("over-age", true, runnerLabels("slot-1", tc.bound, created, expires))

			if err := f.p.Reconcile(t.Context(), tc.session); err != nil {
				t.Fatalf("reconcile: %v", err)
			}

			slots := f.p.Slots()
			if len(slots) != 1 {
				t.Fatalf("slots = %d, want 1", len(slots))
			}

			switch tc.want {
			case "adopted":
				// The container that is still there is the one holding the browser,
				// so it has to survive reconciliation intact.
				if _, err := f.d.InspectContainer(t.Context(), ctr.id); err != nil {
					t.Fatalf("an over-age runner bound to a live session was destroyed; "+
						"it holds the browser an export in progress is walking in: %v", err)
				}
				if slots[0].ContainerID != ctr.id {
					t.Errorf("adopted container = %q, want %q", slots[0].ContainerID, ctr.id)
				}
				if slots[0].State != StateBound {
					t.Errorf("state = %q, want bound", slots[0].State)
				}
				if slots[0].SessionGUID != guid {
					t.Errorf("adopted session = %q, want %q", slots[0].SessionGUID, guid)
				}
				// BoundAt is what the api reads as "when did this session bind".
				// The normal adopt path stamps it with the container's creation time
				// because at boot that is the only record of the bind that outlived
				// the process, so this path has to write it too — the replace path's
				// bookkeeping never did, which is part of why the slot it produced
				// was nonsense.
				if slots[0].BoundAt.UnixMilli() != created.UnixMilli() {
					t.Errorf("BoundAt = %v, want %v", slots[0].BoundAt, created)
				}
			case "removed":
				// The orphan check above the TTL branch is what does this, and the
				// outcome is the same one it gives for an expired session of any age:
				// never resurrect a session the caller says is gone.
				if _, err := f.d.InspectContainer(t.Context(), ctr.id); err == nil {
					t.Error("a container bound to an expired session survived reconciliation")
				}
				if slots[0].SessionGUID == guid {
					t.Errorf("slot still claims expired session %s", guid)
				}
				if slots[0].ContainerID == ctr.id {
					t.Errorf("slot still points at the removed container: %+v", slots[0])
				}
			case "replaced":
				// An unbound runner past its budget is a browser tree holding
				// nobody's session, which is exactly what the budget is for.
				if _, err := f.d.InspectContainer(t.Context(), ctr.id); err == nil {
					t.Error("the over-age container still exists after reconciliation")
				}
				if slots[0].ContainerID == ctr.id {
					t.Error("the over-age container was adopted as-is")
				}
				if slots[0].State != StateIdle {
					t.Errorf("replacement state = %q, want idle", slots[0].State)
				}
			}
		})
	}
}

// Adopting an over-age runner must not adopt a dead one as healthy. `refillable`
// excludes `StateBound`, so a slot recorded as bound with a container that has
// exited is one `EnsurePool` will never refill and nothing will ever replace: the
// dead-runner observer in `Sweep` reports it, and the api — which holds the session
// rows — releases it. The state has to say dead for that conversation to start.
//
// This is the case the adopt branch's own state computation exists for, and the
// only thing that distinguishes it from the case above is `State.Running`.
func TestReconcileAdoptsAnOverAgeBoundRunnerThatHasExitedAsDead(t *testing.T) {
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

	f := newReconcileFixture(t, 1, &Slot{ID: "slot-1"})
	created := f.now.Add(-2 * time.Hour)
	// running: false — the container has exited, and its labels still name a
	// session the caller reports as live.
	ctr := f.d.add("exited", false, runnerLabels("slot-1", true, created, f.now.Add(time.Hour)))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	slots := f.p.Slots()
	if slots[0].State != StateDead {
		t.Errorf("state = %q, want dead — an exited container adopted as bound is a "+
			"slot EnsurePool will never refill", slots[0].State)
	}
	// The identity is still adopted, so the slot is known and the container is
	// left inspectable for diagnosis rather than deleted here.
	if slots[0].ContainerID != ctr.id {
		t.Errorf("adopted container = %q, want %q", slots[0].ContainerID, ctr.id)
	}
	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err != nil {
		t.Errorf("the exited container was removed here; its exit state should stay "+
			"inspectable: %v", err)
	}
	if slots[0].SessionGUID != guid {
		t.Errorf("adopted session = %q, want %q", slots[0].SessionGUID, guid)
	}
	// A boot-adopted dead bound container must appear in DeadBoundSlots so the
	// api can distinguish "dead and reported" from "never seen".
	if got := f.p.DeadBoundSlots(); len(got) != 1 || got[0] != "slot-1" {
		t.Errorf("DeadBoundSlots = %v, want [slot-1]: a boot-adopted dead bound "+
			"container must be reported in /stats deadSlots", got)
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
	// The stopped container is removed — it holds no session's vault (an unbound
	// runner holds only a tmpfs), and leaving it would accumulate an Exited
	// container per crash, which is the leak §4.3 exists to remove. The slot's
	// identity is cleared with it, so the slot becomes an empty one the filler
	// refills on its next tick (T-12).
	if _, err := f.d.InspectContainer(t.Context(), ctr.id); err == nil {
		t.Errorf("dead container was NOT removed; it should be gone: %v", err)
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

// TestDeadRunnerAtBootDoesNotCostAPoolPosition verifies that a runner that
// died before a boot does not cost a pool position. The stopped container is
// removed by Reconcile, and the slot is left empty so EnsurePool refills it.
func TestDeadRunnerAtBootDoesNotCostAPoolPosition(t *testing.T) {
	f := newColdStartFixture(t, 1)
	// Create a stopped container (not Running) at boot. This simulates a
	// runner crashed and left Exited before the orchestrator restarts.
	created := f.now.Add(-time.Minute)
	// The container is created with running=false, so it is "dead" from
	// the daemon's perspective.
	_ = f.d.add("dead", false, runnerLabels("slot-1", false, created, time.Time{}))

	if err := f.p.Reconcile(t.Context(), nothingExpired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// After reconcile, the slot should have ContainerID = "" (empty) rather
	// than holding the dead container's id.
	slots := f.p.Slots()
	if len(slots) != 1 {
		t.Fatalf("slot count = %d, want 1", len(slots))
	}
	if slots[0].ContainerID != "" {
		t.Errorf("slot container ID = %q, want empty string (dead container removed)", slots[0].ContainerID)
	}
	if slots[0].State != StateDead {
		t.Errorf("slot state = %q, want %q", slots[0].State, StateDead)
	}

	// The dead container was removed and the slot's identity cleared, so the slot
	// is now empty — refillable() is true.
	if slots[0].ContainerID != "" {
		t.Errorf("slot container ID = %q, want empty string (dead container removed)", slots[0].ContainerID)
	}
	if !slots[0].refillable() {
		t.Error("slot is not refillable after Reconcile; the dead container was not removed")
	}

	// And EnsurePool refills it — the pool is whole again, and the slot is idle
	// once more, so /claim accepts it and /stats advertises it as claimable.
	if err := f.p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("ensure pool: %v", err)
	}
	after := f.p.Slots()
	if len(after) != 1 {
		t.Fatalf("slot count = %d, want 1", len(after))
	}
	if after[0].ContainerID == "" {
		t.Error("EnsurePool did not refill the slot; ContainerID is still empty")
	}
	if after[0].State != StateIdle {
		t.Errorf("state = %q, want %q (idle after refill)", after[0].State, StateIdle)
	}
	if !after[0].IsIdle() {
		t.Error("slot is not claimable after refill")
	}
}

