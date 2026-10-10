package pool

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/dockerapi"
)

// fakeDaemon is an in-memory Docker Engine stand-in for tests.
//
// It is a fake rather than a mock with expectations because the interesting
// tests here are about *reconciliation outcomes* — what the pool decides about a
// given set of containers — not about whether a particular call was made. A fake
// that models container state lets a test assert the decision; a mock would only
// confirm the sequence, which the reconciler's own tests already cover.
//
// It is safe for concurrent use, because the pool calls it from the maintenance
// goroutine as well as from request handlers.
type fakeDaemon struct {
	mu sync.Mutex

	// containers maps container id to its state.
	containers map[string]*fakeContainer

	// nextID is the id handed to the next created container.
	nextID int

	// failing is the operation to fail, and failingErr its error. Used to
	// exercise the failure paths — a create that fails must return the slot to
	// the pool, not strand it.
	failing    string
	failingErr error

	// blockOn names the operation that blocks until the caller's context is done,
	// answering as the Engine does after a client has stopped listening. It exists
	// because this fake used to ignore its context parameter entirely, which made
	// the worst bug in this component untestable: every cleanup path runs after
	// something has already gone wrong, and the question those paths exist to
	// answer — *did the cleanup reach the daemon, or did it die with the request?*
	// — is precisely a question about the context.
	//
	// Two operations are useful, and they are the two the observed incident needed,
	// because they leave different things behind:
	//
	//   - "create": the Engine finishes the write the client asked for and the
	//     client never learns the id. Reproduces `msout-slot-1-…`, sitting in
	//     `Created` with nothing pointing at it.
	//   - "inspect": create **and** start have already succeeded, and the abort
	//     lands in the readiness wait. Reproduces `msout-slot-2-…`, **Up (healthy)**
	//     — a running Chromium holding the session's vault bind, owned by nothing.
	//
	// Both were invisible to the pool, which is the property the hook exists to make
	// assertable.
	blockOn string

	// blocked is closed by the blocked operation when it is reached, so a test knows
	// when the abort will actually land inside it. A sleep would race: a
	// cancellation arriving earlier aborts the *destroy* leg instead, which is a
	// different defect with a different fix.
	blocked     chan struct{}
	blockOnce   sync.Once
	blockWaited time.Duration

	// calls records every operation the pool asked for, with the context state it
	// carried. The assertion a cancellation test needs is not "remove was called"
	// but "remove was called with a context that was still alive".
	calls []fakeCall
}

// fakeCall is one recorded Docker call.
type fakeCall struct {
	op string
	// live is whether the caller's context was still usable when the call was
	// made — the whole point of the recording. `ctx.Err() != nil` answers it
	// exactly as the real client would have failed the request.
	live bool
}

// fakeContainer is one container in the fake daemon.
type fakeContainer struct {
	id      string
	name    string
	running bool
	labels  map[string]string
	mounts  []dockerapi.CreateMount
	image   string
}

func newFakeDaemon() *fakeDaemon {
	return &fakeDaemon{containers: make(map[string]*fakeContainer), nextID: 1}
}

// add installs a container directly, so a test can describe a pre-existing
// daemon state — which is exactly what boot reconciliation reads.
func (d *fakeDaemon) add(name string, running bool, labels map[string]string) *fakeContainer {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := fmt.Sprintf("ctr%d", d.nextID)
	d.nextID++
	c := &fakeContainer{id: id, name: name, running: running, labels: copyLabels(labels)}
	d.containers[id] = c
	return c
}

// labels exposes a container's labels for assertion.
func (d *fakeDaemon) labels(id string) map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.containers[id]
	if !ok {
		return nil
	}
	return copyLabels(c.labels)
}

// count returns how many containers exist.
func (d *fakeDaemon) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.containers)
}

// findByName returns the container carrying name, or nil.
//
// By name rather than by id because that is how the pool reaches the one container
// it has no id for: a create the Engine finished after the caller hung up. Asserting
// on the count alone would miss the case that matters, where the survivor is the
// one thing nobody has a handle to.
func (d *fakeDaemon) findByName(name string) *fakeContainer {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.containers {
		if c.name == name {
			return c
		}
	}
	return nil
}

// names returns every container's Engine-visible name, sorted by id.
//
// Read directly rather than through `ListContainersByLabel` because it is the
// host-level view this assertion is about: what `docker ps -a` would show, which is
// what an operator looked at to find the two orphans in the first place.
func (d *fakeDaemon) names() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.containers))
	for _, c := range d.containers {
		out = append(out, c.name)
	}
	sort.Strings(out)
	return out
}

// failNext makes the named operation fail once, then clear itself.
//
// "once" matters: a test that wants to observe recovery — a slot returned to the
// pool, a subsequent EnsurePool that succeeds — needs the second attempt to work.
func (d *fakeDaemon) failNext(op string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failing = op
	d.failingErr = err
}

// cancelCreates arms the hook on "create": the next create blocks until its caller
// gives up, and every call after that is recorded with the context it carried.
func (d *fakeDaemon) cancelCreates() {
	d.armBlock("create")
}

// cancelInspects arms the hook on "inspect", so the abort lands in the readiness
// wait — after create and start have already succeeded. That is the window that left
// a **running** container behind, and the one that matters more.
func (d *fakeDaemon) cancelInspects() {
	d.armBlock("inspect")
}

func (d *fakeDaemon) armBlock(op string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.blockOn = op
	d.blocked = make(chan struct{})
	d.blockWaited = 5 * time.Second
}

// waitForBlockedCreate blocks until a create has reached the cancellation hook.
//
// Without it a test cancels at an arbitrary moment and asserts on a window it did
// not aim at: cancel too early and the abort lands in `destroy` (which has its own
// test), too late and the claim has already finished. A test that cannot say *when*
// it cancelled is a test that proves nothing about the create path.
func (d *fakeDaemon) waitForBlockedCreate(t *testing.T) {
	t.Helper()
	d.mu.Lock()
	blocked := d.blocked
	wait := d.blockWaited
	d.mu.Unlock()
	if blocked == nil {
		t.Fatal("waitForBlockedCreate without an armed cancellation hook")
	}
	select {
	case <-blocked:
	case <-time.After(wait):
		t.Fatalf("no create blocked within %v; the test did not reach the window it "+
			"was aiming at", wait)
	}
}

// markBlocked signals that a create has reached the blocking point.
func (d *fakeDaemon) markBlocked() {
	d.mu.Lock()
	blocked := d.blocked
	d.mu.Unlock()
	if blocked == nil {
		return
	}
	d.blockOnce.Do(func() { close(blocked) })
}

// callsFor returns the recorded calls of one operation, in order.
func (d *fakeDaemon) callsFor(op string) []fakeCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []fakeCall
	for _, c := range d.calls {
		if c.op == op {
			out = append(out, c)
		}
	}
	return out
}

// forgetCalls clears the recording, so a test can assert about the calls made
// after a given event rather than everything that preceded it.
func (d *fakeDaemon) forgetCalls() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = nil
}

// record notes a call and the state of the context it arrived on.
func (d *fakeDaemon) record(ctx context.Context, op string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, fakeCall{op: op, live: ctx.Err() == nil})
}

// lastCreate returns the most recent create request, so a test can assert what
// the pool asked the daemon for.
func (d *fakeDaemon) lastCreate() (dockerapi.CreateRequest, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out dockerapi.CreateRequest
	found := false
	for _, c := range d.containers {
		out = dockerapi.CreateRequest{Image: c.image, Mounts: c.mounts, Labels: copyLabels(c.labels)}
		found = true
	}
	return out, found
}

func (d *fakeDaemon) shouldFail(op string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failing == op {
		err := d.failingErr
		d.failing = ""
		d.failingErr = nil
		return err
	}
	return nil
}

func (d *fakeDaemon) CreateContainer(ctx context.Context, req dockerapi.CreateRequest, name string) (dockerapi.CreateResponse, error) {
	d.record(ctx, "create")
	// The hook: the Engine finishes the write the client asked for even though the
	// client has stopped listening, so the container exists — and the caller is told
	// it failed, because the answer never reached it. That combination is the leak:
	// something on the host that this process created and cannot name.
	//
	// Observed as `msout-slot-1-…` sitting in `Created` with nothing pointing at it.
	if d.shouldBlock(ctx, "create") {
		d.store(req, name)
		return dockerapi.CreateResponse{}, ctx.Err()
	}
	if err := d.shouldFail("create"); err != nil {
		return dockerapi.CreateResponse{}, err
	}
	return dockerapi.CreateResponse{ID: d.store(req, name)}, nil
}

// store records a created container and returns its id.
func (d *fakeDaemon) store(req dockerapi.CreateRequest, name string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	id := fmt.Sprintf("ctr%d", d.nextID)
	d.nextID++
	d.containers[id] = &fakeContainer{
		id:     id,
		name:   name,
		labels: copyLabels(req.Labels),
		mounts: req.Mounts,
		image:  req.Image,
	}
	return id
}

// shouldBlock reports whether `op` is the armed hook, consuming the arming so only
// the first such call blocks — the ones after it are the recovery the test watches
// for. When it is armed it waits for the context to be done and reports that the
// call died with it, which is what the real client does.
func (d *fakeDaemon) shouldBlock(ctx context.Context, op string) bool {
	d.mu.Lock()
	if d.blockOn != op {
		d.mu.Unlock()
		return false
	}
	d.blockOn = ""
	blocked := d.blocked
	d.mu.Unlock()

	d.blockOnce.Do(func() {
		if blocked != nil {
			close(blocked)
		}
	})
	<-ctx.Done()
	return true
}

func (d *fakeDaemon) StartContainer(ctx context.Context, id string) error {
	d.record(ctx, "start")
	if err := d.shouldFail("start"); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.containers[id]
	if !ok {
		return fmt.Errorf("no such container: %s", id)
	}
	c.running = true
	return nil
}

func (d *fakeDaemon) StopContainer(ctx context.Context, id string, _ int) error {
	d.record(ctx, "stop")
	if err := d.shouldFail("stop"); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := d.containers[id]; ok {
		c.running = false
	}
	// Stopping a container that is already gone is the outcome the caller
	// wanted, matching the real client's 404 handling.
	return nil
}

// RemoveContainer removes by id or by name.
//
// By name, because the pool removes a container by name on one path: a create the
// Engine completed after the client hung up leaves a container with no id this
// process ever saw, and the name is the only handle it has. The real client accepts
// either, so the fake must too or that path cannot be tested at all.
func (d *fakeDaemon) RemoveContainer(ctx context.Context, id string) error {
	d.record(ctx, "remove")
	if err := d.shouldFail("remove"); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.containers[id]; !ok {
		for key, c := range d.containers {
			if c.name == id {
				delete(d.containers, key)
				break
			}
		}
		return nil
	}
	delete(d.containers, id)
	return nil
}

func (d *fakeDaemon) InspectContainer(ctx context.Context, id string) (*dockerapi.Container, error) {
	d.record(ctx, "inspect")
	// The readiness wait is where the observed abort landed: create and start had
	// both succeeded, so the container was **running**, and the cleanup that should
	// have taken it down was about to run on a dead context.
	if d.shouldBlock(ctx, "inspect") {
		return nil, ctx.Err()
	}
	if err := d.shouldFail("inspect"); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.containers[id]
	if !ok {
		return nil, &dockerapi.EngineError{Status: 404, Message: "no such container"}
	}
	return &dockerapi.Container{
		ID: c.id,
		Names: []string{
			c.name,
		},
		State: dockerapi.ContainerState{
			Status:  statusOf(c.running),
			Running: c.running,
			// Healthy as soon as it is running, so a create does not have to be
			// told to become ready. `EnsurePool` waits for this before returning a
			// claim, and the fakes were written before that wait existed — so they
			// report it here rather than each test having to.
			//
			// The wait's own behaviour is covered directly in readiness_test.go,
			// where a fake that reports `starting` first is the point.
			Health: dockerapi.ContainerHealth{Status: "healthy"},
		},
		Config: dockerapi.ContainerConfig{Image: c.image, Labels: copyLabels(c.labels)},
		Labels: copyLabels(c.labels),
		Mounts: toEngineMounts(c.mounts),
	}, nil
}

func (d *fakeDaemon) ListContainersByLabel(ctx context.Context, label string) ([]string, error) {
	d.record(ctx, "list")
	if err := d.shouldFail("list"); err != nil {
		return nil, err
	}
	// Parse the "label=key=value" filter the real client sends.
	key, value := parseLabelFilter(label)
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.containers))
	for id, c := range d.containers {
		if c.labels[key] == value {
			out = append(out, id)
		}
	}
	return out, nil
}

func parseLabelFilter(filter string) (key, value string) {
	rest := filter
	if len(rest) > 6 && rest[:6] == "label=" {
		rest = rest[6:]
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] == '=' {
			return rest[:i], rest[i+1:]
		}
	}
	return rest, ""
}

func statusOf(running bool) string {
	if running {
		return "running"
	}
	return "exited"
}

func toEngineMounts(mounts []dockerapi.CreateMount) []dockerapi.Mount {
	out := make([]dockerapi.Mount, 0, len(mounts))
	for _, m := range mounts {
		out = append(out, dockerapi.Mount{
			Type:        m.Type,
			Source:      m.Source,
			Destination: m.Destination,
			RW:          !m.ReadOnly,
		})
	}
	return out
}

// copyLabels returns an independent copy.
//
// Reconciliation mutates nothing, but a test asserting on labels after a pool
// operation would otherwise be reading the same map the fake handed out, and a
// later mutation would silently change a passing assertion.
func copyLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// nowFixture returns a fixed instant and a clock pinned to it, for TTL tests.
// The instant comes first because it is the value tests assert against.
func nowFixture() (time.Time, func() time.Time) {
	fixed := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	return fixed, func() time.Time { return fixed }
}
