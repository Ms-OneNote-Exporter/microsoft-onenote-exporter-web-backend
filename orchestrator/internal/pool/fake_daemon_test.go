package pool

import (
	"context"
	"fmt"
	"sync"
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

func (d *fakeDaemon) CreateContainer(_ context.Context, req dockerapi.CreateRequest, name string) (dockerapi.CreateResponse, error) {
	if err := d.shouldFail("create"); err != nil {
		return dockerapi.CreateResponse{}, err
	}
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
	return dockerapi.CreateResponse{ID: id}, nil
}

func (d *fakeDaemon) StartContainer(_ context.Context, id string) error {
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

func (d *fakeDaemon) StopContainer(_ context.Context, id string, _ int) error {
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

func (d *fakeDaemon) RemoveContainer(_ context.Context, id string) error {
	if err := d.shouldFail("remove"); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.containers, id)
	return nil
}

func (d *fakeDaemon) InspectContainer(_ context.Context, id string) (*dockerapi.Container, error) {
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
		State:  dockerapi.ContainerState{Status: statusOf(c.running), Running: c.running},
		Config: dockerapi.ContainerConfig{Image: c.image, Labels: copyLabels(c.labels)},
		Labels: copyLabels(c.labels),
		Mounts: toEngineMounts(c.mounts),
	}, nil
}

func (d *fakeDaemon) ListContainersByLabel(_ context.Context, label string) ([]string, error) {
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
