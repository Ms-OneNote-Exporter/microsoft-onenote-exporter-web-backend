package pool

// `claim` must not hand back a runner that is not yet listening.
//
// ## Why this file exists
//
// Found by attempting a real login for the first time. The api's credential POST
// and the runner's server start, from the two containers' own logs:
//
//     api      15:53:43.166  502 credential handoff failed
//     runner   15:53:43.745  Server listening at http://172.30.0.2:3100
//
// The credential arrived **579ms before the runner was listening.** `StartContainer`
// returns as soon as the Engine accepts the start; the process inside still has to
// start and bind.
//
// ## Why nothing caught it
//
// Every existing test's fake daemon answered `InspectContainer` with whatever it
// liked, or not at all, because nothing consulted it during a create. The tests
// asserted the *shape* of the claim response — that it carried a `runnerUrl` — which
// was true, and true of an address nothing was listening on yet.
//
// The fix is in the orchestrator rather than the api because the api cannot tell
// "not ready yet" from "wrong address": both are a connection failure, and retrying
// a credential POST on that basis risks writing half a credential twice. The
// orchestrator reads the Engine's health state, which is a real signal.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/dockerapi"
)

// readinessDaemon scripts the health state reported for each inspect, so a wait can
// be exercised without a daemon and without sleeping longer than the script needs.
type readinessDaemon struct {
	*fakeDaemon

	// states is consumed one entry per inspect, in order. The last entry repeats
	// once exhausted, so a script ending in "healthy" models a runner that comes up
	// and stays up.
	states []dockerapi.ContainerHealth

	// running parallels states. Nil means every entry is running.
	running []bool

	calls int
}

func (d *readinessDaemon) InspectContainer(ctx context.Context, id string) (*dockerapi.Container, error) {
	i := d.calls
	d.calls++
	if i >= len(d.states) {
		i = len(d.states) - 1
	}

	running := true
	if i < len(d.running) {
		running = d.running[i]
	}

	// Delegate to the embedded fake first, so a container the pool never created is
	// still reported as missing — the script is about health state, not about
	// inventing containers.
	ctr, err := d.fakeDaemon.InspectContainer(ctx, id)
	if err != nil {
		return nil, err
	}
	ctr.State.Status = map[bool]string{true: "running", false: "exited"}[running]
	ctr.State.Running = running
	ctr.State.ExitCode = map[bool]int{true: 0, false: 137}[running]
	ctr.State.Health = d.states[i]
	return ctr, nil
}

// live reports how many containers the fake still holds, under its own lock.
func (d *readinessDaemon) live() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.containers)
}

func newReadinessPool(t *testing.T, states []dockerapi.ContainerHealth, running []bool) (*Pool, *readinessDaemon) {
	d := &readinessDaemon{fakeDaemon: newFakeDaemon(), states: states, running: running}
	cfg := testConfig(t, 1)
	// Short, so "never healthy" does not burn 45 real seconds. The timeout is the
	// thing under test, so it is set explicitly rather than inherited from the
	// default — a test that inherits the production value is a test that either
	// takes 45s or is skipped in short mode.
	cfg.RunnerReadyTimeout = 400 * time.Millisecond
	return New(cfg, d, nil), d
}

func health(status string, streak int) dockerapi.ContainerHealth {
	return dockerapi.ContainerHealth{Status: status, FailingStreak: streak}
}

// The measured case: a runner that is running but not yet listening.
func TestClaimWaitsForARunnerThatIsStillStarting(t *testing.T) {
	p, d := newReadinessPool(t, []dockerapi.ContainerHealth{
		health("starting", 0),
		health("starting", 0),
		health("healthy", 0),
	}, nil)

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}

	// Three inspects: two not-ready, then healthy. Fewer means the wait returned
	// early, which is the bug — the credential would be POSTed to nothing.
	if d.calls < 3 {
		t.Errorf("claim returned after %d inspects; the runner became healthy on the "+
			"third, so the credential would have been POSTed to a port nobody was "+
			"listening on", d.calls)
	}
}

// A runner that never becomes healthy must fail the claim, not hand back an address.
func TestClaimFailsRatherThanHandBackAnUnreadyRunner(t *testing.T) {
	p, _ := newReadinessPool(t, []dockerapi.ContainerHealth{health("starting", 0)}, nil)

	err := p.EnsurePool(t.Context())
	if err == nil {
		t.Fatal("claim succeeded against a runner that never became ready")
	}
	if !strings.Contains(err.Error(), "did not become ready") {
		t.Errorf("error %q does not say the runner never became ready; an operator "+
			"reading it cannot tell a timeout from a crash", err)
	}
}

// Unhealthy *and* past the retry budget is a runner that is not coming. Waiting out
// the deadline would only be waiting for a verdict the Engine is not going to give.
func TestClaimGivesUpOnARunnerExhaustingItsRetries(t *testing.T) {
	p, _ := newReadinessPool(t, []dockerapi.ContainerHealth{health("unhealthy", 3)}, nil)

	start := time.Now()
	err := p.EnsurePool(t.Context())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("claim succeeded against an unhealthy runner")
	}
	if !strings.Contains(err.Error(), "never became healthy") {
		t.Errorf("error %q should name the retry exhaustion, not a timeout", err)
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("waited %v; a runner past its retry budget should not consume the "+
			"whole ready timeout", elapsed)
	}
}

// A container that exits is not going to become ready, and must be reported with its
// exit code rather than a timeout.
func TestClaimReportsAnExitedRunnerWithItsExitCode(t *testing.T) {
	p, _ := newReadinessPool(t,
		[]dockerapi.ContainerHealth{health("starting", 0)},
		[]bool{false},
	)

	err := p.EnsurePool(t.Context())
	if err == nil {
		t.Fatal("claim succeeded against an exited container")
	}
	if got := err.Error(); !strings.Contains(got, "exited") || !strings.Contains(got, "137") {
		t.Errorf("error %q does not name the exit; \"did not become ready within 45s\" "+
			"for a process that died in 600ms sends an operator looking in the wrong "+
			"place entirely", got)
	}
}

// The container must not survive a failed wait, or the next reconcile adopts it as a
// live runner that never became ready — and the pool then reports a runner no
// request can reach, which is the exact shape of the bug this file is about.
func TestAFailedReadinessRemovesTheContainer(t *testing.T) {
	p, d := newReadinessPool(t, []dockerapi.ContainerHealth{health("starting", 0)}, nil)

	if err := p.EnsurePool(t.Context()); err == nil {
		t.Fatal("expected the wait to fail")
	}
	if d.live() != 0 {
		t.Errorf("%d container(s) survived a failed readiness wait; boot reconciliation "+
			"will adopt one as a live runner that never became ready", d.live())
	}
}

// A runner that declares no healthcheck is treated as ready rather than as failed,
// because the create request always declares one — but it is not reported as
// *healthy*, so the two cannot be confused in a log line.
func TestAContainerWithNoHealthcheckIsTreatedAsReady(t *testing.T) {
	p, d := newReadinessPool(t, []dockerapi.ContainerHealth{health("", 0)}, nil)

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("a container with no healthcheck should not be a readiness failure: %v", err)
	}
	if d.calls != 1 {
		t.Errorf("inspected %d times; one check is enough", d.calls)
	}
}
