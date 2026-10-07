package pool

// A pool that cannot fill must not be indistinguishable from a busy one.
//
// ## Why this file exists
//
// Found by deploying to a 1-CPU VPS, not by reading this code.
//
// `NanoCpus` was the constant 2e9, so the Engine rejected every create with
//
//     Range of CPUs is from 0.01 to 1.00, as there are only 1 CPUs available
//
// and the pool stayed empty. What the stack reported:
//
//   /healthz   ok
//   /stats     {"size":0,"slotIds":[]}
//   login      503 {"error":"every session is busy"}
//
// All of it true, none of it useful. The user is told to wait for a busy slot; no
// slot will ever exist. `/healthz` says `ok` because every component it probes is
// alive — the fault is in the one thing it cannot see, which is whether a
// container can be created at all.
//
// Every CI job passed throughout, because every job asserts that components are
// healthy, and they were.
//
// So the pool carries the reason with it. These tests pin that, and the load-bearing
// one is verified by breaking the thing it guards.

import (
	"strings"
	"testing"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/dockerapi"
)

// cpuRangeErr is the Engine's actual message on a host with fewer cores than the
// container asks for. Quoted because the test asserts the reason survives, and a
// paraphrase would not prove that.
func cpuRangeErr() error {
	return &dockerapi.EngineError{
		Status:  400,
		Message: "Range of CPUs is from 0.01 to 1.00, as there are only 1 CPUs available",
	}
}

func TestStatsCarriesWhyThePoolCouldNotFill(t *testing.T) {
	cfg := testConfig(t, 2)
	d := newFakeDaemon()
	d.failNext("create", cpuRangeErr())
	p := New(cfg, d, nil)

	if err := p.EnsurePool(t.Context()); err == nil {
		t.Fatal("EnsurePool succeeded against a daemon that fails every create")
	}

	stats := p.Stats()
	// The assertion that matters: the reason is not lost.
	if stats.FillError == "" {
		t.Fatal("a pool that cannot fill reported no fillError")
	}
	if !strings.Contains(stats.FillError, "Range of CPUs") {
		t.Errorf("fillError = %q, want the Engine's message", stats.FillError)
	}
	if stats.FillFailures != 1 {
		t.Errorf("fillFailures = %d, want 1", stats.FillFailures)
	}
}

func TestAHealthyPoolReportsNoFillError(t *testing.T) {
	cfg := testConfig(t, 2)
	p := New(cfg, newFakeDaemon(), nil)
	_ = p.EnsurePool(t.Context())

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}
	stats := p.Stats()
	// Absent, not empty-and-present: a consumer distinguishes "no fault" from "no
	// information" by the key being missing.
	if stats.FillError != "" {
		t.Errorf("a healthy pool reported fillError = %q", stats.FillError)
	}
	if stats.Size != 2 {
		t.Errorf("size = %d, want 2", stats.Size)
	}
}

func TestTheFaultIsClearedByASuccessfulTopUp(t *testing.T) {
	cfg := testConfig(t, 1)
	d := newFakeDaemon()
	d.failNext("create", cpuRangeErr())
	p := New(cfg, d, nil)

	if err := p.EnsurePool(t.Context()); err == nil {
		t.Fatal("expected the first top-up to fail")
	}
	if p.LastFillFault() == nil {
		t.Fatal("no fault recorded after a failed top-up")
	}

	// `failNext` clears itself, so the second top-up succeeds. A fault that is
	// never cleared would keep reporting a pool as broken after it recovered —
	// which is its own kind of lie, and the one that would make an operator stop
	// trusting the field.
	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("second top-up: %v", err)
	}
	if fault := p.LastFillFault(); fault != nil {
		t.Errorf("fault survived a successful top-up: %v", fault)
	}
	if p.FillFailures() != 0 {
		t.Errorf("fillFailures = %d, want 0 after recovery", p.FillFailures())
	}
}

func TestConsecutiveFailuresAreCounted(t *testing.T) {
	cfg := testConfig(t, 1)
	d := newFakeDaemon()
	p := New(cfg, d, nil)

	for i := 1; i <= 3; i++ {
		d.failNext("create", cpuRangeErr())
		_ = p.EnsurePool(t.Context())
		if got := p.FillFailures(); got != i {
			t.Errorf("after %d attempts fillFailures = %d, want %d", i, got, i)
		}
	}
	// Three failures is "escalate"; one is "retry". A caller cannot make that
	// distinction without the count.
}

func TestRunnerNanoCpusIsWhatTheOperatorConfigured(t *testing.T) {
	// The create request must carry the configured value, not the old constant.
	// This is the assertion that would have caught the 1-CPU deployment failure.
	cfg := testConfig(t, 1)
	cfg.RunnerNanoCpus = 500_000_000 // half a core
	p := noDockerPool(t, cfg)

	req, err := p.buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.HostConfig.NanoCpus != 500_000_000 {
		t.Errorf("NanoCpus = %d, want the configured 500000000", req.HostConfig.NanoCpus)
	}

	// And the default is still POC §18's two cores, so a deployment that says
	// nothing gets what it got before.
	def := testConfig(t, 1)
	def.RunnerNanoCpus = 2_000_000_000
	defReq, err := noDockerPool(t, def).buildCreateRequest("slot-1", "c-1", "", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if defReq.HostConfig.NanoCpus != 2_000_000_000 {
		t.Errorf("default NanoCpus = %d, want 2000000000", defReq.HostConfig.NanoCpus)
	}
}

// A slot's CPU allowance must be validated at config load, not discovered on
// every pool top-up. Below the Engine's floor of 0.01 of a core, every create
// fails with a message about CPU ranges — which is the exact confusion this
// configuration replaces.
func TestRunnableCPUsMustBeAtLeastTheDockerMinimum(t *testing.T) {
	for _, bad := range []string{"0", "1", "9999", "-2000000000", "not-a-number", "1e9"} {
		env := map[string]string{
			"ORCH_HMAC_SECRET_FILE":       "/dev/null",
			"ORCH_RUNNER_NANO_CPUS":       bad,
			"ORCH_VAULT_ROOT":             "/srv/msout/vault",
			"ORCH_ARTIFACT_ROOT":          "/srv/msout/artifacts",
			"ORCH_RUNNER_TOKEN_FILE":      "/run/secrets/runner_token",
			"ORCH_RUNNER_CONTROL_NETWORK": "msout-runner-api",
			"ORCH_RUNNER_NETWORK":         "msout-runner",
		}
		getenv := func(k string) string { return env[k] }
		if _, err := config.Load(getenv, func(string) ([]byte, error) {
			return []byte(strings.Repeat("a", 64)), nil
		}); err == nil {
			t.Errorf("ORCH_RUNNER_NANO_CPUS=%q was accepted", bad)
		}
	}
}
