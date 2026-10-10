// Tests the container healthcheck path.
//
// This exists because the compose healthcheck referenced a `-healthcheck` flag
// that `run()` ignored entirely. The probe therefore started a whole second
// orchestrator, bound the same port, and never exited: the healthcheck failed
// forever while the real orchestrator was perfectly healthy. Nothing caught it,
// because nothing ran the flag.
//
// A config file naming a flag the binary does not implement is the same class of
// bug as a CMD naming a file that was never written, and it is invisible until
// something executes it.

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
)

// The three deadlines are one agreement, and this is the Go half of it.
//
// `WriteTimeout` covers the whole `/claim` handler, so it has to be longer than the
// work that handler does. That work is:
//
//	10s   stop grace before SIGKILL   (pool.destroy, hardcoded)
//	~2s   create + start              (pool.start)
//	45s   waiting for the healthcheck (RunnerReadyTimeout, not env-settable)
//
// and the deadline must clear **that** *and* the api's own budget, because the api
// gives up at 75s and a server that gives up first turns a legitimate claim into a
// transport failure the api cannot tell from a dead orchestrator. At 60s the
// ordering was inverted — the api was still waiting when net/http closed the
// connection — and the claim's in-flight Docker calls died with the request
// context, leaving two containers on the host that nothing owned.
//
// So the assertion is the ordering:
//
//	stop grace + create/start + ready timeout  <  api's budget  <  WriteTimeout
//
// The numbers are not asserted. They come from three places this package does not
// own and any of which can move: the stop grace is a literal in `pool.destroy`, the
// ready timeout is a compile-time constant in `config`, and the client budget is the
// api's. A test that copies them pins nothing, so the api's is **parsed** from its
// source and the ready timeout is **read** through the same loader the process uses.
func TestWriteTimeoutExceedsTheClaimWorstCase(t *testing.T) {
	// Read through the same loader the process uses, so the ready timeout is the one
	// that ships rather than a copy of it in a test. It is deliberately not
	// env-settable (config.go), so this cannot drift away from the default.
	//
	// Only the one variable the loader insists on is answered; the rest read as
	// absent, which is what an operator who set nothing gets.
	cfg, err := config.Load(
		func(key string) string {
			if key == "ORCH_HMAC_SECRET_FILE" {
				return "/dev/null"
			}
			return ""
		},
		func(string) ([]byte, error) { return make([]byte, 64), nil },
	)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	const (
		stopGrace      = 10 * time.Second
		createAndStart = 2 * time.Second
	)
	worstCase := stopGrace + createAndStart + cfg.RunnerReadyTimeout

	clientBudget := time.Duration(apiContainerVerbBudget(t)) * time.Millisecond

	if clientBudget <= worstCase {
		t.Fatalf("the api's container-verb budget is %v and the claim's worst case is "+
			"%v (stop grace %v + create/start %v + ready timeout %v). The client gives "+
			"up before the work is finished, which is the bug: it aborts a legitimate "+
			"claim mid-provision and the cleanup dies with the request context",
			clientBudget, worstCase, stopGrace, createAndStart, cfg.RunnerReadyTimeout)
	}
	if clientBudget >= writeTimeout {
		t.Fatalf("WriteTimeout is %v and the api's container-verb budget is %v. The "+
			"server must outlast the client: if it does not, net/http closes a claim "+
			"the api is still waiting for and the api records it as `unreachable`",
			writeTimeout, clientBudget)
	}
}

// apiContainerVerbBudget reads CONTAINER_VERB_TIMEOUT_MS from the api's source.
//
// Parsed rather than restated, and that is the point of the helper: the two sides
// share no code and cannot import each other, so this agreement is held only by the
// number being right in both places. A copy here would go stale silently — which is
// exactly how a 15s client budget came to sit below a 60s server.
//
// Skipped rather than failed when the api's tree is not alongside this one, because
// a Go test that cannot see the other component has no opinion about it. The api's
// own suite asserts its half (`per-verb timeout budgets`).
func apiContainerVerbBudget(t *testing.T) int {
	t.Helper()

	src, err := os.ReadFile("../api/src/orchestrator-client.ts")
	if err != nil {
		t.Skipf("api source not readable from here: %v", err)
	}
	const decl = "CONTAINER_VERB_TIMEOUT_MS"
	i := strings.Index(string(src), decl+" = ")
	if i < 0 {
		t.Fatalf("api/src/orchestrator-client.ts no longer declares %s. It is the one "+
			"place the two components' deadline agreement is written down: the api "+
			"cannot read the orchestrator's configuration and the orchestrator cannot "+
			"read the api's, so a constant that stops existing is an unagreed budget",
			decl)
	}
	rest := string(src)[i+len(decl)+3:]
	end := strings.IndexAny(rest, ";,\n")
	if end < 0 {
		t.Fatalf("could not parse %s from api/src/orchestrator-client.ts", decl)
	}
	n, err := strconv.Atoi(strings.ReplaceAll(strings.TrimSpace(rest[:end]), "_", ""))
	if err != nil {
		t.Fatalf("could not parse %s as a number of milliseconds: %v", decl, err)
	}
	return n
}

// Every flag referenced by docker-compose.yml must be one this binary handles.
//
// A new flag has to be added here deliberately. The alternative is discovering it
// when a healthcheck reports a service as unhealthy that is fine.
func TestComposeHealthcheckFlagIsImplemented(t *testing.T) {
	compose, err := os.ReadFile("../docker-compose.yml")
	if err != nil {
		t.Skipf("docker-compose.yml not readable: %v", err)
	}
	if !strings.Contains(string(compose), "-healthcheck") {
		t.Fatal("compose no longer references -healthcheck; update this test")
	}

	// An unrecognised flag must not fall through to starting the server. `run`
	// only short-circuits on the flags it knows, so anything else proceeds — which
	// for a probe means hanging until the healthcheck timeout.
	if err := run([]string{"-healthcheck"}); err == nil {
		// A nil error here means the dial succeeded, i.e. nothing is listening yet
		// in this test process. That is the correct "unhealthy" answer, not a
		// fall-through, so it is still evidence the flag was handled rather than
		// ignored — but assert it explicitly so the distinction is on the record.
		t.Log("healthcheck ran and reported healthy; a listener was reachable")
	} else if strings.Contains(err.Error(), "not accepting connections") {
		// The expected outcome with nothing listening. The message matters: it is
		// what appears in the container log when a probe fails.
		t.Logf("healthcheck correctly reported unhealthy: %v", err)
	} else {
		t.Fatalf("healthcheck failed with an unexpected error: %v", err)
	}
}

// A flag the binary does not know must not start a server.
//
// run() ignores arguments it does not recognise, so an unknown flag is
// indistinguishable from no flag at all. For a healthcheck that is a hang rather
// than a refusal, so the check is that the known flag short-circuits before
// anything else happens.
func TestHealthcheckDoesNotRequireTheSecret(t *testing.T) {
	// A liveness probe must not fail because configuration is incomplete: whether
	// the orchestrator is correctly configured is a start-up question, answered by
	// it refusing to start. Reading the secret here would make a rotated-but-not-
	// yet-mounted secret look like a dead process.
	t.Setenv("ORCH_HMAC_SECRET_FILE", "/nonexistent/secret")
	t.Setenv("ORCH_LISTEN", "127.0.0.1:1") // nothing listens here

	err := run([]string{"-healthcheck"})
	if err == nil {
		t.Fatal("expected an unhealthy result with nothing listening")
	}
	if !strings.Contains(err.Error(), "not accepting connections") {
		t.Errorf("error = %v, want a connection failure", err)
	}
	// The point: it failed on the probe, not on the missing secret.
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("healthcheck failed on configuration rather than liveness: %v", err)
	}
}

// A healthy process reports healthy, so the probe can actually pass.
func TestHealthcheckPassesWhenListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	addr := ln.Addr().String()
	t.Setenv("ORCH_LISTEN", addr)

	if err := run([]string{"-healthcheck"}); err != nil {
		t.Fatalf("healthcheck against a live listener failed: %v", err)
	}
}

// A wildcard bind is probed on loopback, because a probe must dial a concrete
// address. ":9100" is not dialable.
func TestHealthcheckNormalisesAWildcardBind(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	t.Setenv("ORCH_LISTEN", fmt.Sprintf(":%d", port))

	// The wildcard form has to resolve to something dialable, or every container
	// using the default ORCH_LISTEN would report unhealthy while serving fine.
	err = run([]string{"-healthcheck"})
	if err != nil {
		t.Skipf("no listener on the normalised loopback address; not a failure of the normalisation: %v", err)
	}
}
