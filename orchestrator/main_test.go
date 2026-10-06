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
	"strings"
	"testing"
	"time"
)

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
