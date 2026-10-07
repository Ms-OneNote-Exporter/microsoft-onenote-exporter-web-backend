package dockerapi

// The create request's mounts must reach the wire.
//
// ## Why this file exists
//
// Found on the first real deployment that created a runner. The container came up
// with **no mounts at all** — `HostConfig.Binds=[]`, no vault, no artifact tree, no
// bearer token — and the runner exited 1:
//
//     MSOUT_RUNNER_TOKEN_FILE could not be read at /run/secrets/runner_token: ENOENT
//
// The cause: `POST /containers/create` **ignores a top-level `Mounts` field.** The
// Engine reads `HostConfig.Binds`. The request struct had `Mounts []CreateMount`
// serialised as `"Mounts"`, so it was marshalled, sent, and discarded.
//
// ## Why nothing caught it
//
// Every existing test asserted against the request **struct**, and the struct was
// correct. The typed field was populated; only the wire format was wrong. That is
// the same shape as the credential bugs in this project — an assertion about the
// handler rather than about what arrived — one layer down, in a JSON payload.
//
// So these tests marshal the request and read the bytes.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeEngine is a stub Docker Engine on a **real unix socket**.
//
// A real socket because the client is built to dial one — a test that pointed it
// at an `httptest` server would need a field the production code does not have,
// and the alternative (asserting on the marshalled struct) is what missed this bug
// in the first place. So the test goes through the same transport the orchestrator
// uses and reads the bytes that arrive.
type fakeEngine struct {
	mu   sync.Mutex
	body []byte
}

func (f *fakeEngine) seen() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.body
}

// start brings up the stub on a socket under the test's temp dir.
func start(t *testing.T) (*Client, *fakeEngine) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "engine.sock")
	engine := &fakeEngine{}

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		engine.mu.Lock()
		engine.body = raw
		engine.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"c1","Warnings":[]}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = os.Remove(sock) })

	return New(sock, 5*time.Second), engine
}

// bodyOf performs a create against the stub and returns the exact JSON the Engine
// would have received.
func bodyOf(t *testing.T, req CreateRequest) map[string]any {
	t.Helper()
	c, engine := start(t)
	if _, err := c.CreateContainer(context.Background(), req, "n"); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(engine.seen(), &out); err != nil {
		t.Fatalf("create body was not JSON: %v\n%s", err, engine.seen())
	}
	return out
}

// aRunnerCreate is the shape `buildCreateRequest` produces, reduced to the parts
// this test is about.
func aRunnerCreate() CreateRequest {
	ro := true
	return CreateRequest{
		Image: "runner:test",
		HostConfig: CreateHostConfig{
			NetworkMode:    "msout-runner",
			ReadonlyRootfs: &ro,
		},
		Mounts: []CreateMount{
			{Type: "bind", Source: "/srv/msout/vault/guid", Destination: "/data", ReadOnly: false},
			{Type: "bind", Source: "/srv/msout/artifacts", Destination: "/artifacts", ReadOnly: false},
			{Type: "bind", Source: "/srv/msout/secrets/runner_token", Destination: "/run/secrets/runner_token", ReadOnly: true},
		},
	}
}

func TestMountsReachTheEngineAsHostConfigBinds(t *testing.T) {
	body := bodyOf(t, aRunnerCreate())

	host, ok := body["HostConfig"].(map[string]any)
	if !ok {
		t.Fatalf("no HostConfig in the create body: %v", body)
	}
	binds, ok := host["Binds"].([]any)
	if !ok {
		t.Fatalf("HostConfig.Binds is %T, not a list — the Engine will mount nothing: %v",
			host["Binds"], host)
	}
	if len(binds) != 3 {
		t.Fatalf("got %d binds, want 3: %v", len(binds), binds)
	}

	want := []string{
		"/srv/msout/vault/guid:/data",
		"/srv/msout/artifacts:/artifacts",
		"/srv/msout/secrets/runner_token:/run/secrets/runner_token:ro",
	}
	for i, spec := range want {
		if got, _ := binds[i].(string); got != spec {
			t.Errorf("bind %d = %q, want %q", i, got, spec)
		}
	}
}

// The old field must not be on the wire at all.
//
// It is not merely redundant: an Engine that honoured it would take the mount list
// from the wrong place, and one that ignores it is the Engine we actually run. The
// assertion pins the request to what the Engine reads, so the two cannot diverge
// again by accident.
func TestTheTopLevelMountsFieldIsNotSent(t *testing.T) {
	body := bodyOf(t, aRunnerCreate())
	if _, present := body["Mounts"]; present {
		t.Errorf("the create body carries a top-level `Mounts`, which the Engine ignores: %v",
			body["Mounts"])
	}
}

// Read-only has to survive the conversion to a bind string, because it is what
// stops a runner writing the token it authenticates with.
func TestReadOnlySurvives(t *testing.T) {
	body := bodyOf(t, aRunnerCreate())
	host := body["HostConfig"].(map[string]any)
	binds := host["Binds"].([]any)

	var token string
	for _, b := range binds {
		if s, _ := b.(string); strings.Contains(s, "/run/secrets/runner_token") {
			token = s
		}
	}
	if !strings.HasSuffix(token, ":ro") {
		t.Errorf("the token bind is %q; a writable mount of the bearer token would let a "+
			"runner replace its own credential", token)
	}
}

func TestAMountWithNoDestinationIsRefusedRatherThanRendered(t *testing.T) {
	// Rendering it would produce `source:` — a specification the Engine parses as
	// something else entirely, silently.
	req := aRunnerCreate()
	req.Mounts = []CreateMount{{Type: "bind", Source: "/srv/msout/artifacts"}}

	c, _ := start(t)
	if _, err := c.CreateContainer(context.Background(), req, "n"); err == nil {
		t.Error("a mount with no destination was accepted")
	}
}

// An empty mount list must produce no `Binds` key rather than `null`, because
// `null` is a different value to the Engine than an absent one.
func TestNoMountsMeansNoBinds(t *testing.T) {
	req := aRunnerCreate()
	req.Mounts = nil

	body := bodyOf(t, req)
	host := body["HostConfig"].(map[string]any)
	if host["Binds"] != nil {
		t.Errorf("Binds = %v, want absent", host["Binds"])
	}
}
