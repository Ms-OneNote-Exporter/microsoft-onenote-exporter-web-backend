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

// An idle runner's mounts, the shape `buildCreateRequest` produces for a pool slot
// that has not yet been bound to a session.
func anIdleRunnerCreate() CreateRequest {
	req := aRunnerCreate()
	req.Mounts = []CreateMount{
		{Type: "tmpfs", Source: "", Destination: "/data"},
		{Type: "bind", Source: "/srv/msout/artifacts", Destination: "/artifacts"},
		{Type: "bind", Source: "/srv/msout/secrets/runner_token", Destination: "/run/secrets/runner_token", ReadOnly: true},
	}
	return req
}

// A tmpfs must reach the Engine as `HostConfig.Tmpfs`, not as a bind.
//
// Found on the same first real container creation, immediately after the Binds fix
// put mounts on the wire. A tmpfs has no host source, so rendering it produced:
//
//	500 {"message":"invalid volume specification: ':/data'"}
//
// The security reason it must still work: `/data` is tmpfs precisely so a *waiting*
// runner holds no credential-bearing host path. Refusing to mount it would mean
// creating runners with an empty `/data`, which is the opposite of the intent.
func TestTmpfsGoesToHostConfigTmpfsNotToBinds(t *testing.T) {
	body := bodyOf(t, anIdleRunnerCreate())
	host := body["HostConfig"].(map[string]any)

	tmpfs, ok := host["Tmpfs"].(map[string]any)
	if !ok {
		t.Fatalf("HostConfig.Tmpfs = %v; /data would be left unmounted, so a waiting "+
			"runner would hold a host path it must not hold", host["Tmpfs"])
	}
	if _, present := tmpfs["/data"]; !present {
		t.Errorf("Tmpfs = %v, want a /data entry", tmpfs)
	}

	binds, _ := host["Binds"].([]any)
	for _, b := range binds {
		if s, _ := b.(string); strings.HasPrefix(s, ":") {
			t.Errorf("bind %q has an empty source; the Engine rejects it outright with "+
				"`invalid volume specification`, so the runner never starts", s)
		}
	}
	if len(binds) != 2 {
		t.Errorf("got %d binds, want 2 (the tmpfs must not be among them): %v", len(binds), binds)
	}
}

// A tmpfs mount's own options string is the tmpfs option, not a source path. An
// empty one still has to produce a valid tmpfs rather than an empty string the
// Engine rejects.
func TestTmpfsOptionsDefaultToWritable(t *testing.T) {
	body := bodyOf(t, anIdleRunnerCreate())
	host := body["HostConfig"].(map[string]any)
	opts, _ := host["Tmpfs"].(map[string]any)["/data"].(string)
	if opts == "" {
		t.Errorf("/data tmpfs options are empty; the Engine rejects an empty " +
			"tmpfs options string")
	}
}

// A tmpfs with explicit options must keep them — a size limit is a control, and
// silently dropping it in favour of Docker's default would be a real weakening.
func TestTmpfsOptionsSurvive(t *testing.T) {
	req := anIdleRunnerCreate()
	req.Mounts[0].Source = "rw,size=64m"

	body := bodyOf(t, req)
	host := body["HostConfig"].(map[string]any)
	opts, _ := host["Tmpfs"].(map[string]any)["/data"].(string)
	if opts != "rw,size=64m" {
		t.Errorf("/data tmpfs options = %q, want %q — a size limit is a control and "+
			"must not be replaced by the default", opts, "rw,size=64m")
	}
}

// A bind with no source is a misconfiguration, and must be refused by name rather
// than rendered into `":/data"` for the Engine to reject opaquely.
func TestABindWithNoSourceIsRefusedByName(t *testing.T) {
	req := anIdleRunnerCreate()
	req.Mounts[0] = CreateMount{Type: "bind", Source: "", Destination: "/data"}

	c, _ := start(t)
	_, err := c.CreateContainer(context.Background(), req, "n")
	if err == nil {
		t.Fatal("a bind mount with no source was accepted")
	}
	if !strings.Contains(err.Error(), `bind mount "/data" has no source`) {
		t.Errorf("error %q does not name the mount; a caller cannot fix an opaque "+
			"Engine rejection", err)
	}
}

// A request with only bind mounts carries no `Tmpfs` key, so nothing depends on the
// Engine treating an empty object and an absent one the same.
func TestNoTmpfsMeansNoTmpfsKey(t *testing.T) {
	body := bodyOf(t, aRunnerCreate())
	host := body["HostConfig"].(map[string]any)
	if host["Tmpfs"] != nil {
		t.Errorf("Tmpfs = %v, want absent", host["Tmpfs"])
	}
}
