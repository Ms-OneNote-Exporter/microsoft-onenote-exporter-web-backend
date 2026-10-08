package dockerapi

// The `filters` parameter is JSON, and getting it wrong fails silently.
//
// ## Why this file exists
//
// Every boot of the orchestrator logged:
//
//     reconcile: list containers: docker engine: 400 {"message":"invalid filter"}
//
// The caller logs that as "boot reconciliation failed, serving anyway" and continues,
// which is the right resilience and the wrong place for a permanent bug. So
// reconciliation had **never run**: an orchestrator restart did not adopt its existing
// runners, and `EnsurePool` would create a second runner for a slot whose container
// was still alive and holding a session's vault.
//
// The cause: `filters=msout.component%3Drunner`. The Engine's schema for `filters`
// is an object of arrays — `{"label":["msout.component=runner"]}` — and a bare value
// is rejected outright.
//
// Nothing caught it because every existing test used the `Daemon` interface with a
// fake, so the query string was never built. These tests read the **request**, which
// is the same lesson as the mount tests: an assertion about the call rather than
// about what arrived.

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startListEngine returns a client whose Engine records the request line.
func startListEngine(t *testing.T, body string) (*Client, *string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "engine.sock")
	var seen string

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			w.WriteHeader(http.StatusOK)
			return
		}
		seen = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = os.Remove(sock) })

	return New(sock, 5*time.Second), &seen
}

// The whole bug: the filter must be a JSON object of arrays.
func TestTheLabelFilterIsSentAsJSON(t *testing.T) {
	c, seen := startListEngine(t, `{"Containers":[]}`)

	if _, err := c.ListContainersByLabel(t.Context(), "msout.component=runner"); err != nil {
		t.Fatalf("ListContainersByLabel: %v", err)
	}

	// Decode the query rather than string-matching the URI, so the assertion is
	// about the *value* the Engine parses and not about the escaping this
	// implementation happens to use.
	q, err := url.ParseQuery(stripPath(*seen))
	if err != nil {
		t.Fatalf("query did not parse: %v\n%s", err, *seen)
	}

	var filter map[string][]string
	if err := json.Unmarshal([]byte(q.Get("filters")), &filter); err != nil {
		t.Fatalf("filters is not JSON — the Engine rejects it with 400 invalid "+
			"\"invalid filter\", which is exactly what happened on every boot:\n%q",
			q.Get("filters"))
	}

	want := "msout.component=runner"
	if got := filter["label"]; len(got) != 1 || got[0] != want {
		t.Errorf(`filters["label"] = %v, want [%q]`, got, want)
	}
}

// `all=1` is what makes a stopped container visible, and boot reconciliation needs
// those: a runner that died must be cleaned up, not just the running ones.
func TestStoppedContainersAreIncluded(t *testing.T) {
	c, seen := startListEngine(t, `{"Containers":[]}`)

	if _, err := c.ListContainersByLabel(t.Context(), "x=y"); err != nil {
		t.Fatalf("ListContainersByLabel: %v", err)
	}

	q, err := url.ParseQuery(stripPath(*seen))
	if err != nil {
		t.Fatalf("query did not parse: %v", err)
	}
	if q.Get("all") != "1" {
		t.Errorf("all = %q, want 1; without it a runner that died is invisible and "+
			"reconciliation adopts it as a live container", q.Get("all"))
	}
}

func TestAListOfIdsIsReturned(t *testing.T) {
	// The Engine's shape, not a bare array — a test body that does not match the
	// response struct fails for a reason unrelated to the bug under test, which is
	// how a real failure gets written off as a broken test.
	c, _ := startListEngine(t, `{"Containers":[{"Id":"a"},{"Id":"b"}]}`)

	ids, err := c.ListContainersByLabel(t.Context(), "x=y")
	if err != nil {
		t.Fatalf("ListContainersByLabel: %v", err)
	}
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Errorf("ids = %v, want [a b]", ids)
	}
}

// stripPath returns just the query string, so the assertions can hand it to
// url.ParseQuery instead of matching against the URI this implementation happens
// to build.
func stripPath(uri string) string {
	_, query, _ := strings.Cut(uri, "?")
	return query
}
