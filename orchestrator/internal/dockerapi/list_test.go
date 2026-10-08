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

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/labels"
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
	c, seen := startListEngine(t, `[]`)

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
	c, seen := startListEngine(t, `[]`)

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
	// The Engine's actual shape: a **bare array**. Checked against a live
	// `GET /containers/json?filters={"label":["msout.component=runner"]}` on the
	// deployed host, not read from a reference.
	//
	// This body was `{"Containers":[...]}` in the first version, because that is what
	// the code declared — so the test agreed with the code and the real mismatch only
	// appeared in production:
	//
	//     json: cannot unmarshal array into Go value of type dockerapi.listResponse
	//
	// The comment on the wrong declaration now says the same thing, because the
	// lesson is not "check the shape" but that a fixture invented from the code under
	// test cannot check the code under test.
	c, _ := startListEngine(t, `[{"Id":"a"},{"Id":"b"}]`)

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

// TestTheFilterIsNotDoubleEncoded is the collision this file's sibling commit fixed.
//
// `labels.RunnerFilter` was declared `"label=msout.role=runner"` — the Engine's own
// filter syntax — and this function encoded it again, producing
//
//	{"label":["label=msout.role=runner"]}
//
// which selects a label *named* `label`. Reconciliation then adopted nothing and
// removed nothing while reporting `boot reconciliation complete`, and the live count
// of orphaned runner containers **went up** after a restart.
//
// So the assertion is on the exact string the Engine receives for the value the pool
// actually passes, and a `label=` prefix in the input is the specific thing it refuses.
func TestTheFilterIsNotDoubleEncoded(t *testing.T) {
	// **`labels.RunnerFilter` itself, not a literal copy of it.**
	//
	// The first version of this test hardcoded `"msout.role=runner"` with a comment
	// saying it was the exact value `Pool.Reconcile` passes. It was not: it was a
	// copy, and it kept passing when the constant was reverted to the double-encoded
	// form. A test that pins one end of a two-ended agreement does not pin the
	// agreement — which is the bug it was written for.
	filter := labels.RunnerFilter

	c, seen := startListEngine(t, `[]`)
	if _, err := c.ListContainersByLabel(t.Context(), filter); err != nil {
		t.Fatalf("ListContainersByLabel: %v", err)
	}

	q, err := url.ParseQuery(stripPath(*seen))
	if err != nil {
		t.Fatalf("query did not parse: %v", err)
	}
	var decoded map[string][]string
	if err := json.Unmarshal([]byte(q.Get("filters")), &decoded); err != nil {
		t.Fatalf("filters is not JSON: %q", q.Get("filters"))
	}

	got, ok := decoded["label"]
	if !ok || len(got) != 1 {
		t.Fatalf(`decoded filters = %v, want one "label" entry`, decoded)
	}
	if got[0] != filter {
		t.Errorf("filters[\"label\"] = %q, want %q", got[0], filter)
	}
	// Named explicitly, because this is the whole bug and it is invisible: a leading
	// `label=` is *valid JSON in the right place*, just a filter for a different label.
	if strings.HasPrefix(got[0], "label=") {
		t.Errorf("the filter is double-encoded: %q selects a label named `label`. "+
			"Reconciliation would find nothing and report success", got[0])
	}
}
