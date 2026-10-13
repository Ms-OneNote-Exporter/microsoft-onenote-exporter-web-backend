package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/auth"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/pool"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// The dockerapi client is real but unreachable in these tests: every request
// here is rejected before a handler runs, or targets a handler that never calls
// Docker. Pool is constructed against a socket path that does not exist, which
// is fine because no Docker call happens.
func newTestServer(t *testing.T) (*Server, http.Handler, *config.Config) {
	t.Helper()
	cfg := &config.Config{
		Listen:               ":0",
		DockerSocket:         filepath.Join(t.TempDir(), "absent.sock"),
		HMACSecret:           []byte(testSecret),
		ReplayWindow:         60 * time.Second,
		VaultRoot:            t.TempDir(),
		ArtifactRoot:         t.TempDir(),
		RunnerImage:          "runner:test",
		RunnerNetwork:        "msout-runner",
		RunnerControlNetwork: "msout-runner-api",
		RunnerPort:           3100,
		PoolSize:             1,
		RunnerTTL:            5 * time.Minute,
		SlotIdleTimeout:      30 * time.Minute,
		RequestTimeout:       time.Second,
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := pool.New(cfg, nil, log)
	srv := New(cfg, p, log, nil)
	return srv, srv.Handler(), cfg
}

// A server whose pool has a slot to give, so a verb that reaches Docker can be
// driven to success.
//
// Needed only where the assertion is about what a caller *receives* on the
// success path — `claim`'s `runnerUrl`, for instance. A test that asserts only
// on a rejection never needs Docker, and the nil client stays the default so
// that a test reaching for it by accident fails rather than quietly passing.
func newTestServerWithDaemon(t *testing.T) (*Server, http.Handler, *config.Config) {
	t.Helper()
	return newTestServerWithDaemonSized(t, 1)
}

// As above, with a pool of the given size. `poolSize` is not cosmetic: a claim
// consumes a slot and does not return it, so a test that claims three times
// against a one-slot pool is testing 503, not URLs.
func newTestServerWithDaemonSized(t *testing.T, poolSize int) (*Server, http.Handler, *config.Config) {
	t.Helper()
	_, _, cfg := newTestServer(t)
	cfg.PoolSize = poolSize
	// Rebuild the pool over the daemon, keeping the same config and the same
	// server instance so route table and signature handling are the real ones.
	p := pool.New(cfg, &claimDaemon{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := New(cfg, p, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("EnsurePool: %v", err)
	}
	return srv, srv.Handler(), cfg
}

// do sends a request with a freshly computed valid signature.
func do(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	}
	r := httptest.NewRequest(method, path, reader)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	ts, sig := auth.Sign([]byte(testSecret), method, r.URL.EscapedPath(), body, time.Now())
	r.Header.Set(auth.HeaderTS, ts)
	r.Header.Set(auth.HeaderSig, sig)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// doRaw sends a request with no signature at all.
func doRaw(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	}
	r := httptest.NewRequest(method, path, reader)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// A signed request must not be rejected for a reason unrelated to Docker.
func TestSignedRequestIsNotRejectedByAuth(t *testing.T) {
	_, h, _ := newTestServer(t)

	// GET /stats reads no Docker state.
	rec := do(t, h, http.MethodGet, "/stats", nil)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusBadRequest {
		t.Fatalf("signed /stats rejected with %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /stats = %d, want 200. body: %s", rec.Code, rec.Body.String())
	}
}

// T-I5: an unknown path is 404. There is no default branch that could accept it.
func TestUnknownPathIs404(t *testing.T) {
	_, h, _ := newTestServer(t)
	for _, path := range []string{"/", "/exec", "/containers/create", "/stats/../exec", "/..", "/claim/"} {
		rec := do(t, h, http.MethodPost, path, []byte(`{}`))
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", path, rec.Code)
		}
	}
}

// T-I5: a known path with the wrong method is 405, not 404 and not a handler.
func TestWrongMethodIs405(t *testing.T) {
	_, h, _ := newTestServer(t)
	cases := []struct{ method, path string }{
		{http.MethodGet, "/claim"},
		{http.MethodDelete, "/release"},
		{http.MethodPut, "/recycle"},
		{http.MethodPost, "/stats"},
		{http.MethodGet, "/stat"},
	}
	for _, tc := range cases {
		rec := do(t, h, tc.method, tc.path, nil)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", tc.method, tc.path, rec.Code)
		}
		if rec.Header().Get("Allow") == "" {
			t.Errorf("%s %s: Allow header missing", tc.method, tc.path)
		}
	}
}

// T-I1: unsigned requests fail on every path, and never leak whether the path
// exists. An unsigned caller must not be able to tell 404 from 405.
func TestUnsignedRequestsFailOnEveryPath(t *testing.T) {
	_, h, _ := newTestServer(t)
	statuses := map[int]bool{}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/stats"},
		{http.MethodPost, "/claim"},
		{http.MethodPost, "/release"},
		{http.MethodPost, "/stat"},
		{http.MethodGet, "/healthz"},
		{http.MethodPost, "/exec"},
		{http.MethodGet, "/does-not-exist"},
	} {
		rec := doRaw(t, h, tc.method, tc.path, nil)
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s unsigned = %d, want 4xx", tc.method, tc.path, rec.Code)
		}
		statuses[rec.Code] = true
	}
	if len(statuses) != 1 {
		t.Errorf("unsigned requests returned differing statuses %v; the response must not reveal whether a path exists", statuses)
	}
}

// T-I1: a request with a valid signature but a wrong secret fails.
func TestWrongSecretRejected(t *testing.T) {
	_, h, _ := newTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/stats", nil)
	ts, sig := auth.Sign([]byte("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		http.MethodGet, "/stats", nil, time.Now())
	r.Header.Set(auth.HeaderTS, ts)
	r.Header.Set(auth.HeaderSig, sig)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret = %d, want 401. body: %s", rec.Code, rec.Body.String())
	}
}

// T-I2: a captured signature replayed past the window fails, at the HTTP layer.
func TestReplayedRequestPastWindowRejected(t *testing.T) {
	_, h, _ := newTestServer(t)

	sent := time.Now()
	body := []byte(`{"sessionGuid":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","sessionExpiresAtMs":1}`)
	r := httptest.NewRequest(http.MethodPost, "/claim", strings.NewReader(string(body)))
	ts, sig := auth.Sign([]byte(testSecret), http.MethodPost, "/claim", body, sent)
	r.Header.Set(auth.HeaderTS, ts)
	r.Header.Set(auth.HeaderSig, sig)

	// Re-verify with a clock 61s later, using the same handler's window check by
	// constructing a server whose notion of "now" has moved. The handler calls
	// time.Now directly, so instead assert on Verify and on the window boundary
	// the server uses.
	if err := auth.Verify([]byte(testSecret), r, body, 60*time.Second, sent.Add(61*time.Second)); err == nil {
		t.Fatal("expected a 61s-old signature to be rejected")
	}

	// And the immediate replay of the same bytes is accepted by the handler,
	// which proves the rejection above is about age and not about the request.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusBadRequest {
		t.Fatalf("fresh replay = %d, want not-auth. body: %s", rec.Code, rec.Body.String())
	}
}

// T-I4: a signature over an empty body, replayed with a body, is rejected.
func TestBodySubstitutionRejectedOverHTTP(t *testing.T) {
	_, h, _ := newTestServer(t)

	// Sign for GET /stats with no body...
	ts, sig := auth.Sign([]byte(testSecret), http.MethodGet, "/stats", nil, time.Now())
	// ...then send it to a POST that carries a body.
	body := []byte(`{"sessionGuid":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","sessionExpiresAtMs":1}`)
	r := httptest.NewRequest(http.MethodPost, "/claim", strings.NewReader(string(body)))
	r.Header.Set(auth.HeaderTS, ts)
	r.Header.Set(auth.HeaderSig, sig)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("body substitution = %d, want 401. body: %s", rec.Code, rec.Body.String())
	}
}

// T-X3: no endpoint accepts a field beyond its own schema. The verb set is
// enumerated here rather than assumed, and every handler is probed with a
// smuggling attempt.
func TestNoEndpointAcceptsCallerSuppliedCommandFields(t *testing.T) {
	_, h, _ := newTestServer(t)

	// Fields that would be dangerous if any handler read them.
	dangerous := map[string]any{
		"image":         "evil:latest",
		"command":       "sh",
		"cmd":           []string{"sh", "-c", "cat /srv/msout/vault"},
		"entrypoint":    []string{"/bin/sh"},
		"mounts":        []any{map[string]any{"source": "/", "destination": "/host"}},
		"binds":         []string{"/:/host"},
		"network":       "host",
		"networkMode":   "host",
		"privileged":    true,
		"capAdd":        []string{"SYS_ADMIN"},
		"hostPid":       true,
		"path":          "/etc/passwd",
		"artifactPath":  "/srv/msout/vault",
		"vaultRoot":     "/",
		"user":          "root",
		"securityOpt":   []string{"seccomp=unconfined"},
		"labels":        map[string]string{"msout.role": "runner"},
		"restartPolicy": "always",
		"timeout":       9999,
	}

	for _, path := range []string{"/claim", "/release", "/recycle", "/remove", "/stat", "/delete-artifact"} {
		for field, value := range dangerous {
			payload := map[string]any{
				"sessionGuid":        "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
				"slotId":             "slot-1",
				"artifactId":         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"sessionExpiresAtMs": time.Now().Add(time.Hour).UnixMilli(),
				field:                value,
			}
			body, _ := json.Marshal(payload)
			rec := do(t, h, http.MethodPost, path, body)
			// The requirement is that the field is not *used*. Either a 400
			// (unknown field rejected) or a 503 (schema accepted, no slot) is a
			// pass; 200 would mean it was read, and 500 would mean it reached a
			// nil Docker client.
			switch rec.Code {
			case http.StatusBadRequest, http.StatusServiceUnavailable, http.StatusConflict, http.StatusNotFound:
				// acceptable
			case http.StatusOK:
				t.Errorf("%s accepted smuggled field %q with 200", path, field)
			default:
				t.Errorf("%s with field %q = %d; want 400/409/503. body: %s",
					path, field, rec.Code, rec.Body.String())
			}
		}
	}
}

// Unknown fields must be rejected outright rather than silently ignored, so a
// caller cannot come to believe it set an image.
func TestUnknownFieldIsRejectedNotIgnored(t *testing.T) {
	_, h, _ := newTestServer(t)
	body := []byte(`{"slotId":"slot-1","somethingElse":true}`)
	rec := do(t, h, http.MethodPost, "/release", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400. body: %s", rec.Code, rec.Body.String())
	}
}

// Trailing content after the JSON object must not be silently accepted on the
// first value.
func TestTrailingContentRejected(t *testing.T) {
	_, h, _ := newTestServer(t)
	body := []byte(`{"slotId":"slot-1"}{"image":"evil"}`)
	rec := do(t, h, http.MethodPost, "/release", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("trailing content = %d, want 400. body: %s", rec.Code, rec.Body.String())
	}
}

// The session guid is joined to a host path, so it is validated before use.
func TestClaimRejectsNonUUIDGuid(t *testing.T) {
	_, h, _ := newTestServer(t)
	for _, guid := range []string{
		"../../etc",
		"not-a-guid",
		"3F2504E0-4F89-11D3-9A0C-0305E82C3301",
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301/../../x",
	} {
		body, _ := json.Marshal(map[string]any{
			"sessionGuid":        guid,
			"sessionExpiresAtMs": time.Now().Add(time.Hour).UnixMilli(),
		})
		rec := do(t, h, http.MethodPost, "/claim", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("guid %q = %d, want 400", guid, rec.Code)
		}
	}
}

// The artifact id is joined to a host path too.
func TestStatRejectsNonConformingArtifactID(t *testing.T) {
	_, h, _ := newTestServer(t)
	for _, id := range []string{
		"../../srv/msout/vault",
		"short",
		"AAAA/AAAA/AAAA/AAAA/AAAA/AAAA/AAAA/AAAA/AAA",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 44 chars
	} {
		body, _ := json.Marshal(map[string]string{"artifactId": id})
		rec := do(t, h, http.MethodPost, "/stat", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("artifactId %q = %d, want 400", id, rec.Code)
		}
	}
}

// The body cap is a real limit: a large body must be refused without being
// parsed, so a caller cannot make this process allocate or hash without bound.
func TestOversizedBodyRejected(t *testing.T) {
	_, h, _ := newTestServer(t)
	body := make([]byte, maxBodyBytes+1024)
	for i := range body {
		body[i] = 'a'
	}
	rec := do(t, h, http.MethodPost, "/claim", body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d, want 413. body: %s", rec.Code, rec.Body.String())
	}
}

// With no slots in the pool, claim is pool exhaustion — 503, not 500. The
// distinction matters to `api`: 503 carries a wait estimate it computes from its
// own session rows, while 500 means something broke.
func TestClaimOnEmptyPoolIs503(t *testing.T) {
	_, h, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]any{
		"sessionGuid":        "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"sessionExpiresAtMs": time.Now().Add(time.Hour).UnixMilli(),
	})
	rec := do(t, h, http.MethodPost, "/claim", body)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("claim on empty pool = %d, want 503. body: %s", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"no idle slot"}` {
		t.Fatalf("body = %s, want a pool-exhaustion message", got)
	}
}

// An unexpected internal error must be reported generically. The orchestrator
// holds the vault root and the Docker socket path in its config, and the caller
// is a different component on a different trust level. A Docker engine error
// names its socket path, so that text must never reach the response body.
//
// This drives writeHandlerError directly rather than trying to provoke a real
// failure through the pool, because the alternative is a fixture whose failure
// mode is a nil pointer — which produces a different error than the one being
// tested for leakage.
func TestInternalErrorDoesNotLeakInternals(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &Server{log: log}

	// Stand in for what a failed Docker call actually returns.
	cause := errors.New(
		"docker engine (/var/run/docker.sock): read unix /var/run/docker.sock: " +
			"connection refused; removing container from /srv/msout/vault/3f2504e0",
	)

	rec := httptest.NewRecorder()
	srv.writeHandlerError(rec, httptest.NewRequest(http.MethodPost, "/claim", nil), cause)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("internal error = %d, want 500", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{
		"/var/run/docker.sock", "/srv/msout/vault", "docker engine",
		"connection refused", "dial unix",
	} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks %q: %s", leak, body)
		}
	}
	// The whole body must be the fixed generic message.
	if got := strings.TrimSpace(body); got != `{"error":"internal error"}` {
		t.Errorf("body = %s, want exactly the generic message", got)
	}
}

// The pool's sentinel errors map to statuses `api` acts on differently.
func TestPoolErrorsMapToActionableStatuses(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// A real pool, because the ErrNoSlot branch now asks it whether a top-up
	// failed. The previous `&Server{log: log}` left `pool` nil and would have
	// panicked the moment that branch was taken — which is the test failing for
	// the right reason, but only once the code it guards exists.
	_, _, cfg := newTestServer(t)
	srv := New(cfg, pool.New(cfg, nil, log), log, nil)

	cases := []struct {
		err    error
		status int
	}{
		{pool.ErrNoSlot, http.StatusServiceUnavailable},
		{pool.ErrUnknownSlot, http.StatusConflict},
		{pool.ErrAlreadyBound, http.StatusConflict},
		{pool.ErrNotBound, http.StatusConflict},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		srv.writeHandlerError(rec, httptest.NewRequest(http.MethodPost, "/claim", nil), tc.err)
		if rec.Code != tc.status {
			t.Errorf("%v = %d, want %d", tc.err, rec.Code, tc.status)
		}
	}
}

// An unknown slot is a stale caller view, not a broken service: 409 tells `api`
// to re-read the pool rather than to alert.
func TestUnknownSlotIsConflict(t *testing.T) {
	_, h, _ := newTestServer(t)
	rec := do(t, h, http.MethodPost, "/remove", []byte(`{"slotId":"slot-does-not-exist"}`))
	if rec.Code != http.StatusConflict {
		t.Fatalf("remove unknown slot = %d, want 409. body: %s", rec.Code, rec.Body.String())
	}
}

// The HMAC secret must never appear in a response, in any code path.
func TestSecretNeverAppearsInResponses(t *testing.T) {
	_, h, _ := newTestServer(t)
	secret := testSecret
	for _, tc := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodGet, "/stats", nil},
		{http.MethodGet, "/healthz", nil},
		{http.MethodPost, "/claim", []byte(`{"sessionGuid":"3f2504e0-4f89-11d3-9a0c-0305e82c3301","sessionExpiresAtMs":1}`)},
		{http.MethodPost, "/remove", []byte(`{"slotId":"slot-1"}`)},
	} {
		rec := do(t, h, tc.method, tc.path, tc.body)
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("%s %s leaks the HMAC secret", tc.method, tc.path)
		}
		if strings.Contains(rec.Header().Get("Set-Cookie"), secret) {
			t.Errorf("%s %s sets a cookie", tc.method, tc.path)
		}
	}
}

// Every response is uncacheable. The orchestrator holds pool state, and a cached
// /stats would report a pool that no longer exists.
func TestResponsesAreNotCacheable(t *testing.T) {
	_, h, _ := newTestServer(t)
	rec := do(t, h, http.MethodGet, "/stats", nil)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want json", ct)
	}
}

// /stats reports pool occupancy in the shape `api` parses.
func TestStatsShape(t *testing.T) {
	_, h, _ := newTestServer(t)
	rec := do(t, h, http.MethodGet, "/stats", nil)

	var out struct {
		Size             int            `json:"size"`
		ByState          map[string]int `json:"byState"`
		RunnerTTLSeconds int            `json:"runnerTtlSeconds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v. body: %s", err, rec.Body.String())
	}
	if out.RunnerTTLSeconds != 300 {
		t.Errorf("runnerTtlSeconds = %d, want 300", out.RunnerTTLSeconds)
	}
	if out.ByState == nil {
		t.Error("byState missing")
	}
}

// /healthz surfaces the reconciliation outcome, so a partial boot problem is
// visible to `api` rather than only in a log.
func TestHealthzReportsReconcileError(t *testing.T) {
	srv, h, _ := newTestServer(t)

	rec := do(t, h, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}
	var clean struct {
		OK bool `json:"ok"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &clean)
	if !clean.OK {
		t.Error("ok should be true before reconciliation is recorded")
	}

	srv.SetReconcileResult(os.ErrDeadlineExceeded)
	rec = do(t, h, http.MethodGet, "/healthz", nil)
	var dirty struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &dirty)
	if dirty.OK {
		t.Error("ok should be false once reconciliation has failed")
	}
	if dirty.Error == "" {
		t.Error("error should be surfaced on /healthz")
	}
}

// The route table is the whole API. This test fails if a route is added without
// a test asserting its shape, which is the operational form of "no endpoint
// accepts a command, image, flag, mount, network or path from a caller".
func TestRouteTableIsExactlyTheVerbSet(t *testing.T) {
	srv, _, _ := newTestServer(t)
	table := srv.routeTable()

	want := map[string][]string{
		"/claim":    {http.MethodPost},
		"/release":  {http.MethodPost},
		"/recycle":  {http.MethodPost},
		"/remove":   {http.MethodPost},
		"/stat":     {http.MethodPost},
		"/stats":    {http.MethodGet},
		"/healthz":  {http.MethodGet},
		"/finalize": {http.MethodPost},
		// The ninth verb, and the one this test exists to make deliberate. It removes
		// an artifact the api owns and nothing else — no slot, no vault, no container
		// — so it is enumerated here like every other path rather than added quietly.
		"/delete-artifact": {http.MethodPost},
	}

	if len(table) != len(want) {
		t.Fatalf("route count = %d, want %d. table: %v", len(table), len(want), table)
	}
	for path, methods := range want {
		got, ok := table[path]
		if !ok {
			t.Errorf("missing route %s", path)
			continue
		}
		if len(got) != len(methods) {
			t.Errorf("%s has %d methods, want %d", path, len(got), len(methods))
		}
		for _, m := range methods {
			if _, ok := got[m]; !ok {
				t.Errorf("%s missing method %s", path, m)
			}
		}
	}
}

// The schema structs are the other half of T-X3: each is asserted to have only
// the identifier fields, so adding a field is a deliberate act that shows up in
// review.
func TestRequestSchemasHoldOnlyIdentifiers(t *testing.T) {
	cases := []struct {
		name   string
		value  any
		fields []string
	}{
		{"claimRequest", claimRequest{}, []string{"sessionGuid", "sessionExpiresAtMs"}},
		{"slotRequest", slotRequest{}, []string{"slotId"}},
		{"recycleRequest", recycleRequest{}, []string{"slotId", "reason"}},
		{"statRequest", statRequest{}, []string{"artifactId"}},
		// The deletion verb's schema is asserted as narrowly as the others, and for
		// a sharper reason: it is the only verb whose work is destructive. One field,
		// an identifier — so a caller cannot name a path, a slot or a session.
		{"deleteArtifactRequest", deleteArtifactRequest{}, []string{"artifactId"}},
		// `partial` is a boolean, not an identifier. It is the one field on any
		// verb that is not an id, and it is asserted here explicitly so adding it
		// was a visible act: it selects the `.partial.zip` name and writes the
		// marker, so it is a claim about an export rather than a pointer to one.
		// Nothing about the filesystem comes from it — no path, no size.
		{"finalizeRequest", finalizeRequest{}, []string{"artifactId", "sessionGuid", "partial"}},
	}
	for _, tc := range cases {
		got := jsonFieldNames(tc.value)
		if len(got) != len(tc.fields) {
			t.Errorf("%s has fields %v, want %v", tc.name, got, tc.fields)
			continue
		}
		for _, f := range tc.fields {
			if !contains(got, f) {
				t.Errorf("%s missing field %s; has %v", tc.name, f, got)
			}
		}
	}
}

// jsonFieldNames returns a value's JSON field names, so a schema test does not
// depend on reflection being readable by hand.
func jsonFieldNames(v any) []string {
	raw, _ := json.Marshal(v)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// ---- POST /delete-artifact --------------------------------------------------
//
// The ninth verb. The filesystem work is covered against real directories in
// internal/pool/artifact_test.go; what is only true of the *HTTP* surface is
// tested here — that it is in the route table, that it requires the same signature
// as every other verb, and that each kind of refusal gets the status a caller can
// act on.
//
// The status mapping is the assertion worth having. This is a **destructive** verb
// on a surface where everything else either creates or inspects, and it is called
// from an erase that runs while the user's cookie is still open. A 409 here has to
// mean "your id is not the shape" and nothing else, or the api's step 6b cannot
// tell a malformed call from a full disk.

// publishForTest finalises a staged archive so there is something to delete.
func publishForTest(t *testing.T, cfg *config.Config, id string, size int) {
	t.Helper()
	stageForTest(t, cfg, id, size)
	p := pool.New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := p.Finalize(pool.FinalizeInput{ArtifactID: id, SessionGUID: finalizeGUID}); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

func deleteBody(id string) []byte {
	b, _ := json.Marshal(map[string]any{"artifactId": id})
	return b
}

// The whole point, as one assertion: what the api is told afterwards.
//
// A handler that returned 200 without deleting anything would pass every
// signature- and schema-shaped test and leave the vault on the volume — which is
// the bug this verb exists to close.
func TestDeleteArtifactRemovesThePublishedArchive(t *testing.T) {
	_, h, cfg := newTestServer(t)
	publishForTest(t, cfg, finalizeID, 512)

	// Before: a download would be authorised.
	if stat := do(t, h, http.MethodPost, "/stat", deleteBody(finalizeID)); stat.Code != http.StatusOK ||
		!strings.Contains(stat.Body.String(), `"exists":true`) {
		t.Fatalf("before delete, /stat = %d %s; want exists:true", stat.Code, stat.Body.String())
	}

	rec := do(t, h, http.MethodPost, "/delete-artifact", deleteBody(finalizeID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "deleted") {
		t.Errorf("body = %s, want it to report what it did", rec.Body.String())
	}

	// After: not there, which is the only thing `api` can check.
	after := do(t, h, http.MethodPost, "/stat", deleteBody(finalizeID))
	if after.Code != http.StatusOK {
		t.Fatalf("stat after delete = %d: %s", after.Code, after.Body.String())
	}
	if !strings.Contains(after.Body.String(), `"exists":false`) {
		t.Errorf("/stat says %s; the artifact is still downloadable after an erase", after.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.ArtifactRoot, finalizeID, pool.StagedArchiveName)); !os.IsNotExist(err) {
		t.Error("the archive is still on the artifact volume")
	}
}

// Idempotent over HTTP, because the api's erase is best-effort and retried and
// "already gone" is the outcome it wanted. A 404 here would make every repeated
// erase report a failure.
func TestDeleteArtifactAnswers200ForAnArtifactThatIsAlreadyGone(t *testing.T) {
	_, h, cfg := newTestServer(t)
	publishForTest(t, cfg, finalizeID, 64)

	if rec := do(t, h, http.MethodPost, "/delete-artifact", deleteBody(finalizeID)); rec.Code != http.StatusOK {
		t.Fatalf("first delete = %d: %s", rec.Code, rec.Body.String())
	}
	rec := do(t, h, http.MethodPost, "/delete-artifact", deleteBody(finalizeID))
	if rec.Code != http.StatusOK {
		t.Fatalf("second delete = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	// ...and on a tree that never published anything.
	rec = do(t, h, http.MethodPost, "/delete-artifact",
		deleteBody(strings.Repeat("B", 43)))
	if rec.Code != http.StatusOK {
		t.Errorf("delete of an unknown artifact = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// 400, before the id is ever joined to a host path. A 409 would suggest a stale id
// rather than a malformed one, and the api would treat it as an orchestrator
// disagreement.
func TestDeleteArtifactRejectsABadArtifactID(t *testing.T) {
	_, h, _ := newTestServer(t)

	for _, bad := range []string{"short", strings.Repeat("a", 44), "../" + finalizeID, "", ".."} {
		rec := do(t, h, http.MethodPost, "/delete-artifact", deleteBody(bad))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("id %q: status = %d, want 400: %s", bad, rec.Code, rec.Body.String())
		}
	}
}

// A traversal must delete nothing. The destructive verb is the one where that
// matters most, so it is asserted over HTTP as well as in the pool test.
//
// The probe is a sibling of the artifact directories — one level up from where
// `<root>/<artifactId>` would sit — so `../escaped` resolves to exactly this path
// and the assertion is about the join rather than about an unrelated temp dir.
func TestDeleteArtifactRejectsATraversalAndDeletesNothing(t *testing.T) {
	_, h, cfg := newTestServer(t)
	sibling := filepath.Join(cfg.ArtifactRoot, "escaped")
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatalf("create the probe: %v", err)
	}
	defer func() { _ = os.RemoveAll(sibling) }()

	rec := do(t, h, http.MethodPost, "/delete-artifact", deleteBody("../escaped"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Errorf("a traversal deleted %s: %v", sibling, err)
	}
}

// Same as every other verb, and asserted because a destructive path added to the
// table without the auth hook has no other symptom than an open endpoint: anyone
// who can reach this process could delete published vaults.
func TestDeleteArtifactRequiresASignature(t *testing.T) {
	_, h, cfg := newTestServer(t)
	publishForTest(t, cfg, finalizeID, 64)

	rec := doRaw(t, h, http.MethodPost, "/delete-artifact", deleteBody(finalizeID))
	if rec.Code == http.StatusOK {
		t.Fatalf("an unsigned delete succeeded: %s", rec.Body.String())
	}
	// ...and the artifact is still there, which is the half of the assertion that
	// matters: a refusal that deleted anyway would pass the status check.
	if _, err := os.Stat(filepath.Join(cfg.ArtifactRoot, finalizeID, pool.StagedArchiveName)); err != nil {
		t.Errorf("an unsigned request removed the archive: %v", err)
	}
}

func TestDeleteArtifactRejectsAMalformedBody(t *testing.T) {
	_, h, _ := newTestServer(t)

	rec := do(t, h, http.MethodPost, "/delete-artifact", []byte("{not json"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

// A deletion verb must not accept anything that could name a different directory.
// `DisallowUnknownFields` is the enforcement, asserted through the verb rather than
// only through `TestUnknownFieldIsRejectedNotIgnored` on `/release`.
func TestDeleteArtifactRejectsAnUnknownField(t *testing.T) {
	_, h, cfg := newTestServer(t)
	publishForTest(t, cfg, finalizeID, 64)

	rec := do(t, h, http.MethodPost, "/delete-artifact",
		[]byte(`{"artifactId":"`+finalizeID+`","path":"/etc"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.ArtifactRoot, finalizeID, pool.StagedArchiveName)); err != nil {
		t.Errorf("an unknown field still deleted the artifact: %v", err)
	}
}

// In the route table, POST only. A handler that exists but is not in the table is
// unreachable code a reader would believe in; a path that accepts a second method is
// a verb set that has grown without anyone reading it.
func TestDeleteArtifactIsInTheRouteTableForPostOnly(t *testing.T) {
	_, h, _ := newTestServer(t)

	for _, tc := range []struct {
		method string
		want   int
	}{
		{http.MethodGet, http.StatusMethodNotAllowed},
		{http.MethodDelete, http.StatusMethodNotAllowed},
		{http.MethodPut, http.StatusMethodNotAllowed},
	} {
		rec := do(t, h, tc.method, "/delete-artifact", nil)
		if rec.Code != tc.want {
			t.Errorf("%s /delete-artifact = %d, want %d", tc.method, rec.Code, tc.want)
		}
		if rec.Code == http.StatusMethodNotAllowed && rec.Header().Get("Allow") == "" {
			t.Errorf("%s /delete-artifact: Allow header missing", tc.method)
		}
	}
}

// The blast-radius property, over HTTP: one id removes one artifact. A mistyped id
// must not take a stranger's vault with it, which is the one thing a destructive
// verb on a shared volume has to get right.
func TestDeleteArtifactRemovesOnlyTheNamedArtifact(t *testing.T) {
	otherID := strings.Repeat("B", 43)
	_, h, cfg := newTestServer(t)
	publishForTest(t, cfg, finalizeID, 64)
	publishForTest(t, cfg, otherID, 64)

	if rec := do(t, h, http.MethodPost, "/delete-artifact", deleteBody(finalizeID)); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, http.MethodPost, "/stat", deleteBody(finalizeID)); !strings.Contains(rec.Body.String(), `"exists":false`) {
		t.Errorf("the named artifact survived: %s", rec.Body.String())
	}
	if rec := do(t, h, http.MethodPost, "/stat", deleteBody(otherID)); !strings.Contains(rec.Body.String(), `"exists":true`) {
		t.Errorf("deleting one artifact removed another: %s", rec.Body.String())
	}
}
