package server

// The finalize verb.
//
// The library it calls is tested against the filesystem in
// internal/pool/artifact_test.go. What is tested here is the part that is only
// true of the *HTTP* surface: the status each failure produces, and the fact that
// the verb requires the same signature as every other one.
//
// The status mapping is the assertion worth having. `writeHandlerError` has a
// branch per sentinel error, and a new verb that returns a bare error gets a
// generic 500 — which for "nothing was staged" tells an operator to go looking at
// a disk that is fine.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/pool"
)

const (
	finalizeGUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	finalizeID   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 base64url
)

func finalizeBody(id string, guid string, partial bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"artifactId":  id,
		"sessionGuid": guid,
		"partial":     partial,
	})
	return b
}

// stageForTest writes a vault.zip into the artifact staging tree.
func stageForTest(t *testing.T, cfg *config.Config, id string, size int) {
	t.Helper()
	dir := filepath.Join(cfg.ArtifactRoot, pool.StagingDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, pool.StagedArchiveName), make([]byte, size), 0o600); err != nil {
		t.Fatalf("stage: %v", err)
	}
}

func TestFinalizePublishesAndReportsWhatItDid(t *testing.T) {
	_, h, cfg := newTestServer(t)
	stageForTest(t, cfg, finalizeID, 512)

	rec := do(t, h, http.MethodPost, "/finalize", finalizeBody(finalizeID, finalizeGUID, false))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got struct {
		ArtifactID  string `json:"artifactId"`
		ArchiveName string `json:"archiveName"`
		Bytes       int64  `json:"bytes"`
		Partial     bool   `json:"partial"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if got.ArtifactID != finalizeID {
		t.Errorf("artifactId = %q, want %q", got.ArtifactID, finalizeID)
	}
	if got.ArchiveName != "vault.zip" {
		t.Errorf("archiveName = %q, want vault.zip", got.ArchiveName)
	}
	if got.Bytes != 512 {
		t.Errorf("bytes = %d, want 512", got.Bytes)
	}
	if got.Partial {
		t.Error("partial = true for a clean finalize")
	}

	// The point of the verb, from the api's side: it can now stat the artifact.
	statRec := do(t, h, http.MethodPost, "/stat", []byte(`{"artifactId":"`+finalizeID+`"}`))
	if statRec.Code != http.StatusOK {
		t.Fatalf("stat = %d: %s", statRec.Code, statRec.Body.String())
	}
	var stat pool.Stat
	if err := json.Unmarshal(statRec.Body.Bytes(), &stat); err != nil {
		t.Fatalf("decode stat: %v", err)
	}
	if !stat.Exists {
		t.Error("finalize returned 200 but /stat says the artifact does not exist; " +
			"every download would 404")
	}
}

func TestFinalizeNamesAPartialArchive(t *testing.T) {
	_, h, cfg := newTestServer(t)
	stageForTest(t, cfg, finalizeID, 256)

	rec := do(t, h, http.MethodPost, "/finalize", finalizeBody(finalizeID, finalizeGUID, true))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "vault.partial.zip") {
		t.Errorf("body = %s, want it to name vault.partial.zip", rec.Body.String())
	}
}

func TestFinalizeAnswers409WhenNothingIsStaged(t *testing.T) {
	// The status is the assertion. A generic 500 here sends an operator to look
	// at a disk that is fine; the caller needs to know its own export produced no
	// archive.
	_, h, _ := newTestServer(t)

	rec := do(t, h, http.MethodPost, "/finalize", finalizeBody(finalizeID, finalizeGUID, false))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "nothing staged") {
		t.Errorf("body = %s, want it to say nothing was staged", rec.Body.String())
	}
}

func TestFinalizeRejectsABadArtifactID(t *testing.T) {
	// 400, before it is ever joined to a host path. A 409 here would suggest a
	// stale id rather than a malformed one.
	_, h, _ := newTestServer(t)

	for _, bad := range []string{"short", strings.Repeat("a", 44), "../" + finalizeID, ""} {
		rec := do(t, h, http.MethodPost, "/finalize", finalizeBody(bad, finalizeGUID, false))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("id %q: status = %d, want 400: %s", bad, rec.Code, rec.Body.String())
		}
	}
}

func TestFinalizeRejectsABadSessionGUID(t *testing.T) {
	_, h, _ := newTestServer(t)

	rec := do(t, h, http.MethodPost, "/finalize", finalizeBody(finalizeID, "not-a-guid", false))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestFinalizeRequiresASignature(t *testing.T) {
	// Same as every other verb, and asserted because a verb added to the route
	// table without the auth hook is the kind of omission that has no other
	// symptom than an open endpoint.
	_, h, cfg := newTestServer(t)
	stageForTest(t, cfg, finalizeID, 64)

	rec := doRaw(t, h, http.MethodPost, "/finalize", finalizeBody(finalizeID, finalizeGUID, false))
	if rec.Code == http.StatusOK {
		t.Fatalf("an unsigned finalize succeeded: %s", rec.Body.String())
	}
}

func TestFinalizeRejectsAMalformedBody(t *testing.T) {
	_, h, _ := newTestServer(t)

	rec := do(t, h, http.MethodPost, "/finalize", []byte("{not json"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestFinalizeIsInTheRouteTable(t *testing.T) {
	// The route table is "the complete set of what the orchestrator can be asked
	// to do", and T-X3 is that reading it is sufficient. A handler that exists
	// but is not in the table is unreachable code that a reader would believe in.
	_, h, _ := newTestServer(t)

	rec := do(t, h, http.MethodGet, "/finalize", nil)
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("GET /finalize = %d; the verb should exist for POST only", rec.Code)
	}
}
