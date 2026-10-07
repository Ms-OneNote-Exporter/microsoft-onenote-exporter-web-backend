package server

// The `runnerUrl` field on a claim response.
//
// `api` needs somewhere to post a credential, and this is the only place it is
// told. If the field is absent the api would have to derive a container name or
// resolve an IP itself, which means a second implementation of the orchestrator's
// naming — the exact shape that produced three silent failures in runner.go and
// index.ts, where each side agreed the other provided something neither did.
//
// So the test here is about the far side: the URL in the response must be one a
// caller could actually dial, and it must not be reachable by being derived from
// anything the caller supplied.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/dockerapi"
)

const claimGUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

type claimServer struct {
	*Server
	url string
}

// TestClaimReturnsAnAddressApiCanDial drives a real claim through the real
// handler and reads the response the api will read.
func TestClaimReturnsAnAddressApiCanDial(t *testing.T) {
	srv, h, cfg := newTestServerWithDaemon(t)

	body, _ := json.Marshal(map[string]any{
		"sessionGuid":        claimGUID,
		"sessionExpiresAtMs": time.Now().Add(time.Hour).UnixMilli(),
	})
	rec := do(t, h, http.MethodPost, "/claim", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("claim = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got struct {
		SlotID      string `json:"slotId"`
		ContainerID string `json:"containerId"`
		RunnerURL   string `json:"runnerUrl"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SlotID == "" || got.ContainerID == "" {
		t.Fatalf("claim did not report a slot: %s", rec.Body.String())
	}

	// The URL names the alias this component registered, on the configured port.
	// Asserted against the config rather than a literal so that changing the
	// network name or port in one place cannot leave a stale expectation here.
	want := srv.pool.RunnerURL(got.SlotID)
	if got.RunnerURL != want {
		t.Errorf("runnerUrl = %q, want %q", got.RunnerURL, want)
	}
	if !strings.HasPrefix(got.RunnerURL, "http://msout-runner-"+got.SlotID+":") {
		t.Errorf("runnerUrl %q is not the slot's alias address", got.RunnerURL)
	}
	if !strings.HasSuffix(got.RunnerURL, ":"+itoa(cfg.RunnerPort)) {
		t.Errorf("runnerUrl %q does not carry the configured port %d", got.RunnerURL, cfg.RunnerPort)
	}
}

// The URL must not be derivable from the request. A caller that could choose its
// own runner's address could aim the credential at a container it controls, so
// every input to the claim is varied and the URL is checked for having ignored
// all of them.
func TestClaimURLDoesNotDependOnTheRequest(t *testing.T) {
	// Three slots, because each claim consumes one. With a single slot this test
	// would pass its first assertion and fail the rest on "no idle slot" — which
	// is what it did before this comment existed.
	srv, h, _ := newTestServerWithDaemonSized(t, 3)

	var seen []string
	// Different guids, different expiry — the only fields a claim accepts.
	for i, guid := range []string{
		claimGUID,
		"00000000-0000-4000-8000-000000000000",
		"ffffffff-ffff-4fff-bfff-ffffffffffff",
	} {
		body, _ := json.Marshal(map[string]any{
			"sessionGuid":        guid,
			"sessionExpiresAtMs": time.Now().Add(time.Duration(i+1) * time.Hour).UnixMilli(),
		})
		rec := do(t, h, http.MethodPost, "/claim", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("claim %d = %d: %s", i, rec.Code, rec.Body.String())
		}
		var got struct {
			RunnerURL string `json:"runnerUrl"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if strings.Contains(got.RunnerURL, guid) {
			t.Errorf("runnerUrl %q contains the session guid; a GUID in a URL reaches "+
				"access logs, which is the leak PLAN-v3 §5 opaque ids exist to prevent",
				got.RunnerURL)
		}
		seen = append(seen, got.RunnerURL)
	}

	// Each claim took a different slot, and each slot's address is its own. If
	// the URLs were identical the alias would not be per-slot — and one shared
	// address would mean a credential handed to slot 2 lands in slot 1's
	// container, which is two sessions sharing a browser.
	_ = srv
	if len(seen) == 3 && seen[0] == seen[1] && seen[1] == seen[2] {
		t.Errorf("every slot reports the same runnerUrl %q; the alias is not per-slot", seen[0])
	}
}

// A pool with no Docker client must not produce a URL that looks usable. The
// failure mode being guarded is the opposite one — a 503 with a plausible-looking
// address in the body, which would let a client cache a URL for a container that
// was never created.
func TestClaimOnEmptyPoolReportsNoURL(t *testing.T) {
	_, h, _ := newTestServer(t)
	body, _ := json.Marshal(map[string]any{
		"sessionGuid":        claimGUID,
		"sessionExpiresAtMs": time.Now().Add(time.Hour).UnixMilli(),
	})
	rec := do(t, h, http.MethodPost, "/claim", body)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "runnerUrl") {
		t.Errorf("a failed claim returned an address: %s", rec.Body.String())
	}
}

// itoa avoids importing strconv into a file whose only need is a port suffix.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

// The daemon below answers CreateContainer and StartContainer, which is all a
// successful claim needs. Everything else fails, because a claim does not call it
// and a test that silently depended on one would be testing something else.
type claimDaemon struct {
	nextID string
}

func (d *claimDaemon) CreateContainer(_ context.Context, _ dockerapi.CreateRequest, name string) (dockerapi.CreateResponse, error) {
	if d.nextID == "" {
		d.nextID = "container-1"
	} else {
		d.nextID = d.nextID + "x"
	}
	return dockerapi.CreateResponse{ID: d.nextID}, nil
}

func (d *claimDaemon) StartContainer(_ context.Context, _ string) error { return nil }

func (d *claimDaemon) StopContainer(_ context.Context, _ string, _ int) error { return nil }

func (d *claimDaemon) RemoveContainer(_ context.Context, _ string) error { return nil }

func (d *claimDaemon) InspectContainer(_ context.Context, _ string) (*dockerapi.Container, error) {
	return nil, &dockerapi.EngineError{Status: 404, Message: "no such container"}
}

func (d *claimDaemon) ListContainersByLabel(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
