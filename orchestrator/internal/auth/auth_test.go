package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

// signedRequest builds a request with a valid signature for the given inputs.
func signedRequest(t *testing.T, secret []byte, method, path string, body []byte, now time.Time) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	ts, sig := Sign(secret, method, r.URL.EscapedPath(), body, now)
	r.Header.Set(HeaderTS, ts)
	r.Header.Set(HeaderSig, sig)
	return r
}

// TestVerifyAcceptsFreshSignature is the happy path. Without it, a scheme that
// rejects everything passes every rejection test below.
func TestVerifyAcceptsFreshSignature(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	r := signedRequest(t, testSecret, http.MethodPost, "/claim", []byte(`{"a":1}`), now)

	if err := Verify(testSecret, r, []byte(`{"a":1}`), 60*time.Second, now); err != nil {
		t.Fatalf("fresh signature rejected: %v", err)
	}
}

// T-I1: an unsigned call to any endpoint fails.
func TestVerifyRejectsMissingHeaders(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	r := httptest.NewRequest(http.MethodPost, "/claim", nil)

	if err := Verify(testSecret, r, nil, 60*time.Second, now); err != ErrMissingHeaders {
		t.Fatalf("want ErrMissingHeaders, got %v", err)
	}

	// A timestamp with no signature is equally unsigned.
	r2 := httptest.NewRequest(http.MethodPost, "/claim", nil)
	r2.Header.Set(HeaderTS, "1700000000000")
	if err := Verify(testSecret, r2, nil, 60*time.Second, now); err != ErrMissingHeaders {
		t.Fatalf("ts without sig: want ErrMissingHeaders, got %v", err)
	}
}

// T-I2: a captured, correctly signed request replayed after 61s fails.
func TestVerifyRejectsReplayPastWindow(t *testing.T) {
	sent := time.UnixMilli(1_700_000_000_000)
	// Capture the exact bytes a legitimate caller would send.
	r := signedRequest(t, testSecret, http.MethodPost, "/claim", []byte(`{"a":1}`), sent)

	// 59s later: inside the window.
	if err := Verify(testSecret, r, []byte(`{"a":1}`), 60*time.Second, sent.Add(59*time.Second)); err != nil {
		t.Fatalf("59s old rejected: %v", err)
	}

	// 61s later: outside. This is the exact boundary the plan names.
	if err := Verify(testSecret, r, []byte(`{"a":1}`), 60*time.Second, sent.Add(61*time.Second)); err != ErrOutsideWindow {
		t.Fatalf("61s old: want ErrOutsideWindow, got %v", err)
	}
}

// The window must reject a future timestamp too. Accepting only the past would
// let a caller park a valid signature indefinitely.
func TestVerifyRejectsFutureTimestamp(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	r := signedRequest(t, testSecret, http.MethodPost, "/claim", nil, now)

	if err := Verify(testSecret, r, nil, 60*time.Second, now.Add(90*time.Second)); err != ErrOutsideWindow {
		t.Fatalf("want ErrOutsideWindow for future ts, got %v", err)
	}
}

// The window is symmetric at the boundary, in both directions.
func TestVerifyWindowBoundariesAreSymmetric(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	r := signedRequest(t, testSecret, http.MethodGet, "/stats", nil, now)

	for _, delta := range []time.Duration{-60 * time.Second, 60 * time.Second} {
		if err := Verify(testSecret, r, nil, 60*time.Second, now.Add(delta)); err != nil {
			t.Fatalf("exactly %v: want accepted, got %v", delta, err)
		}
	}
	for _, delta := range []time.Duration{-61 * time.Second, 61 * time.Second} {
		if err := Verify(testSecret, r, nil, 60*time.Second, now.Add(delta)); err != ErrOutsideWindow {
			t.Fatalf("exactly %v: want rejected, got %v", delta, err)
		}
	}
}

// T-I3: a signature captured for GET /stats replayed as POST /release fails.
// The method and the path are both inside the signed string.
func TestVerifyRejectsMethodAndPathSubstitution(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	r := signedRequest(t, testSecret, http.MethodGet, "/stats", nil, now)

	// Same headers, different method and path.
	attack := httptest.NewRequest(http.MethodPost, "/release", nil)
	attack.Header.Set(HeaderTS, r.Header.Get(HeaderTS))
	attack.Header.Set(HeaderSig, r.Header.Get(HeaderSig))

	if err := Verify(testSecret, attack, nil, 60*time.Second, now); err != ErrBadSignature {
		t.Fatalf("method+path substitution: want ErrBadSignature, got %v", err)
	}

	// Method alone.
	methodOnly := httptest.NewRequest(http.MethodPost, "/stats", nil)
	methodOnly.Header.Set(HeaderTS, r.Header.Get(HeaderTS))
	methodOnly.Header.Set(HeaderSig, r.Header.Get(HeaderSig))
	if err := Verify(testSecret, methodOnly, nil, 60*time.Second, now); err != ErrBadSignature {
		t.Fatalf("method substitution: want ErrBadSignature, got %v", err)
	}

	// Path alone.
	pathOnly := httptest.NewRequest(http.MethodGet, "/remove", nil)
	pathOnly.Header.Set(HeaderTS, r.Header.Get(HeaderTS))
	pathOnly.Header.Set(HeaderSig, r.Header.Get(HeaderSig))
	if err := Verify(testSecret, pathOnly, nil, 60*time.Second, now); err != ErrBadSignature {
		t.Fatalf("path substitution: want ErrBadSignature, got %v", err)
	}
}

// T-I4: a signature over an empty body replayed with a body fails. The body
// digest is in the signed string.
func TestVerifyRejectsBodySubstitution(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	signed := signedRequest(t, testSecret, http.MethodPost, "/claim", nil, now)

	// Same signature, now with a body. The path and method are unchanged, so
	// only the digest binding can catch this.
	if err := Verify(testSecret, signed, []byte(`{"slotId":"slot-1"}`), 60*time.Second, now); err != ErrBadSignature {
		t.Fatalf("empty->body substitution: want ErrBadSignature, got %v", err)
	}
}

// A body swapped for a different body also fails, even when the length matches.
func TestVerifyRejectsBodySwapOfEqualLength(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	original := []byte(`{"slotId":"slot-1"}`)
	swapped := []byte(`{"slotId":"slot-2"}`)
	if len(original) != len(swapped) {
		t.Fatal("fixture lengths must match for this test to be meaningful")
	}

	r := signedRequest(t, testSecret, http.MethodPost, "/release", original, now)
	if err := Verify(testSecret, r, swapped, 60*time.Second, now); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

// A wrong secret must fail, and must fail as a mismatch rather than a window
// error, so a rotated secret is diagnosable from the log line.
func TestVerifyRejectsWrongSecret(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	other := []byte("fedcba9876543210fedcba9876543210")
	r := signedRequest(t, testSecret, http.MethodGet, "/stats", nil, now)

	if err := Verify(other, r, nil, 60*time.Second, now); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

// A malformed timestamp is a client bug and is reported as one, distinctly from
// an out-of-window timestamp. Collapsing them would make a clock problem
// indistinguishable from an attack in the logs.
func TestVerifyRejectsMalformedTimestamp(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	r := httptest.NewRequest(http.MethodGet, "/stats", nil)
	r.Header.Set(HeaderTS, "not-a-number")
	r.Header.Set(HeaderSig, "whatever")

	if err := Verify(testSecret, r, nil, 60*time.Second, now); err != ErrBadTimestamp {
		t.Fatalf("want ErrBadTimestamp, got %v", err)
	}
}

// The signed string must be unambiguous: no combination of fields can produce
// another request's signed bytes. Without the separators, "GET" + "/stats" and
// "GET/" + "stats" style collisions would be reachable.
func TestSigningStringIsUnambiguous(t *testing.T) {
	a := signingString("1", "GET", "/stats", nil)
	b := signingString("1", "GET", "/stats", nil)
	if a != b {
		t.Fatal("signing string must be deterministic")
	}

	// Distinct inputs must produce distinct signed strings.
	seen := map[string]bool{a: true}
	for _, other := range []string{
		signingString("2", "GET", "/stats", nil),
		signingString("1", "POST", "/stats", nil),
		signingString("1", "GET", "/release", nil),
		signingString("1", "GET", "/stats", []byte("x")),
	} {
		if seen[other] {
			t.Fatal("distinct requests produced an identical signed string")
		}
		seen[other] = true
	}
}

// Sign and Verify must agree without the caller passing the path through
// EscapedPath itself — a mismatch here would be a silent total failure to
// authenticate in production, which is why it is tested end to end.
func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	cases := []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodPost, "/claim", []byte(`{"sessionGuid":"x"}`)},
		{http.MethodGet, "/stats", nil},
		{http.MethodPost, "/stat", []byte(`{"artifactId":"y"}`)},
		{http.MethodGet, "/healthz", []byte{}},
	}
	for _, tc := range cases {
		r := signedRequest(t, testSecret, tc.method, tc.path, tc.body, now)
		if err := Verify(testSecret, r, tc.body, 60*time.Second, now); err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
	}
}

// The signature is base64url with no padding, which is what the header
// transport can carry without quoting.
func TestSignatureEncoding(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	_, sig := Sign(testSecret, http.MethodGet, "/stats", nil, now)
	if len(sig) != 43 {
		t.Fatalf("signature length = %d, want 43 (32 bytes, base64url unpadded)", len(sig))
	}
	if strings.ContainsAny(sig, "+/=") {
		t.Fatalf("signature is not unpadded base64url: %q", sig)
	}
}
