// Package auth implements the signed internal-call scheme for
// api -> orchestrator requests.
//
// A bare bearer token is not enough. The threat is a *replayed* request to an
// endpoint that can create containers, so the signature covers everything that
// distinguishes one request from another (PLANNING/PLAN-v3.md §2.1):
//
//	X-Msout-TS:  <unix ms>
//	X-Msout-Sig: base64url(HMAC-SHA256(secret, TS + "\n" + METHOD + "\n" + path + "\n" + sha256hex(body)))
//
// Method and path are in the signed string, so a signature captured for
// GET /stats cannot be replayed as POST /release (T-I3). The body digest is in
// it, so a signature over an empty body cannot be re-pointed at a POST that
// carries one (T-I4).
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Header names. Deliberately prefixed so they cannot collide with anything a
// browser sends, and so they are obvious in a packet capture.
const (
	HeaderTS  = "X-Msout-TS"
	HeaderSig = "X-Msout-Sig"
)

// Errors returned by Verify. They are distinct so the caller can map them to
// distinct status codes: a replay is 401, a malformed request is 400. Collapsing
// them would make a client's clock bug indistinguishable from an attack.
var (
	ErrMissingHeaders = errors.New("auth: missing signature headers")
	ErrBadTimestamp   = errors.New("auth: malformed timestamp")
	ErrOutsideWindow  = errors.New("auth: timestamp outside replay window")
	ErrBadSignature   = errors.New("auth: signature mismatch")
)

// Sign returns the headers a caller must attach for this request.
//
// Exported because `api` needs it. The signing string is assembled here rather
// than at the call site so both sides cannot drift.
func Sign(secret []byte, method, path string, body []byte, now time.Time) (ts, sig string) {
	ts = strconv.FormatInt(now.UnixMilli(), 10)
	return ts, Signature(secret, ts, method, path, body)
}

// Signature computes the base64url signature for a signed request.
func Signature(secret []byte, ts, method, path string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingString(ts, method, path, body)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// signingString is the exact byte sequence both sides agree on.
//
// The newlines are load-bearing separators. Without them, a method and path
// could be chosen so that one request's field boundaries produce another
// request's string ("GET\n/stats" vs "GET\n/stats" style confusion). This is
// the same reason the signed string includes a body digest rather than the body.
func signingString(ts, method, path string, body []byte) string {
	sum := sha256.Sum256(body)
	var b strings.Builder
	b.Grow(len(ts) + len(method) + len(path) + 3*32 + 3)
	b.WriteString(ts)
	b.WriteByte('\n')
	b.WriteString(strings.ToUpper(method))
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(sum[:]))
	return b.String()
}

// Verify checks an incoming request's signature against the window.
//
// now is a parameter rather than a call to time.Now so the window is testable
// at its exact boundaries rather than approximately.
func Verify(secret []byte, r *http.Request, body []byte, window time.Duration, now time.Time) error {
	ts := r.Header.Get(HeaderTS)
	got := r.Header.Get(HeaderSig)
	if ts == "" || got == "" {
		return ErrMissingHeaders
	}

	ms, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrBadTimestamp
	}
	sent := time.UnixMilli(ms)

	// Abs in both directions: a timestamp too far in the *future* is as
	// suspicious as one too far in the past. Accepting only the past would let
	// a caller park a valid signature for as long as it likes.
	skew := sent.Sub(now)
	if skew < 0 {
		skew = -skew
	}
	if skew > window {
		return ErrOutsideWindow
	}

	want := Signature(secret, ts, r.Method, r.URL.EscapedPath(), body)

	// Constant-time comparison (T-I7). subtle.ConstantTimeCompare returns 0
	// immediately if the lengths differ, which leaks length only; the signature
	// is always 43 chars of base64url, so that is not informative.
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return ErrBadSignature
	}
	return nil
}
