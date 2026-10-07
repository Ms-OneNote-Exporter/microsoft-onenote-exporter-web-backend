package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/auth"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/pool"
)

// httpError is an error carrying the status it should produce.
//
// Handlers return errors rather than writing responses, so the status mapping
// lives in exactly one place and a new handler cannot invent its own.
type httpError struct {
	status int
	code   string
	cause  error
}

func (e *httpError) Error() string {
	if e.cause != nil {
		return e.code + ": " + e.cause.Error()
	}
	return e.code
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *httpError) Unwrap() error { return e.cause }

func badRequest(code string, cause error) error {
	return &httpError{status: http.StatusBadRequest, code: code, cause: cause}
}

// conflict is a 409: the request is well-formed and authorised, but the caller's
// view of the world is stale — it asked for something that is not there, or that
// is already in a different state.
func conflict(code string, cause error) error {
	return &httpError{status: http.StatusConflict, code: code, cause: cause}
}

// writeHandlerError maps an error to a status and body.
//
// The pool's sentinel errors are the interesting cases: ErrNoSlot is 503
// because it is a capacity condition `api` can answer with a wait estimate,
// and the rest are 409 because they mean the caller's view of the pool is stale
// rather than the request being wrong. An unexpected error is logged in full
// and reported generically, because the Engine's error text can contain a
// socket path.
func (s *Server) writeHandlerError(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpError
	switch {
	case errors.As(err, &he):
		writeError(w, he.status, he.code)
	case errors.Is(err, pool.ErrNoSlot):
		writeError(w, http.StatusServiceUnavailable, "no idle slot")
	case errors.Is(err, pool.ErrUnknownSlot):
		writeError(w, http.StatusConflict, "unknown slot")
	case errors.Is(err, pool.ErrAlreadyBound), errors.Is(err, pool.ErrNotBound):
		writeError(w, http.StatusConflict, "slot state does not allow this")
	case errors.Is(err, pool.ErrNothingStaged):
		// Its own case, because it is the one 409 a caller can act on: it means
		// it asked to publish an export that produced no archive. Falling into
		// the generic 500 would send an operator looking at a disk that is fine.
		writeError(w, http.StatusConflict, "nothing staged to finalise")
	default:
		s.log.Error("handler failed",
			"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "error", err)
		// Deliberately generic. A Docker engine error can name a socket path
		// or a host directory, and the caller is a different component on a
		// different trust level.
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// writeAuthError maps an auth failure to a status.
//
// Missing or malformed headers are 400 and a bad signature or an out-of-window
// timestamp is 401. They are kept distinct because they mean different things
// to whoever is debugging: a 400 is a client bug, a 401 is either an attack or
// a clock problem. Collapsing them would make the failure matrix in
// PLANNING/PLAN-v3.md §7.3 unactionable.
//
// Every one of these responses is written by this function rather than by a
// per-handler path, so there is no branch where an auth failure falls through
// to a handler's own error writer.
func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrMissingHeaders):
		writeError(w, http.StatusBadRequest, "missing signature headers")
	case errors.Is(err, auth.ErrBadTimestamp):
		writeError(w, http.StatusBadRequest, "malformed timestamp")
	case errors.Is(err, auth.ErrOutsideWindow):
		writeError(w, http.StatusUnauthorized, "timestamp outside replay window")
	default:
		writeError(w, http.StatusUnauthorized, "signature mismatch")
	}
}

// errorBody is the shape of every non-2xx response.
type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already sent, so the only honest thing left is to
		// stop. The caller sees a truncated body, which is a clearer failure
		// than a half-written one.
		return
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorBody{Error: code})
}

// slogDefaultTime is time.Now behind a function value.
//
// A function rather than a direct call keeps the duration computation honest if
// this is ever used with a fake clock in tests, and it reads more clearly than
// repeating time.Now() twice in one expression.
func slogDefaultTime() time.Time { return time.Now() }

// logRequest is the middleware's audit line.
//
// Only method, path, status and duration. No headers, no body, no
// Authorization value. The orchestrator never holds a credential, but it does
// hold the HMAC secret in its memory, and a log line that recorded the
// signature would make a replay trivial for anyone who read the logs.
func logRequest(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := slogDefaultTime()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Info("internal call",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"durationMs", slogDefaultTime().Sub(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// statusRecorder captures the status code for the audit line.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
