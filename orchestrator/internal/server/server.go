// Package server is the orchestrator's HTTP surface.
//
// Five verbs and a health check. That is the entire API, and the way that is
// enforced is structural rather than conventional:
//
//   - Routes are registered in an explicit map literal in routes(). An unknown
//     method or path never reaches a handler, so there is no default branch to
//     get wrong (PLANNING/PLAN-v3.md §2.1, test T-I5).
//   - Every handler takes a typed request struct and ignores the raw body
//     beyond the fields that struct declares. A caller cannot smuggle a field
//     in because there is nowhere for it to be read from (T-X3).
//   - Every request passes the signature check before routing. An unsigned
//     request does not learn whether the path exists, which keeps this surface
//     from being a probe oracle for a host-local attacker.
//
// The read paths that take no session state (/stats, /healthz) are signed like
// everything else. There is no unauthenticated read endpoint: the orchestrator
// is not published to the host at all, so an unauthenticated read would buy
// nothing and cost the argument that its exposure is zero.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/auth"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/pool"
)

// maxBodyBytes caps a request body. Every verb's legitimate body is well under
// this — the largest is a claim request carrying two identifiers. A caller
// cannot make the orchestrator allocate by sending a large body, and it cannot
// make the signature check expensive by hashing gigabytes.
const maxBodyBytes = 8 << 10

// SessionLookup reports whether a session is still live.
//
// `api` owns session state; the orchestrator only needs to answer "is this
// still valid" so boot reconciliation can refuse to resurrect an expired
// session (PLANNING/PLAN-v2.md §2.5). It is a predicate, not a data feed: the
// orchestrator never learns a session's notebook, its state or its auth state.
type SessionLookup interface {
	SessionExpired(guid string) bool
}

// SessionLookupFunc adapts a function to SessionLookup.
type SessionLookupFunc func(guid string) bool

// SessionExpired implements SessionLookup.
func (f SessionLookupFunc) SessionExpired(guid string) bool { return f(guid) }

// NeverExpire is the SessionLookup to use before `api` is reachable. It reports
// nothing expired, so reconciliation adopts what it finds rather than deleting
// a session that is merely not yet known. The safe direction: adopting a
// container that should have been reaped is recoverable, deleting a live
// session is not.
func NeverExpire(string) bool { return false }

// Server serves the verb set.
type Server struct {
	cfg      *config.Config
	pool     *pool.Pool
	log      *slog.Logger
	sessions SessionLookup

	// reconcileErr records the outcome of boot reconciliation so /healthz can
	// report it. Reconciliation failing is not fatal — the process still serves
	// the verb set, it just cannot trust the pool yet — so this is state to
	// expose rather than an error to return from New.
	reconcileErr error
}

// New returns a Server.
func New(cfg *config.Config, p *pool.Pool, log *slog.Logger, sessions SessionLookup) *Server {
	if log == nil {
		log = slog.Default()
	}
	if sessions == nil {
		sessions = SessionLookupFunc(NeverExpire)
	}
	return &Server{cfg: cfg, pool: p, log: log, sessions: sessions}
}

// SetReconcileResult records the boot reconciliation outcome for /healthz.
func (s *Server) SetReconcileResult(err error) { s.reconcileErr = err }

// Handler returns the routed handler with the signature middleware applied.
// Handler returns the fully wrapped handler: the route table with the
// signature check inside it, under the audit log.
//
// The signature check is inside routes() rather than a wrapping middleware
// because it must run before routing. A wrapping middleware that ran after
// dispatch would let an unsigned caller reach a handler's not-found branch.
func (s *Server) Handler() http.Handler {
	return logRequest(s.log, s.routes())
}

// routeTable returns the method -> path map, exposed for tests.
//
// It exists so the verb set can be enumerated in a test rather than asserted in
// prose. Returning the map keyed by path (rather than a flat list of paths) is
// what lets a test also check that no path acquired a second method.
func (s *Server) routeTable() map[string]map[string]struct{} {
	table := map[string]map[string]struct{}{
		"/claim":    {http.MethodPost: {}},
		"/release":  {http.MethodPost: {}},
		"/recycle":  {http.MethodPost: {}},
		"/remove":   {http.MethodPost: {}},
		"/stat":     {http.MethodPost: {}},
		"/stats":    {http.MethodGet: {}},
		"/healthz":  {http.MethodGet: {}},
		"/finalize": {http.MethodPost: {}},
	}
	return table
}

// routes is the complete route table.
//
// Kept as an explicit literal rather than built from the verb list so that
// reading this function is sufficient to enumerate what the orchestrator can be
// asked to do. That is the operational form of T-X3.
func (s *Server) routes() http.Handler {
	type handlerFunc func(*call) (any, error)

	table := map[string]map[string]handlerFunc{
		"/claim": {
			http.MethodPost: s.handleClaim,
		},
		"/release": {
			http.MethodPost: s.handleRelease,
		},
		"/recycle": {
			http.MethodPost: s.handleRecycle,
		},
		"/remove": {
			http.MethodPost: s.handleRemove,
		},
		"/stat": {
			http.MethodPost: s.handleStat,
		},
		"/finalize": {
			http.MethodPost: s.handleFinalize,
		},
		"/stats": {
			http.MethodGet: s.handleStats,
		},
		"/healthz": {
			http.MethodGet: s.handleHealthz,
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A body is read before routing so the signature covers it (T-I4). It
		// is read with a hard cap so a large body cannot be used to make this
		// process allocate or hash without bound.
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, "read body")
			return
		}
		if len(body) > maxBodyBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}

		// Verify before routing: an unsigned caller must not be able to
		// distinguish 404 from 405 from a handler's own error.
		if err := auth.Verify(s.cfg.HMACSecret, r, body, s.cfg.ReplayWindow, time.Now()); err != nil {
			s.log.Warn("rejected internal call",
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "error", err)
			writeAuthError(w, err)
			return
		}

		byMethod, ok := table[r.URL.Path]
		if !ok {
			writeError(w, http.StatusNotFound, "unknown path")
			return
		}
		handler, ok := byMethod[r.Method]
		if !ok {
			// 405 for a known path with the wrong method. The Allow header is
			// set because this is the one place the verb set becomes visible,
			// and it is already visible to anyone who can authenticate.
			allowed := make([]string, 0, len(byMethod))
			for m := range byMethod {
				allowed = append(allowed, m)
			}
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		c := &call{req: r, body: body}
		out, err := handler(c)
		if err != nil {
			s.writeHandlerError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
}

// call carries a verified request into a handler.
type call struct {
	req  *http.Request
	body []byte
}

// decode reads the body into v, rejecting unknown fields.
//
// DisallowUnknownFields is the belt to the braces of the typed-struct rule. It
// means a caller sending {"sessionGuid":"…","image":"evil"} gets a 400 rather
// than a silent no-op, which matters because a silently-ignored field is how a
// caller would come to believe it could set an image.
func (c *call) decode(v any) error {
	if len(c.body) == 0 {
		return errors.New("empty body")
	}
	dec := json.NewDecoder(strings.NewReader(string(c.body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing content so `{"slotId":"a"} {"evil":1}` is not silently
	// accepted on the first value.
	if dec.More() {
		return errors.New("trailing content after json object")
	}
	return nil
}

// claimRequest is the whole of the claim verb's input schema.
type claimRequest struct {
	// SessionGUID identifies the session. Validated as a UUID before it is
	// used to build any path.
	SessionGUID string `json:"sessionGuid"`
	// SessionExpiresAtMs is the session's absolute cap, in Unix ms.
	SessionExpiresAtMs int64 `json:"sessionExpiresAtMs"`
}

// handleClaim takes an idle slot and binds it to a session.
func (s *Server) handleClaim(c *call) (any, error) {
	var req claimRequest
	if err := c.decode(&req); err != nil {
		return nil, badRequest("malformed claim request", err)
	}
	if !config.ValidGUID(req.SessionGUID) {
		// Rejected on shape, before it reaches the pool. The pool would reject
		// it too; the check is here so the reason is a clean 400 rather than an
		// internal error.
		return nil, badRequest("sessionGuid must be a lowercase uuid", nil)
	}
	if req.SessionExpiresAtMs <= 0 {
		return nil, badRequest("sessionExpiresAtMs is required", nil)
	}

	slot, err := s.pool.Claim(c.req.Context(), req.SessionGUID,
		time.UnixMilli(req.SessionExpiresAtMs))
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"slotId":      slot.ID,
		"containerId": slot.ContainerID,
		// Where `api` posts the credential. Absent here it would have to guess
		// a container name or resolve an IP, and either guess is a second
		// implementation of this component's naming — the drift that produced
		// the three silent failures in runner.go/index.ts.
		//
		// Stable for the life of the *slot*, not the container, so this does not
		// go stale when `recycle` replaces the container. See pool.RunnerURL.
		"runnerUrl": s.pool.RunnerURL(slot.ID),
	}, nil
}

// slotRequest is the input schema for release, recycle and remove.
type slotRequest struct {
	SlotID string `json:"slotId"`
}

// handleRelease returns a slot and destroys its container.
func (s *Server) handleRelease(c *call) (any, error) {
	var req slotRequest
	if err := c.decode(&req); err != nil {
		return nil, badRequest("malformed release request", err)
	}
	if err := s.pool.Release(c.req.Context(), req.SlotID); err != nil {
		return nil, err
	}
	return map[string]any{"released": true}, nil
}

// recycleRequest adds a reason to the recycle verb's schema.
//
// The reason is recorded in the log only. It is not a command, and it cannot
// affect what the verb does — recycle always does the same thing.
type recycleRequest struct {
	SlotID string `json:"slotId"`
	Reason string `json:"reason"`
}

// handleRecycle replaces a container that outlived the runner TTL.
func (s *Server) handleRecycle(c *call) (any, error) {
	var req recycleRequest
	if err := c.decode(&req); err != nil {
		return nil, badRequest("malformed recycle request", err)
	}
	if err := s.pool.Recycle(c.req.Context(), req.SlotID, req.Reason); err != nil {
		return nil, err
	}
	return map[string]any{"recycled": true}, nil
}

// handleRemove tears a slot down entirely.
func (s *Server) handleRemove(c *call) (any, error) {
	var req slotRequest
	if err := c.decode(&req); err != nil {
		return nil, badRequest("malformed remove request", err)
	}
	if err := s.pool.Remove(c.req.Context(), req.SlotID); err != nil {
		return nil, err
	}
	return map[string]any{"removed": true}, nil
}

// statRequest is the input schema for the stat verb.
type statRequest struct {
	ArtifactID string `json:"artifactId"`
}

// handleStat reports whether an artifact exists and how large it is.
//
// The only question `api` asks before authorising a download. It asks it here
// rather than reading the filesystem itself so that `api` never needs access to
// the artifact tree (PLANNING/PLAN-v3.md §2.2).
func (s *Server) handleStat(c *call) (any, error) {
	var req statRequest
	if err := c.decode(&req); err != nil {
		return nil, badRequest("malformed stat request", err)
	}
	if !config.ValidArtifactID(req.ArtifactID) {
		return nil, badRequest("artifactId must be 43 base64url characters", nil)
	}
	return s.pool.ArtifactStat(req.ArtifactID)
}

// handleStats reports pool occupancy.
func (s *Server) handleStats(*call) (any, error) {
	return s.pool.Stats(), nil
}

// finalizeRequest is the input schema for the finalize verb.
type finalizeRequest struct {
	ArtifactID  string `json:"artifactId"`
	SessionGUID string `json:"sessionGuid"`
	Partial     bool   `json:"partial"`
}

// handleFinalize publishes a staged archive under its artifact id.
//
// PLAN-v3 §2.2 splits this deliberately: the runner streams the zip into a
// staging directory and this process publishes it. It owns the artifact volume
// and it is the only component that knows the artifact id, which is the caller's
// and deliberately unrelated to the session GUID (§5).
//
// `partial` is a claim the caller makes about an export, and it is trusted for
// *labelling only* — it selects the `.partial.zip` name and writes the marker.
// Nothing here verifies it against the export that actually ran, because this
// process cannot: it never saw the walk. So a caller that passes `false` for a
// truncated vault gets an unmarked archive, and the honest fix is for the api to
// pass the truth it already has rather than for this verb to guess.
func (s *Server) handleFinalize(c *call) (any, error) {
	var req finalizeRequest
	if err := c.decode(&req); err != nil {
		return nil, badRequest("malformed finalize request", err)
	}
	if !config.ValidArtifactID(req.ArtifactID) {
		return nil, badRequest("artifactId must be 43 base64url characters", nil)
	}
	if !config.ValidGUID(req.SessionGUID) {
		return nil, badRequest("sessionGuid must be a lowercase uuid", nil)
	}

	result, err := s.pool.Finalize(pool.FinalizeInput{
		ArtifactID:  req.ArtifactID,
		SessionGUID: req.SessionGUID,
		Partial:     req.Partial,
	})
	if err != nil {
		// Reported as-is rather than flattened: `nothing staged` is a caller
		// error (it finalised an export that produced no archive) and deserves a
		// 409, while a filesystem refusal is a 500. Collapsing both would make an
		// operator chase a full disk that is not the problem.
		if errors.Is(err, pool.ErrNothingStaged) || errors.Is(err, pool.ErrArtifactIDInvalid) {
			return nil, conflict("nothing staged to finalise", err)
		}
		return nil, err
	}
	return result, nil
}

// handleHealthz reports liveness and the boot reconciliation outcome.
//
// `api` polls this for its own health, and an operator reads it to answer "did
// the orchestrator start cleanly", so the reconciliation error is surfaced here
// rather than only in the log.
func (s *Server) handleHealthz(*call) (any, error) {
	out := map[string]any{
		"ok":                  s.reconcileErr == nil,
		"pool":                s.pool.Stats(),
		"replayWindowSeconds": int(s.cfg.ReplayWindow.Seconds()),
	}
	if s.reconcileErr != nil {
		out["error"] = s.reconcileErr.Error()
	}
	return out, nil
}
