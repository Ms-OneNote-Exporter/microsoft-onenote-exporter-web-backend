// Package pool manages the runner slot pool.
//
// The orchestrator's job is small on purpose: keep a fixed number of runner
// containers around, hand idle ones to sessions, and take them back. It holds
// no session state and makes no authorisation decisions — those belong to `api`
// and its SQLite (PLANNING/PLAN-v3.md §2.2). What it does hold is the authority
// to start and destroy containers, which is why its input surface is a fixed
// verb set and nothing more.
package pool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/dockerapi"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/labels"
)

// Errors distinguishable by the HTTP layer.
var (
	// ErrNoSlot means every runner is busy. This is the pool-exhaustion case
	// from PLANNING/PLAN-v2.md §2.6; `api` turns it into a 503 with a wait
	// estimate it computes from its own session rows.
	ErrNoSlot = errors.New("pool: no idle slot")

	// ErrUnknownSlot means the slot id is not in the pool at all, which is a
	// caller error rather than a transient condition.
	ErrUnknownSlot = errors.New("pool: unknown slot")

	// ErrAlreadyBound means the slot is already serving a session.
	ErrAlreadyBound = errors.New("pool: slot already bound")

	// ErrNotBound means a release or recycle named a slot that holds no
	// session.
	ErrNotBound = errors.New("pool: slot not bound")
)

// State is a slot's lifecycle state.
type State string

const (
	// StateStarting is a container that exists but is not yet running.
	StateStarting State = "starting"
	// StateIdle is a running container with no session bound.
	StateIdle State = "idle"
	// StateBound is a running container serving a session.
	StateBound State = "bound"
	// StateDraining is a container being stopped or replaced.
	StateDraining State = "draining"
	// StateDead is a container that failed to start or exited unexpectedly.
	StateDead State = "dead"
)

// Slot is one pool position and the container currently occupying it.
//
// A slot outlives its containers. When one is recycled the slot keeps its id
// and gets a new container id, which is why both identities are carried
// separately in the labels.
type Slot struct {
	// ID is the stable slot identity, assigned at startup.
	ID string
	// State is the current lifecycle state.
	State State
	// ContainerID is the Docker container id, empty when the slot has none.
	ContainerID string
	// SessionGUID is the session this slot serves, empty when unbound.
	SessionGUID string
	// CreatedAt is when the current container was created. The recycle budget
	// is measured from here, not from slot creation.
	CreatedAt time.Time
	// BoundAt is when the current session bound. Idle-TTL is measured from
	// here.
	BoundAt time.Time
	// SessionExpiresAt mirrors the session's absolute cap so the reaper can
	// retire a container without consulting anything else.
	SessionExpiresAt time.Time
}

// IsIdle reports whether the slot can be handed to a session.
func (s *Slot) IsIdle() bool { return s.State == StateIdle }

// Daemon is the Docker Engine surface the pool uses.
//
// An interface rather than a concrete *dockerapi.Client, for two reasons. It is
// the seam that makes Reconcile testable without a daemon — boot reconciliation
// is the one part of this component with real branching, so testing it against a
// fake buys more than testing it against nothing. And it makes the authority
// explicit: these six calls are everything the pool can do to the host, so the
// set can be read in one screen and re-reviewed when a verb is added.
//
// Note what is absent. There is no method taking a caller-influenced image,
// command, flag, mount, network or path — the verbs pass identifiers, and this
// interface has nowhere to put an instruction.
type Daemon interface {
	CreateContainer(ctx context.Context, req dockerapi.CreateRequest, name string) (dockerapi.CreateResponse, error)
	StartContainer(ctx context.Context, id string) error
	StopContainer(ctx context.Context, id string, timeout int) error
	RemoveContainer(ctx context.Context, id string) error
	InspectContainer(ctx context.Context, id string) (*dockerapi.Container, error)
	ListContainersByLabel(ctx context.Context, label string) ([]string, error)
}

// Pool owns the slots and the Docker calls that create and destroy them.
type Pool struct {
	cfg    *config.Config
	docker Daemon
	log    *slog.Logger
	now    func() time.Time

	mu    sync.Mutex
	slots map[string]*Slot

	// rand picks an idle slot at random. PLANNING/PLAN-v2.md §2.4 specifies
	// ORDER BY RANDOM() in the SQLite claim, so this matches it: spreading
	// load across runners rather than always handing out the same one, which
	// would keep one container warm and leave the rest cold.
	randMu sync.Mutex
	rnd    *rand.Rand

	// lastFillErr is why the most recent EnsurePool could not create a container,
	// and fillFailureCount how many attempts in a row have failed. Both cleared by
	// a successful top-up.
	//
	// They exist because a pool that cannot fill is indistinguishable from a busy
	// one through the slot list, and the difference matters: one clears by waiting
	// and the other never clears at all. See Stats.FillError.
	lastFillErr      error
	fillFailureCount int
}

// New returns a pool. It does not touch Docker; call Reconcile or EnsurePool.
func New(cfg *config.Config, docker Daemon, log *slog.Logger) *Pool {
	if log == nil {
		log = slog.Default()
	}
	return &Pool{
		cfg:    cfg,
		docker: docker,
		log:    log,
		now:    time.Now,
		//nolint:gosec // G404: not used for anything security-bearing. Slot
		// selection only; every decision it affects is re-checked under mu.
		rnd:   rand.New(rand.NewSource(time.Now().UnixNano())),
		slots: make(map[string]*Slot, cfg.PoolSize),
	}
}

// Slots returns a snapshot of the pool, safe to read without holding the lock.
func (p *Pool) Slots() []Slot {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Slot, 0, len(p.slots))
	for _, s := range p.slots {
		out = append(out, *s)
	}
	return out
}

// Stats is the shape the GET /stats verb returns.
type Stats struct {
	Size             int            `json:"size"`
	ByState          map[string]int `json:"byState"`
	RunnerTTLSeconds int            `json:"runnerTtlSeconds"`
	// SlotIDs are the orchestrator's own names for its slots.
	//
	// The api stores one of these in sessions.runner_id and passes it back as a
	// slotId to release and recycle, so it has to learn them rather than derive
	// them. Deriving them identically on both sides was considered and rejected: a
	// divergence — a renumbering, a sparse pool, an added state — would make the
	// api release a slot the orchestrator considers someone else's. That is not a
	// bookkeeping error, it is one session tearing down another's container while it
	// has an export in flight.
	//
	// Ids only, never container ids. §2.1 restricts the api from holding container
	// identities it cannot verify, and a slot name is not that: it is how the api
	// asks for a slot, not a handle it can address a container with.
	//
	// mac's review, and he put the alternative's failure mode better than I did.
	SlotIDs []string `json:"slotIds"`

	// FillError is why the last pool top-up failed, when it did. Absent when the
	// pool is healthy, so a consumer can tell "no fault" from "no information".
	//
	// The api turns this into the difference between "every session is busy" — wait
	// and it may clear — and "the control plane cannot start runners" — waiting is
	// pointless and an operator is needed. Both are 503; only one of them is true.
	//
	// A string rather than a code because there is no enumeration to agree on: the
	// cause is whatever the Engine said, and inventing a code for each would be a
	// vocabulary maintained on both sides of a boundary, which is how the three
	// silent failures in runner.go and index.ts happened.
	FillError string `json:"fillError,omitempty"`

	// FillFailures counts consecutive failed top-up attempts. Present so a consumer
	// can distinguish one blip from a pool that has been unable to fill for minutes,
	// which is the difference between retrying and escalating.
	FillFailures int `json:"fillFailures,omitempty"`
}

// Stats summarises the pool.
func (p *Pool) Stats() Stats {
	slots := p.Slots()
	byState := make(map[string]int, len(slots))
	ids := make([]string, 0, len(slots))
	for _, s := range slots {
		byState[string(s.State)]++
		ids = append(ids, s.ID)
	}
	// Sorted, so two calls against an unchanged pool produce byte-identical output.
	// An unstable order would make a diff of two /stats responses meaningless, and
	// would let the api's view churn for no reason.
	sort.Strings(ids)
	stats := Stats{
		Size:             len(slots),
		ByState:          byState,
		RunnerTTLSeconds: int(p.cfg.RunnerTTL.Seconds()),
		SlotIDs:          ids,
	}
	if fault := p.LastFillFault(); fault != nil {
		stats.FillError = fault.Error()
		stats.FillFailures = p.fillFailures()
	}
	return stats
}

// LastFillFault returns why the most recent pool top-up could not create a
// container, or nil if the last top-up succeeded or none has failed.
//
// ## Why this exists
//
// Found by deploying to a 1-CPU VPS, where every create failed with `Range of CPUs
// is from 0.01 to 1.00`. The pool stayed empty, and the api reported a login as
// **503 "every session is busy"** — which is the one thing it is definitely not.
// No slot would ever exist, so no amount of waiting would help, and PLAN-v3 §2.6
// is explicit that a caller must be told which of those two things it is.
//
// Nothing reported it. `/healthz` said `ok`, `/stats` said `size: 0`, every CI job
// passed, and the only evidence was an ERROR line in a container log nobody reads.
//
// So the pool carries the reason with it, and the api can name it. This does not
// make the pool healthy; it makes the fault visible to something that checks.
func (p *Pool) LastFillFault() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastFillErr
}

// fillFailures is how many consecutive top-up attempts have failed.
func (p *Pool) fillFailures() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fillFailureCount
}

// FillFailures is how many consecutive top-up attempts have failed. Exported for
// the server's error body, which reports it so a caller can tell one blip from a
// pool that has been unable to fill for minutes.
func (p *Pool) FillFailures() int { return p.fillFailures() }

// Claim takes an idle slot and binds it to a session.
//
// Returns ErrNoSlot when the pool is exhausted rather than queueing: the wait
// estimate the caller shows the user is computed from session rows in SQLite,
// and a queued claim here would hold a request open with no way to communicate
// when it would be satisfied.
func (p *Pool) Claim(ctx context.Context, sessionGUID string, sessionExpiresAt time.Time) (*Slot, error) {
	p.mu.Lock()
	idle := make([]*Slot, 0, len(p.slots))
	for _, s := range p.slots {
		if s.IsIdle() {
			idle = append(idle, s)
		}
	}
	p.mu.Unlock()

	if len(idle) == 0 {
		return nil, ErrNoSlot
	}

	p.randMu.Lock()
	slot := idle[p.rnd.Intn(len(idle))]
	p.randMu.Unlock()

	p.mu.Lock()
	// Re-check under the lock. Between the scan and here another claim could
	// have taken this slot; claiming it anyway would let two sessions share a
	// container, which is the one failure this pool must never have.
	if !slot.IsIdle() {
		p.mu.Unlock()
		return nil, ErrNoSlot
	}
	// Mark it bound before releasing the lock so a concurrent claim cannot pick
	// it. The state is provisional: if the container work below fails, p.fail()
	// puts the slot back to idle.
	slot.State = StateBound
	slot.SessionGUID = sessionGUID
	slot.BoundAt = p.now()
	slot.SessionExpiresAt = sessionExpiresAt
	idleContainerID := slot.ContainerID
	slotID := slot.ID
	p.mu.Unlock()

	// The idle container cannot be reused. Docker mounts are fixed at create
	// time, so a runner that must hold vault/<guid> is a different container
	// from one holding a tmpfs /data — and an idle container deliberately holds
	// only a tmpfs, because an idle runner should not have a credential-bearing
	// mount at all. Claim therefore replaces the container.
	//
	// This is also the right security shape rather than merely the necessary
	// one: the browser process tree that was idle is discarded, so no state
	// carries across into the session that is about to type a password.
	if err := p.destroy(ctx, idleContainerID); err != nil {
		p.fail(slot, idleContainerID)
		return nil, err
	}

	if err := p.createBound(ctx, slot, sessionGUID, sessionExpiresAt); err != nil {
		p.fail(slot, "")
		return nil, err
	}

	p.mu.Lock()
	out := *slot
	p.mu.Unlock()

	p.log.Info("claimed slot", "slot", slotID, "container", out.ContainerID,
		"session", sessionGUID, "replacedContainer", idleContainerID)
	return &out, nil
}

// fail returns a slot to idle after a failed container operation.
//
// The slot is dropped back to idle with no container rather than to its
// previous state: the previous container is gone, so a slot that claims to hold
// it would hand `api` an id that resolves to nothing. EnsurePool refills it on
// the next tick.
func (p *Pool) fail(slot *Slot, deadContainerID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if deadContainerID != "" {
		p.log.Error("claim: container operation failed, slot returned to pool",
			"slot", slot.ID, "container", deadContainerID)
	} else {
		p.log.Error("claim: container creation failed, slot returned to pool", "slot", slot.ID)
	}
	slot.State = StateIdle
	slot.ContainerID = ""
	slot.CreatedAt = time.Time{}
	slot.SessionGUID = ""
	slot.BoundAt = time.Time{}
	slot.SessionExpiresAt = time.Time{}
}

// Release unbinds a session and stops the container.
//
// The session volume is not touched: PLANNING/PLAN-v2.md §2.3 keeps the vault
// across a rebind so auth.json survives, and destroying it here would log the
// user out every time a slot is returned.
func (p *Pool) Release(ctx context.Context, slotID string) error {
	slot, err := p.lockedSlot(slotID)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if slot.State != StateBound && slot.State != StateIdle {
		p.mu.Unlock()
		return ErrNotBound
	}
	sessionGUID := slot.SessionGUID
	containerID := slot.ContainerID
	slot.State = StateDraining
	slot.SessionGUID = ""
	slot.BoundAt = time.Time{}
	slot.SessionExpiresAt = time.Time{}
	p.mu.Unlock()

	if err := p.destroy(ctx, containerID); err != nil {
		p.mu.Lock()
		slot.State = StateDead
		p.mu.Unlock()
		return err
	}

	// The container is not replaced here. Release ends a session's hold, and
	// re-creating a runner immediately would spin up a browser for a pool
	// position that may sit idle for the whole idle TTL. EnsurePool refills on
	// its next tick instead, which also keeps this verb's latency independent of
	// image pull time.
	//
	// The slot stays in the pool as StateStarting with no container, so its id
	// remains reserved: a claim that arrives before the refill waits for the
	// slot rather than creating a second runner for the same position.
	p.mu.Lock()
	slot.ContainerID = ""
	slot.CreatedAt = time.Time{}
	slot.State = StateStarting
	p.mu.Unlock()

	p.log.Info("released slot", "slot", slot.ID, "container", containerID, "session", sessionGUID)
	return nil
}

// Recycle replaces a bound container that has outlived the runner TTL.
//
// Distinct from Release: a session keeps its slot and its vault, but the
// browser process tree does not survive. This is the 5-minute budget from
// PLANNING/PLAN-v2.md §2.1.
func (p *Pool) Recycle(ctx context.Context, slotID, reason string) error {
	slot, err := p.lockedSlot(slotID)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if slot.State == StateDraining || slot.State == StateDead {
		p.mu.Unlock()
		return ErrNotBound
	}
	containerID := slot.ContainerID
	slot.State = StateDraining
	p.mu.Unlock()

	if err := p.destroy(ctx, containerID); err != nil {
		p.mu.Lock()
		slot.State = StateDead
		p.mu.Unlock()
		return err
	}

	// Re-created immediately, and re-bound to the same session: recycle is
	// synchronous from the caller's point of view, and leaving the slot empty
	// would make a session that was mid-export look interrupted.
	//
	// The vault is remounted, not recreated, so auth.json survives — which is
	// the whole reason recycle exists separately from release (PLAN-v2 §2.3).
	sessionGUID := slot.SessionGUID
	sessionExpiresAt := slot.SessionExpiresAt
	if err := p.createBound(ctx, slot, sessionGUID, sessionExpiresAt); err != nil {
		p.mu.Lock()
		slot.State = StateDead
		p.mu.Unlock()
		return fmt.Errorf("recycle: recreate: %w", err)
	}

	p.mu.Lock()
	slot.State = StateBound
	p.mu.Unlock()

	p.log.Info("recycled slot", "slot", slot.ID, "oldContainer", containerID,
		"newContainer", slot.ContainerID, "reason", reason)
	return nil
}

// Remove tears a slot down entirely: no container, not counted in pool size.
// Used by erase, where the session volume is destroyed too.
func (p *Pool) Remove(ctx context.Context, slotID string) error {
	slot, err := p.lockedSlot(slotID)
	if err != nil {
		return err
	}
	p.mu.Lock()
	containerID := slot.ContainerID
	slot.State = StateDraining
	p.mu.Unlock()

	if err := p.destroy(ctx, containerID); err != nil {
		p.mu.Lock()
		slot.State = StateDead
		p.mu.Unlock()
		return err
	}

	p.mu.Lock()
	delete(p.slots, slotID)
	p.mu.Unlock()

	p.log.Info("removed slot", "slot", slotID, "container", containerID)
	return nil
}

// EnsurePool tops the pool up to cfg.PoolSize, creating idle runners.
//
// Idempotent and safe to call on a timer. A slot that is starting and has not
// come up yet is left alone, so a slow image pull does not spawn duplicates on
// every tick.
func (p *Pool) EnsurePool(ctx context.Context) error {
	p.mu.Lock()
	need := p.cfg.PoolSize - len(p.slots)
	var created []*Slot
	for i := 0; i < need; i++ {
		slot := &Slot{
			ID:    fmt.Sprintf("slot-%d", nextSlotSeq),
			State: StateStarting,
		}
		nextSlotSeq++
		p.slots[slot.ID] = slot
		created = append(created, slot)
	}
	p.mu.Unlock()

	if need <= 0 {
		return nil
	}

	var firstErr error
	for _, slot := range created {
		if err := p.create(ctx, slot); err != nil {
			p.mu.Lock()
			delete(p.slots, slot.ID)
			p.mu.Unlock()
			p.log.Error("ensure pool: create failed", "slot", slot.ID, "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
	}

	// Record the outcome for Stats, and clear it on any success.
	//
	// A pool that cannot fill must be distinguishable from a pool that is merely
	// full, or the api tells a user to wait for a slot that will never exist. That
	// is not hypothetical: it is what a 1-CPU host did, silently, with healthz
	// reporting ok the whole time.
	p.mu.Lock()
	if firstErr != nil {
		p.lastFillErr = firstErr
		p.fillFailureCount++
	} else if p.fillFailureCount > 0 {
		p.log.Info("pool top-up recovered", "afterFailures", p.fillFailureCount)
		p.lastFillErr = nil
		p.fillFailureCount = 0
	}
	p.mu.Unlock()

	return firstErr
}

// Sweep applies the TTLs to idle and bound slots.
//
// Two independent clocks, from PLANNING/PLAN-v2.md §2.1:
//
//   - idle runners are removed after SlotIdleTimeout, releasing their memory
//     without touching a session row, because an idle container holds a
//     Chromium tree and no session.
//   - bound runners are recycled after RunnerTTL, which bounds how long one
//     browser process tree serves one session.
//
// The absolute session cap is not enforced here. `api` owns session expiry and
// calls Remove; the orchestrator not knowing when a session expires is why it
// cannot decide to erase one.
func (p *Pool) Sweep(ctx context.Context) error {
	now := p.now()

	for _, slot := range p.Slots() {
		switch slot.State {
		case StateIdle:
			if slot.CreatedAt.IsZero() {
				continue
			}
			if now.Sub(slot.CreatedAt) > p.cfg.SlotIdleTimeout {
				if err := p.Remove(ctx, slot.ID); err != nil && !errors.Is(err, ErrUnknownSlot) {
					p.log.Error("sweep: remove idle slot", "slot", slot.ID, "error", err)
				} else {
					p.log.Info("sweep: removed idle slot past TTL", "slot", slot.ID)
				}
			}
		case StateBound:
			if slot.CreatedAt.IsZero() {
				continue
			}
			if now.Sub(slot.CreatedAt) > p.cfg.RunnerTTL {
				if err := p.Recycle(ctx, slot.ID, "runner ttl"); err != nil && !errors.Is(err, ErrUnknownSlot) {
					p.log.Error("sweep: recycle bound slot", "slot", slot.ID, "error", err)
				}
			}
		}
	}
	return nil
}

// Reconcile compares the pool against the Docker daemon at boot.
//
// This is the orchestrator's half of boot reconciliation
// (PLANNING/PLAN-v2.md §2.5, restated for two reconcilers in PLAN-v3 §2.1).
// The orchestrator reconciles *containers*; `api` reconciles *sessions*;
// neither trusts the other's view alone.
//
// Rules, in order:
//
//   - A container carrying our labels is ours. Adopt it into the slot its
//     labels name, so a restart does not discard a logged-in session.
//   - A container of ours whose slot does not exist is an orphan. Remove it.
//   - A container whose session has already expired is an orphan, whatever its
//     state label claims. Never resurrect an expired session.
//   - A container past the runner TTL is recycled rather than adopted.
//
// `sessionExpired` is supplied by `api`'s view via the signed verb. It is a
// predicate, not data: the orchestrator does not learn session state, it is told
// whether a given GUID is still alive.
func (p *Pool) Reconcile(ctx context.Context, sessionExpired func(guid string) bool) error {
	ids, err := p.docker.ListContainersByLabel(ctx, labels.RunnerFilter)
	if err != nil {
		return fmt.Errorf("reconcile: list containers: %w", err)
	}

	p.mu.Lock()
	known := make(map[string]string, len(p.slots)) // container id -> slot id
	for id, s := range p.slots {
		if s.ContainerID != "" {
			known[s.ContainerID] = id
		}
	}
	p.mu.Unlock()

	for _, id := range ids {
		ctr, err := p.docker.InspectContainer(ctx, id)
		if err != nil {
			// A container that vanished between list and inspect is fine: the
			// only thing we could have wanted from it was to delete it.
			p.log.Warn("reconcile: inspect failed, skipping", "container", id, "error", err)
			continue
		}

		slotID := ctr.Labels[labels.SlotID]
		if slotID == "" {
			p.log.Warn("reconcile: runner without a slot label, removing",
				"container", id)
			if err := p.docker.RemoveContainer(ctx, id); err != nil {
				p.log.Error("reconcile: remove unlabelled runner", "container", id, "error", err)
			}
			continue
		}

		p.mu.Lock()
		slot, exists := p.slots[slotID]
		p.mu.Unlock()

		if !exists {
			p.log.Warn("reconcile: runner for unknown slot, removing",
				"container", id, "slot", slotID)
			if err := p.docker.RemoveContainer(ctx, id); err != nil {
				p.log.Error("reconcile: remove orphan runner", "container", id, "error", err)
			}
			continue
		}

		createdAt, err := labels.ReadCreatedAt(ctr.Labels)
		if err != nil {
			// Without a creation time the recycle budget cannot be computed.
			// Replacing the container is the only safe move: adopting it would
			// mean a container of unknown age with a 5-minute budget attached.
			p.log.Warn("reconcile: runner without a creation label, replacing",
				"container", id, "slot", slotID)
			if err := p.replace(ctx, slot, id); err != nil {
				p.log.Error("reconcile: replace unlabelled-age runner", "container", id, "error", err)
			}
			continue
		}

		guid, bound := labels.ReadSessionGUID(ctr.Labels)
		if bound && sessionExpired != nil && sessionExpired(guid) {
			// The session is gone. The container is an orphan. Its vault
			// belongs to the erase path, not to us.
			p.log.Info("reconcile: runner bound to an expired session, removing",
				"container", id, "slot", slotID, "session", guid)
			if err := p.docker.RemoveContainer(ctx, id); err != nil {
				p.log.Error("reconcile: remove expired runner", "container", id, "error", err)
			}
			p.mu.Lock()
			slot.State = StateDead
			slot.ContainerID = ""
			slot.SessionGUID = ""
			p.mu.Unlock()
			continue
		}

		// The runner TTL is enforced here as well as in Sweep. Sweep covers a
		// long-running process; this covers a host that was down, where the
		// container may be days old by the time anything looks at it. Adopting
		// an over-age container would attach a fresh 5-minute budget to a
		// browser process tree that has been running for days.
		if p.now().Sub(createdAt) > p.cfg.RunnerTTL {
			p.mu.Lock()
			slot.ContainerID = id
			slot.CreatedAt = createdAt
			slot.SessionGUID = guid
			slot.State = StateDraining
			if bound {
				// A missing or unparseable expiry leaves the slot with a zero
				// cap. That is the conservative direction: the orchestrator does
				// not decide session expiry, and `api` will rebind or erase on
				// its own view.
				if exp, err := labels.ReadExpires(ctr.Labels); err == nil {
					slot.SessionExpiresAt = exp
				}
			}
			p.mu.Unlock()

			p.log.Warn("reconcile: runner past its ttl, replacing",
				"container", id, "slot", slotID,
				"ageSeconds", int(p.now().Sub(createdAt).Seconds()))

			// replace() puts an idle runner in the slot, which is correct for an
			// unbound container. A bound one is handled by the caller's own
			// session state: the slot is marked draining, so the next claim or
			// sweep re-establishes it with the vault remounted.
			if err := p.replace(ctx, slot, id); err != nil {
				p.log.Error("reconcile: replace over-age runner", "container", id, "error", err)
			}
			continue
		}

		state := StateIdle
		if bound {
			state = StateBound
		}
		if !ctr.State.Running {
			// Adopt the identity but let EnsurePool replace a dead container.
			state = StateDead
		}

		p.mu.Lock()
		slot.ContainerID = id
		slot.CreatedAt = createdAt
		slot.SessionGUID = guid
		if bound {
			slot.BoundAt = createdAt
			if exp, err := labels.ReadExpires(ctr.Labels); err == nil {
				slot.SessionExpiresAt = exp
			}
		}
		slot.State = state
		p.mu.Unlock()

		p.log.Info("reconcile: adopted runner", "container", id, "slot", slotID, "state", state)
	}

	return nil
}

// Stat is the answer to the stat verb: whether an artifact exists and how big
// it is.
//
// This is the whole reason the orchestrator is a separate process from `api`
// (PLANNING/PLAN-v3.md §2.2). `api` needs to know if an artifact exists before
// authorising a download, but it must not have filesystem access to the
// artifact tree, because §2.2's split exists precisely so Caddy can hold a
// read-only artifact mount without also being able to read auth.json.
type Stat struct {
	Exists bool  `json:"exists"`
	Size   int64 `json:"size"`
}

// ArtifactStat reports on one artifact directory.
//
// artifactID has already been validated as 43 base64url characters by the
// caller, so the path built here contains no separators and cannot escape
// ArtifactRoot.
func (p *Pool) ArtifactStat(artifactID string) (Stat, error) {
	dir := filepath.Join(p.cfg.ArtifactRoot, artifactID)
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return Stat{Exists: false}, nil
		}
		return Stat{}, fmt.Errorf("stat %s: %w", artifactID, err)
	}
	if !info.IsDir() {
		// An artifact is a directory containing a finalised zip plus a partial
		// marker. A regular file where a directory is expected means something
		// is wrong that "exists: true" would hide.
		return Stat{Exists: false}, nil
	}
	return Stat{Exists: true, Size: dirSize(dir)}, nil
}

// dirSize sums the regular files under dir.
//
// os.ReadDir is used rather than filepath.WalkDir so a symlink cannot lead the
// sum out of the artifact tree. Depth is bounded so a pathological tree cannot
// turn a download authorisation into a long-running request.
func dirSize(dir string) int64 {
	var total int64
	var walk func(string, int)
	walk = func(current string, depth int) {
		if depth > 4 {
			return
		}
		entries, err := os.ReadDir(current)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.Type()&os.ModeSymlink != 0 {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.IsDir() {
				walk(filepath.Join(current, e.Name()), depth+1)
				continue
			}
			total += info.Size()
		}
	}
	walk(dir, 0)
	return total
}

// nextSlotSeq numbers slots so their ids are stable and readable in logs. It is
// not persisted: after a restart, slots are renumbered and adopted by label, so
// the id is a log handle rather than a durable identity.
var nextSlotSeq = 1

func (p *Pool) lockedSlot(id string) (*Slot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	slot, ok := p.slots[id]
	if !ok {
		return nil, ErrUnknownSlot
	}
	return slot, nil
}

// create makes an *idle* container for slot and starts it.
//
// Idle runners hold a tmpfs at /data and no vault mount: a container that is
// waiting for a session should not be one container away from holding a
// credential jar. EnsurePool is the only caller.
func (p *Pool) create(ctx context.Context, slot *Slot) error {
	return p.start(ctx, slot, "", time.Time{})
}

// createBound makes a container for slot carrying the session's vault mount.
// Claim and Recycle are the callers.
func (p *Pool) createBound(ctx context.Context, slot *Slot, sessionGUID string, sessionExpiresAt time.Time) error {
	return p.start(ctx, slot, sessionGUID, sessionExpiresAt)
}

// start creates and starts a container, then records it on the slot.
//
// The slot's identity is re-read under the lock inside start rather than passed
// in, because two verbs can be in flight for the same slot and the container id
// belongs to whichever finished last to take the lock — and the reconciler
// would then see a label naming a container that is not the current one.
func (p *Pool) start(ctx context.Context, slot *Slot, sessionGUID string, sessionExpiresAt time.Time) error {
	p.mu.Lock()
	slotID := slot.ID
	p.mu.Unlock()

	containerID := fmt.Sprintf("c-%s-%d", slotID, time.Now().UnixNano())
	req, err := p.buildCreateRequest(slotID, containerID, sessionGUID, sessionExpiresAt)
	if err != nil {
		return err
	}

	created, err := p.docker.CreateContainer(ctx, req, containerName(slotID, containerID))
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}
	if err := p.docker.StartContainer(ctx, created.ID); err != nil {
		// A created-but-unstarted container left behind would be adopted by the
		// next reconcile as a live runner that never ran.
		_ = p.docker.RemoveContainer(ctx, created.ID)
		return fmt.Errorf("start container: %w", err)
	}

	// Do not hand back a runner that is not yet listening.
	//
	// `StartContainer` returns as soon as the Engine accepts the start; the
	// process inside still has to start and bind its port. Found by attempting a
	// real login, where the api's credential POST arrived 579ms *before* the
	// runner's server began listening — so every login failed with a connection
	// refused that neither side could explain:
	//
	//     api      15:53:43.166  502 credential handoff failed
	//     runner   15:53:43.745  Server listening at http://172.30.0.2:3100
	//
	// Waiting here rather than in the api, because the api cannot tell "not ready
	// yet" from "wrong address": both are a connection failure, and retrying a
	// credential POST on that basis risks writing half a credential twice. The
	// orchestrator *can* tell, from the Engine's health state, and it is the
	// component that owns the container.
	//
	// The container is removed on failure so it is not adopted by the next
	// reconcile as a live runner that never became ready.
	if err := p.waitReady(ctx, created.ID); err != nil {
		_ = p.docker.RemoveContainer(ctx, created.ID)
		return err
	}

	p.mu.Lock()
	slot.ContainerID = created.ID
	slot.CreatedAt = p.now()
	// An idle container makes the slot idle. A bound one leaves the state to
	// the caller that claimed it, which already set it under the lock before
	// calling — overwriting it here would clear the provisional bind.
	if sessionGUID == "" {
		slot.State = StateIdle
	}
	p.mu.Unlock()
	return nil
}

// waitReady blocks until a container's healthcheck reports healthy, or gives up.
//
// Bounded, and it gives up for a *reason*:
//
//   - a container that stops running is not going to become ready, so it returns
//     at once with the exit code rather than burning the whole budget
//   - a container that is unhealthy and **not** improving is returned at once too,
//     rather than waiting out the retries the healthcheck itself is configured to
//     allow for
//
// The signal is the Engine's own health state rather than a port probe: the
// orchestrator is deliberately **not** on the runner network (§2.1 — it has no
// egress and no runner reachability, which is why the api holds the credential
// path), so it cannot connect to a runner to ask. It can read the healthcheck,
// because the Engine runs it.
//
// `Health.Status` empty means the container declares no healthcheck. That is
// treated as ready, because the create request always declares one and a container
// that somehow did not is not this function's to second-guess — but it is not
// treated as *healthy*, so the two cannot be confused in a log line.
func (p *Pool) waitReady(ctx context.Context, containerID string) error {
	deadline := time.Now().Add(p.cfg.RunnerReadyTimeout)
	// Short interval: the runner is usually ready in well under a second, and the
	// point of waiting is to shave the login's latency, not to add a fixed cost.
	const tick = 100 * time.Millisecond

	for {
		ctr, err := p.docker.InspectContainer(ctx, containerID)
		if err != nil {
			return fmt.Errorf("inspect runner: %w", err)
		}

		if !ctr.State.Running {
			return fmt.Errorf(
				"runner exited before it was ready: status=%q exit=%d",
				ctr.State.Status, ctr.State.ExitCode)
		}

		switch ctr.State.Health.Status {
		case "healthy":
			return nil
		case "":
			// No healthcheck declared. See the comment: ready, but not "healthy".
			return nil
		case "unhealthy":
			// The healthcheck's own `Retries` decides what "still starting" means,
			// so exceeding them means the runner is not coming.
			if ctr.State.Health.FailingStreak >= p.cfg.RunnerUnhealthyRetries {
				return fmt.Errorf(
					"runner never became healthy: %d consecutive failed healthchecks",
					ctr.State.Health.FailingStreak)
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf(
				"runner did not become ready within %s (health %q)",
				p.cfg.RunnerReadyTimeout, ctr.State.Health.Status)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(tick):
		}
	}
}

// replace removes an old container and puts a fresh one in the slot.
func (p *Pool) replace(ctx context.Context, slot *Slot, oldContainerID string) error {
	if err := p.docker.RemoveContainer(ctx, oldContainerID); err != nil {
		return fmt.Errorf("replace: remove old: %w", err)
	}
	p.mu.Lock()
	slot.ContainerID = ""
	slot.State = StateStarting
	p.mu.Unlock()
	return p.create(ctx, slot)
}

// destroy stops and removes a container. An empty id is a no-op, which is what
// lets a verb that may or may not have a container call it unconditionally.
func (p *Pool) destroy(ctx context.Context, containerID string) error {
	if containerID == "" {
		return nil
	}
	// 10s grace for Chromium to exit cleanly before the daemon escalates to
	// SIGKILL. A runner that cannot be killed would otherwise wedge release and
	// leave the slot draining for the life of the process.
	if err := p.docker.StopContainer(ctx, containerID, 10); err != nil {
		p.log.Warn("stop container failed, removing anyway", "container", containerID, "error", err)
	}
	if err := p.docker.RemoveContainer(ctx, containerID); err != nil {
		return fmt.Errorf("remove container %s: %w", containerID, err)
	}
	return nil
}

// containerName builds the Engine-visible name. Derived from the two ids, both
// of which the orchestrator generated, so it satisfies the Engine's
// ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ requirement without any sanitising of input.
func containerName(slotID, containerID string) string {
	return "msout-" + slotID + "-" + containerID
}

// runnerAlias is the DNS name `api` dials a runner by, on the control network.
//
// Derived from the slot id alone, deliberately — that is the whole reason to
// prefer it over the container IP.
//
// `recycle` replaces a slot's container without changing the slot, so a stored
// IP would silently start pointing at a dead container the moment a runner aged
// out. Every symptom of that is wrong: the api reports a transport failure,
// the orchestrator reports a healthy pool, and nothing says the address is
// stale. A name tied to the slot survives, so the api's stored address stays
// correct across every recycle, and `claim` can return it once.
//
// The "msout-runner-" prefix keeps it distinct from a container name, which
// carries a container id as well. Both are lowercase alphanumerics with dashes,
// as Docker's DNS requires.
func runnerAlias(slotID string) string {
	return "msout-runner-" + slotID
}

// RunnerURL is where `api` reaches the container in a slot, on the control
// network.
//
// It is a name rather than a resolved address on purpose, and it is assembled
// only from values this component generated — the slot id and a deploy-time
// port. No request field reaches it, so this is not a caller-controlled URL
// even though the api dereferences it: the api is not a browser, and it is the
// only thing that can hold a credential stream.
func (p *Pool) RunnerURL(slotID string) string {
	if strings.TrimSpace(slotID) == "" {
		return ""
	}
	return fmt.Sprintf("http://%s:%d", runnerAlias(slotID), p.cfg.RunnerPort)
}
