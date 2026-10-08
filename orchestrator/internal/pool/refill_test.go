package pool

// A released slot must come back.
//
// ## Why this file exists
//
// Found on a real host, after a single login: the pool reported
//
//     {"size":1,"byState":{"starting":1}}
//
// for four minutes with no top-up activity at all, and the next login answered
// `503 every session is busy`. `size: 1` is true — one slot — and there was no
// container behind it, so no login could ever use it.
//
// `Release` deliberately leaves the slot in the map so its id stays reserved: `api`
// may still hold that id in `sessions.runner_id`. It set the slot to `StateStarting`
// and its comment said "EnsurePool refills on its next tick".
//
// `EnsurePool` decided what to fill by counting **slots**:
//
//     need := p.cfg.PoolSize - len(p.slots)
//
// The released slot was still in the map, so `need` was 0 and nothing refilled it.
// **Every release shrank the pool by one, permanently.** After `PoolSize` logins the
// pool was empty while reporting a size of `PoolSize`.
//
// So the bug is not "the refill failed" — it is that the refill was never requested,
// and the state that was supposed to request it did not mean "no container".

import (
	"context"
	"testing"
	"time"
)

// `TestEnsurePoolRefillsAfterRelease` in pool_test.go covers one release/refill cycle
// and carries the history of how it got that name. The cases here are the ones it does
// not: that it *keeps* working, that it keeps the slot's identity, and that a failed
// refill is retried rather than abandoned.
//
// claimAndRelease takes a slot and gives it back, which is the sequence a real login
// followed by a TTL expiry produces.
func claimAndRelease(t *testing.T, p *Pool, guid string) {
	t.Helper()
	claimed, err := p.Claim(context.Background(), guid, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("claim for %s: %v", guid, err)
	}
	if err := p.Release(context.Background(), claimed.ID); err != nil {
		t.Fatalf("release for %s: %v", guid, err)
	}
}

// Repeated, because the failure mode is cumulative and a single cycle looks fine.
func TestThePoolDoesNotShrinkAcrossManyLogins(t *testing.T) {
	cfg := testConfig(t, 2)
	p := New(cfg, newFakeDaemon(), nil)

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("initial EnsurePool: %v", err)
	}

	for i := 0; i < 6; i++ {
		claimAndRelease(t, p, "22222222-2222-4222-8222-22222222222"+string(rune('0'+i)))
		if err := p.EnsurePool(t.Context()); err != nil {
			t.Fatalf("EnsurePool after login %d: %v", i, err)
		}
		if idle := p.Stats().ByState[string(StateIdle)]; idle != 2 {
			t.Fatalf("after %d logins idle = %d, want 2 — the pool shrinks by one per "+
				"release and never recovers", i+1, idle)
		}
	}
}

// The slot's **id** must survive a release-and-refill, because `api` holds it.
//
// A refill that created a fresh slot instead of reusing the released one would look
// correct by size — `size` would be right — while `sessions.runner_id` pointed at a
// slot id that no longer exists, and the next `release` for that session would answer
// 409 for a session that is still live.
func TestARefilledSlotKeepsItsId(t *testing.T) {
	cfg := testConfig(t, 1)
	d := newFakeDaemon()
	p := New(cfg, d, nil)

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("initial EnsurePool: %v", err)
	}
	before := slotIDsOf(p)

	claimAndRelease(t, p, "33333333-3333-4333-8333-333333333333")
	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("refill: %v", err)
	}
	after := slotIDsOf(p)

	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("slot count changed: %v -> %v", before, after)
	}
	if before[0] != after[0] {
		t.Errorf("slot id changed across a release and refill: %q -> %q. `api` holds "+
			"this id in sessions.runner_id, so a change strands that session against a "+
			"slot that no longer exists", before[0], after[0])
	}
}

// A create that keeps failing must leave the slot reserved rather than deleting it,
// for the same reason — and it must be retried rather than abandoned.
func TestAFailedRefillKeepsTheSlotReservedAndRetries(t *testing.T) {
	cfg := testConfig(t, 1)
	d := newFakeDaemon()
	p := New(cfg, d, nil)

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("initial EnsurePool: %v", err)
	}
	original := slotIDsOf(p)[0]

	claimAndRelease(t, p, "44444444-4444-4444-8444-444444444444")

	// The refill fails. The slot must still exist, under the same id.
	d.failNext("create", cpuRangeErr())
	if err := p.EnsurePool(t.Context()); err == nil {
		t.Fatal("EnsurePool succeeded against a daemon that fails every create")
	}
	if got := slotIDsOf(p); len(got) != 1 || got[0] != original {
		t.Fatalf("slots = %v after a failed refill, want [%s]. A reserved slot must "+
			"survive a failed refill: `api` still holds its id, and deleting it would "+
			"strand that session", got, original)
	}

	// And the next tick must actually retry it, rather than finding `need == 0`.
	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("retry after a failed refill: %v", err)
	}
	if idle := p.Stats().ByState[string(StateIdle)]; idle != 1 {
		t.Errorf("idle = %d after the retry, want 1; a slot abandoned in `vacant` is "+
			"never retried and the pool never recovers: %+v", idle, p.Stats().ByState)
	}
}

// A vacant slot is not idle and must not be counted as available. The api asks
// `/stats` to tell "busy" from "cannot fill", and a slot with no container is
// neither.
func TestAVacantSlotIsNotReportedIdle(t *testing.T) {
	cfg := testConfig(t, 1)
	p := New(cfg, newFakeDaemon(), nil)

	if err := p.EnsurePool(t.Context()); err != nil {
		t.Fatalf("initial EnsurePool: %v", err)
	}
	claimed, err := p.Claim(t.Context(), "55555555-5555-4555-8555-555555555555", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Release leaves the slot reserved with no container, so the reported state can
	// be inspected without EnsurePool having refilled it yet.
	if err := p.Release(t.Context(), claimed.ID); err != nil {
		t.Fatalf("release: %v", err)
	}

	stats := p.Stats()
	if idle := stats.ByState[string(StateIdle)]; idle != 0 {
		t.Errorf("idle = %d with a vacant slot, want 0", idle)
	}
	if stats.ByState[string(StateVacant)] != 1 {
		t.Errorf("byState = %+v, want one vacant slot; the api has to be able to see "+
			"that a slot exists but cannot be claimed", stats.ByState)
	}
}

func slotIDsOf(p *Pool) []string {
	stats := p.Stats()
	return append([]string(nil), stats.SlotIDs...)
}
