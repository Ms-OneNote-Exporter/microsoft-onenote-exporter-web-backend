// Package labels holds the container label vocabulary used for boot
// reconciliation and inspection.
//
// Docker labels are recovery, inspection and boot-reconciliation metadata only
// (PLANNING/PLAN-v2.md §2.4). They are never the lock: the authoritative slot
// state lives in SQLite, and a runner that claims to be idle here while SQLite
// says otherwise is a reconciler problem, not a state transfer.
package labels

import (
	"errors"
	"strconv"
	"time"
)

const (
	// Role marks a container as ours. Every reconciliation query filters on it,
	// so a container we did not create is never adopted or removed.
	Role = "msout.role"

	// RoleRunner is the only value of Role we act on.
	RoleRunner = "runner"

	// SlotID is the stable identity of a pool slot, assigned at startup and
	// carried by every container that slot has ever created. It is how a
	// replacement container is recognised as belonging to the same slot.
	SlotID = "msout.slot.id"

	// ContainerID distinguishes containers within a slot, so a reconciler can
	// tell the current one from a predecessor it replaced.
	ContainerID = "msout.container.id"

	// SessionGUID is the session this runner is currently bound to. Empty when
	// the runner is idle. Labels are never the lock — see the package comment —
	// so this is informational, used to decide whether a container can be
	// recycled without waiting out its TTL.
	SessionGUID = "msout.session.guid"

	// Expires is the absolute Unix-ms expiry of the bound session. A container
	// past this is an orphan by definition, whatever its state label says.
	Expires = "msout.expires"

	// CreatedAt is the Unix-ms creation time of the container, which is what
	// the 5-minute recycle budget is measured from.
	CreatedAt = "msout.created_at"

	// Component is a free-form owner tag ("runner", "orchestrator"), present so
	// an operator listing containers by label can tell them apart.
	Component = "msout.component"

	// Image records the image a container was created from. Not read back for
	// any decision — the configured image is authoritative and a label that
	// disagreed with it would be an attack surface, not a feature. It exists
	// so `docker ps` shows which build a runner is running.
	Image = "msout.image"
)

// Base returns the label set every runner container carries.
//
// Slot and container identity are included because reconciliation cannot
// identify a runner without them, and the session fields are deliberately
// absent: a fresh container has no session, and writing empty strings would
// make "unbound" indistinguishable from "label missing".
func Base(slotID, containerID, image string) map[string]string {
	return map[string]string{
		Role:        RoleRunner,
		Component:   "runner",
		SlotID:      slotID,
		ContainerID: containerID,
		Image:       image,
		CreatedAt:   strconv.FormatInt(time.Now().UnixMilli(), 10),
	}
}

// Bind returns the labels added when a slot is bound to a session.
func Bind(sessionGUID string, expiresAt time.Time) map[string]string {
	return map[string]string{
		SessionGUID: sessionGUID,
		Expires:     strconv.FormatInt(expiresAt.UnixMilli(), 10),
	}
}

// ReadCreatedAt reads the creation timestamp from a label set.
//
// A missing or unparseable value is an error rather than a default: the recycle
// budget depends on it, and treating an unknown creation time as "now" would
// keep an ancient container alive forever.
//
// Named ReadCreatedAt rather than CreatedAt because the package constant of that
// name is the label key, and a function shadowing its own key is a readability
// cost in every call site.
func ReadCreatedAt(labels map[string]string) (time.Time, error) {
	raw, ok := labels[CreatedAt]
	if !ok {
		return time.Time{}, errors.New("labels: missing " + CreatedAt)
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("labels: unparseable " + CreatedAt)
	}
	return time.UnixMilli(ms), nil
}

// ReadExpires reads the session expiry from a label set.
func ReadExpires(labels map[string]string) (time.Time, error) {
	raw, ok := labels[Expires]
	if !ok {
		return time.Time{}, errors.New("labels: missing " + Expires)
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("labels: unparseable " + Expires)
	}
	return time.UnixMilli(ms), nil
}

// ReadSessionGUID reads the bound session from a label set, reporting false when
// the runner is unbound.
func ReadSessionGUID(labels map[string]string) (string, bool) {
	v, ok := labels[SessionGUID]
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// RunnerFilter selects our runner containers, as the Engine's own filter syntax —
// `label=<key>=<value>`. It is what `Daemon.ListContainersByLabel` is given.
//
// It is **not** a bare `key=value`, and the difference is load-bearing. The two
// conventions collided the first time this path worked: the filter was declared
// `"label=msout.role=runner"` and the client encoded it a second time, producing
//
//	{"label":["label=msout.role=runner"]}
//
// which selects a label *named* `label` whose value is `msout.role=runner`. No
// container has that, so reconciliation silently adopted nothing and removed nothing
// while reporting `boot reconciliation complete`.
//
// Two ways this could be resolved, and which was chosen:
//   - strip `label=` here and let the client do the encoding, so the constant is a
//     bare `key=value` and the parameter means what its name says
//   - keep the Engine syntax and have the client detect a leading `label=`
//
// The second was rejected: a value that means one thing to its caller and another to
// the thing it is passed to is the same class of bug as a container path used as a
// bind source. `ListContainersByLabel` takes a **label** and encodes it, and the
// encoding is asserted in `list_test.go`.
const RunnerFilter = Role + "=" + RoleRunner
