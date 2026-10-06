package pool

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/dockerapi"
	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/labels"
)

// errInvalidGUID rejects a session id that is not a UUID before it is ever
// joined to a host path.
//
// This is the control that keeps a caller from escaping VaultRoot. A path
// sanitiser would be the wrong shape: "reject anything that is not exactly a
// UUID" is a smaller and more obviously complete rule than "strip the bad
// characters".
var errInvalidGUID = errors.New("pool: invalid session guid")

// buildCreateRequest assembles a runner create request.
//
// This is the "runner argv is built from a template in this component's own
// code" rule from PLANNING/PLAN-v3.md §2.1, made literal. Nothing here is
// derived from a request: the only caller-influenced value is the session GUID,
// and it appears solely as a validated label value and a bind-mount source.
//
// The flag set is PLAN-v2 §5.1 verbatim, with the rationale for each
// non-obvious flag carried in the comment.
func (p *Pool) buildCreateRequest(slotID, containerID, sessionGUID string, sessionExpiresAt time.Time) (dockerapi.CreateRequest, error) {
	init := true
	readOnly := true
	autoRemove := false
	pidsLimit := int64(512)
	stopTimeout := 10

	lbl := labels.Base(slotID, containerID, p.cfg.RunnerImage)

	var mounts []dockerapi.CreateMount
	if sessionGUID == "" {
		// An idle runner holds no session volume. Mounting one speculatively
		// would put a vault directory into every idle container and make an
		// idle slot a credential-bearing container, which is the opposite of
		// what an idle TTL is for.
		mounts = []dockerapi.CreateMount{
			{Type: "tmpfs", Source: "", Destination: "/data"},
		}
	} else {
		bound, err := p.bindSession(sessionGUID)
		if err != nil {
			return dockerapi.CreateRequest{}, err
		}
		lbl = mergeLabels(lbl, labels.Bind(sessionGUID, sessionExpiresAt))
		mounts = bound
	}

	req := dockerapi.CreateRequest{
		Image:  p.cfg.RunnerImage,
		Labels: lbl,
		User:   "node",
		HostConfig: dockerapi.CreateHostConfig{
			NetworkMode:    p.cfg.RunnerNetwork,
			Init:           &init,
			ReadonlyRootfs: &readOnly,
			// Chromium crashes on Docker's 64MB /dev/shm default. This is the
			// single most load-bearing flag in the list (PLAN-v2 §5.1).
			ShmSize: 1 << 30,
			Memory:  2560 << 20,
			// MemorySwap pinned equal to Memory so a runaway cannot silently
			// swap. It gets OOM-killed instead, which is a visible failure
			// rather than a slow one.
			MemorySwap:  2560 << 20,
			NanoCpus:    2e9,
			PidsLimit:   &pidsLimit,
			CapDrop:     []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges"},
			// The writable set under a read-only rootfs, and nothing else.
			// noexec+nosuid because nothing legitimate executes from either.
			Tmpfs: map[string]string{
				"/tmp":              "rw,noexec,nosuid,size=512m,uid=1000,gid=1000",
				"/home/node/.cache": "rw,noexec,nosuid,size=512m,uid=1000,gid=1000",
			},
			// A runner that exits must come back through reconcile, not
			// through the daemon's restart policy: a self-restarting runner
			// silently re-acquires its vault mount.
			RestartPolicy: dockerapi.RestartPolicy{Name: "no"},
			AutoRemove:    &autoRemove,
			LogConfig: dockerapi.LogConfig{
				Type: "json-file",
				Config: map[string]string{
					"max-size": "10m",
					"max-file": "3",
				},
			},
		},
		StopConfig: &dockerapi.StopContainerConfig{Timeout: &stopTimeout},
		HealthConfig: &dockerapi.HealthConfig{
			Test: []string{"CMD", "node", "/app/dist/healthcheck.js"},
			// The Engine takes these as nanoseconds.
			Interval:    (15 * time.Second).Nanoseconds(),
			Timeout:     (5 * time.Second).Nanoseconds(),
			Retries:     3,
			StartPeriod: (20 * time.Second).Nanoseconds(),
		},
		// One network, pinned. The runner is not on msout-control, so it cannot
		// reach the orchestrator or `api`, and it holds no route to the Docker
		// socket because the socket is not mounted into it (PLAN-v3 §2.1).
		Networking: &dockerapi.NetworkingConfig{
			EndpointsConfig: map[string]*dockerapi.EndpointConfig{
				p.cfg.RunnerNetwork: {},
			},
		},
		Env: []string{
			// Every @msout package log and HTML dump lands inside the session
			// directory and dies with it on erase (PLAN-v2 §5.6).
			"ONENOTE_EXPORT_LOG_DIR=/data/logs",
		},
		Mounts: mounts,
	}

	return req, nil
}

// bindSession returns the mounts a bound runner carries: one bind mount of the
// session's vault directory at /data, rw.
//
// `api` and Caddy hold neither this mount nor the artifact tree as writable.
// That is the vault/artifact split (PLANNING/PLAN-v3.md §2.2): the credential
// bytes live in this mount, and no browser-reachable component can read it.
func (p *Pool) bindSession(sessionGUID string) ([]dockerapi.CreateMount, error) {
	if !config.ValidGUID(sessionGUID) {
		return nil, errInvalidGUID
	}
	vault := filepath.Join(p.cfg.VaultRoot, sessionGUID)
	// 0700: this directory will hold auth.json, a live Microsoft cookie jar.
	// MkdirAll applies the process umask, so the mode is re-applied explicitly
	// afterwards — a vault that came out 0755 under a permissive umask is a
	// real leak, not a cosmetic one.
	if err := os.MkdirAll(vault, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(vault, 0o700); err != nil {
		return nil, err
	}
	return []dockerapi.CreateMount{
		{Type: "bind", Source: vault, Destination: "/data", ReadOnly: false},
	}, nil
}

// mergeLabels overlays add onto base, returning a new map.
//
// Not mutating base matters: labels.Base is also used for the idle case, and a
// bind label leaking into an idle runner would make reconciliation believe it
// is serving a session.
func mergeLabels(base, add map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(add))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range add {
		out[k] = v
	}
	return out
}
