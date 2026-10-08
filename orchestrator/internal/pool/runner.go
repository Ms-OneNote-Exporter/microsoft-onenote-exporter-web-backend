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

	// The artifact mount is unconditional, bound or not.
	//
	// The runner streams a finished vault into its artifact directory, and the
	// root filesystem is read-only — so without this mount the archive has
	// nowhere to go and every export fails at the last step, after all the work
	// of doing it. It is the same directory `ArtifactStat` reads and the same one
	// Caddy is given read-only, so the staged file and the published one cannot
	// drift apart.
	//
	// An idle runner gets it too, and holding an empty artifact directory is not
	// a capability: the vault bind is what makes a container credential-bearing,
	// and that is still only added on bind.
	artifactMount := dockerapi.CreateMount{
		Type:        "bind",
		Source:      p.cfg.ArtifactRoot,
		Destination: "/artifacts",
		ReadOnly:    false,
	}

	// The bearer token, mounted from the orchestrator's own secret file.
	//
	// Read-only, and named for what it is: a token that lets this orchestrator
	// authenticate to a container it created. It never carries or reveals a
	// session credential, so it is not the §2.1 prohibition on secrets — but it is
	// still a file rather than an env var, for the reason given on the Env entry.
	tokenMount := dockerapi.CreateMount{
		Type:        "bind",
		Source:      p.cfg.RunnerTokenFile,
		Destination: "/run/secrets/runner_token",
		ReadOnly:    true,
	}

	var mounts []dockerapi.CreateMount
	if sessionGUID == "" {
		// An idle runner holds no session volume. Mounting one speculatively
		// would put a vault directory into every idle container and make an
		// idle slot a credential-bearing container, which is the opposite of
		// what an idle TTL is for.
		mounts = []dockerapi.CreateMount{
			{Type: "tmpfs", Source: "", Destination: "/data"},
			artifactMount,
			tokenMount,
		}
	} else {
		bound, err := p.bindSession(sessionGUID)
		if err != nil {
			return dockerapi.CreateRequest{}, err
		}
		lbl = mergeLabels(lbl, labels.Bind(sessionGUID, sessionExpiresAt))
		mounts = append(bound, artifactMount, tokenMount)
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
			MemorySwap: 2560 << 20,
			// Deploy-time, not a constant. See config.RunnerNanoCpus: a hardcoded
			// 2e9 made this component refuse to create any container at all on a
			// host with fewer than two cores, so the pool stayed permanently empty
			// and the api reported the result as "every session is busy".
			NanoCpus:    p.cfg.RunnerNanoCpus,
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
			//
			// **Short, on purpose, because the claim path waits on this.** The
			// orchestrator returns from `claim` only once the runner reports
			// healthy, so these values are login latency rather than background
			// cost: with a 20s start period and a 15s interval, a login would wait
			// up to 35 seconds for a runner that is actually listening in ~600ms.
			//
			// 3s is still far more often than a runner needs. The cost of a short
			// interval is a `/healthz` request every few seconds per runner, on a
			// loopback socket, from a process that is idle anyway.
			Interval: (3 * time.Second).Nanoseconds(),
			Timeout:  (5 * time.Second).Nanoseconds(),
			Retries:  3,
			// Equal to the interval, which is the floor the contract test requires.
			// A runner's own HTTP sidecar binds in ~600ms — measured on a real host —
			// so 3s is ample; `Retries: 3` then leaves ~9s of grace before the Engine
			// will call it unhealthy at all.
			//
			// Note this healthcheck probes `/healthz`, which does **not** launch
			// Chromium. Chromium starts per login, inside the runner process, and is
			// gated by that request's own timeout rather than by this period.
			StartPeriod: (3 * time.Second).Nanoseconds(),
		},
		// Two networks, both pinned, and what each one is for is the whole
		// topology:
		//
		//   RunnerControlNetwork — internal, and `api` is its only other
		//     member. This is the credential path: `api` posts the password here.
		//     Internal means no default route, so joining it cannot give `api`
		//     egress (PLAN-v3 §2.1). `api` is NOT on msout-control and the
		//     orchestrator is NOT here, so the component holding the Docker
		//     socket is one hop away from the credential rather than on it.
		//
		//   RunnerNetwork — egress to Microsoft, and `api` is deliberately not
		//     on it. That is the constraint the first network exists to satisfy.
		//
		// The alias is what makes the address stable: it is derived from the
		// slot id, so it survives `recycle` replacing the container, whereas a
		// container IP would not. See RunnerURL.
		//
		// Neither network name comes from a request. `RunnerURL` is derived
		// from the slot id the orchestrator generated, and the ip is nil because
		// a static address would let a caller-predictable value become a mount
		// target — the same argument EndpointConfig already records.
		Networking: &dockerapi.NetworkingConfig{
			EndpointsConfig: map[string]*dockerapi.EndpointConfig{
				p.cfg.RunnerControlNetwork: {Aliases: []string{runnerAlias(slotID)}},
				p.cfg.RunnerNetwork:        {},
			},
		},
		Env: []string{
			// Every @msout package log and HTML dump lands inside the session
			// directory and dies with it on erase (PLAN-v2 §5.6).
			"ONENOTE_EXPORT_LOG_DIR=/data/logs",
			// Where the token the orchestrator presents lives. A *path*, never the
			// value: an env var is visible in `docker inspect` and in
			// `/proc/<pid>/environ` to anything that can read the container's
			// config, including a container that has no business knowing it.
			//
			// The runner refuses to start without this. That is deliberate on its
			// side — a default token would accept requests from anything that can
			// reach the container, and this process holds credential bytes — and it
			// means the mount below is not optional. See runner/tests/contract.test.ts,
			// which is what caught this being absent.
			"MSOUT_RUNNER_TOKEN_FILE=/run/secrets/runner_token",
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
