// Package config loads and validates the orchestrator's configuration.
//
// Every rule here is fail-closed: a malformed value stops the process rather
// than falling back to something permissive. That is a stated design property
// (PLANNING/PLAN-v3.md §3.3 for the api, and the same reasoning applied to the
// orchestrator in §2.1), and it is what makes a bad deployment loud instead of
// quietly open.
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrMissingSecret is returned when the HMAC secret file is absent or empty.
//
// This is deliberately fatal. The orchestrator can create containers; serving
// it unauthenticated because a secret failed to mount is the worst outcome
// available, so there is no open-access fallback and no default secret
// (PLANNING/PLAN-v3.md §2.1, test T-I6).
var ErrMissingSecret = errors.New("orchestrator: HMAC secret is absent or empty")

// Config is the orchestrator's full runtime configuration.
//
// Note what is *not* here: there is no field a caller can influence. Every
// value comes from this process's own environment or from its own baked-in
// template. That is the structural half of "no endpoint accepts a command,
// image, flag, mount, network or path from a caller" (T-X3); the other half is
// that the HTTP layer never reads these from a request.
type Config struct {
	// Listen is the bind address for the HTTP surface. It is never published
	// to the host: the compose service sits on an internal: true network with
	// no ports (T-X2).
	Listen string

	// DockerSocket is the path to the Docker Engine socket.
	DockerSocket string

	// HMACSecret is the shared secret for api -> orchestrator calls. It is
	// read from a file, normally a Docker secret mount, because an env var is
	// visible in `docker inspect` and to anything that can read the process
	// environment.
	HMACSecret []byte

	// ReplayWindow bounds the accepted clock skew on signed calls.
	ReplayWindow time.Duration

	// VaultRoot and ArtifactRoot are the host paths. The orchestrator mounts
	// them into runners; it is the only component that can read the vault at
	// all (PLANNING/PLAN-v3.md §2.1, §2.2).
	VaultRoot    string
	ArtifactRoot string

	// RunnerImage is fixed at deploy time. No request field can change it.
	RunnerImage string

	// RunnerNetwork is the restricted-egress network name. Fixed, and the
	// orchestrator is not a member of it (T-X2).
	RunnerNetwork string

	// RunnerControlNetwork is the second network a runner joins: an
	// `internal: true` one whose only other member is `api`.
	//
	// It exists because the credential has to reach a runner and neither
	// existing network could carry it. `msout-runner` has egress, so putting
	// `api` on it would give the browser-facing component a route to the
	// internet — the thing PLAN-v3 §2.1 forbids. `msout-control` is the
	// orchestrator's, and the runner joining it would put the credential path
	// one hop from the only process holding the Docker socket.
	//
	// So a third network, internal, with exactly two members. `api` gains a
	// route to a runner's HTTP port and nothing else; the runner gains a route
	// to `api` and no egress it did not have.
	RunnerControlNetwork string

	// RunnerPort is the port the runner's HTTP API listens on, and the port
	// RunnerURL embeds. Fixed at deploy time like every other runner
	// property: no request field can change it.
	RunnerPort int

	// RunnerNanoCpus is the CPU allowance in a runner's create request, in
	// billionths of a CPU — 2e9 is two cores, matching POC §18.
	//
	// Configurable because a hardcoded 2 made this component **undeployable** on a
	// host with fewer than two cores: the Engine rejects the whole create request
	// with `Range of CPUs is from 0.01 to 1.00, as there are only N CPUs
	// available`, so every slot fails to fill and the pool stays empty. That was
	// found by deploying to a 1-CPU VPS, not by reading the code.
	//
	// It stays deploy-time config rather than being clamped to the host's CPU
	// count, for the reason everything else here is: a value this component
	// silently rewrites is a misconfiguration nobody is told about. If it is wrong
	// the create fails loudly, which is the right failure for a capacity setting.
	RunnerNanoCpus int64

	// RunnerTokenFile is the host path of the bearer token each runner mounts
	// read-only, and which it requires in order to start.
	//
	// A path, never a value, for the reason every other secret in this stack is a
	// file: an env var is visible in `docker inspect` and in `/proc/<pid>/environ`.
	// The runner refuses to boot without it, so this is not optional — see
	// runner/tests/contract.test.ts.
	RunnerTokenFile string

	// PoolSize is how many runners exist when idle.
	PoolSize int

	// RunnerTTL is the 5-minute recycle budget from PLANNING/PLAN-v2.md §2.1.
	RunnerTTL time.Duration

	// SlotIdleTimeout is how long an idle runner is kept before removal.
	SlotIdleTimeout time.Duration

	// RequestTimeout bounds a single Docker Engine API call.
	RequestTimeout time.Duration

	// ShutdownGrace is how long in-flight requests get on SIGTERM.
	ShutdownGrace time.Duration
}

// guidPattern is the session identifier format. The orchestrator builds host
// paths from it, so it must be a closed character class with no separators.
// Without this, a caller-supplied guid containing "../" would escape
// VaultRoot. Validating the identifier is cheaper and more obvious than
// sanitising the path afterwards.
var guidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ArtifactIDPattern is the opaque artifact identifier: 32 random bytes,
// base64url, exactly 43 characters.
//
// This is the same width and alphabet as the session secret, and for the same
// reason: it appears in a download URL, so it must not be guessable and must
// not encode anything. No GUID and no notebook name (PLANNING/PLAN-v3.md §5).
var ArtifactIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ValidGUID reports whether s is a well-formed session GUID.
func ValidGUID(s string) bool { return guidPattern.MatchString(s) }

// ValidArtifactID reports whether s is a well-formed artifact id.
func ValidArtifactID(s string) bool { return ArtifactIDPattern.MatchString(s) }

// Load reads configuration from the environment and returns it, or an error
// describing the first fatal problem.
//
// The returned error is intentionally specific. "refuses to start" is only
// useful during an incident if the operator can tell which variable is wrong.
func Load(getenv func(string) string, readFile func(string) ([]byte, error)) (*Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if readFile == nil {
		readFile = os.ReadFile
	}

	cfg := &Config{
		Listen:        envOr(getenv, "ORCH_LISTEN", ":9100"),
		DockerSocket:  envOr(getenv, "ORCH_DOCKER_SOCKET", "/var/run/docker.sock"),
		ReplayWindow:  60 * time.Second,
		VaultRoot:     envOr(getenv, "ORCH_VAULT_ROOT", "/srv/msout/vault"),
		ArtifactRoot:  envOr(getenv, "ORCH_ARTIFACT_ROOT", "/srv/msout/artifacts"),
		RunnerImage:   envOr(getenv, "ORCH_RUNNER_IMAGE", "ghcr.io/ms-one-note-exporter/runner:0.0.0"),
		RunnerNetwork: envOr(getenv, "ORCH_RUNNER_NETWORK", "msout-runner"),
		// The third network, and the port `api` dials on it. Both fixed at deploy
		// time for the same reason as everything else here: no request field
		// reaches them.
		RunnerControlNetwork: envOr(getenv, "ORCH_RUNNER_CONTROL_NETWORK", "msout-runner-api"),
		RunnerPort:           3100,
		// POC §18's two cores. Deploy-time only, for the reason on the field.
		RunnerNanoCpus: 2_000_000_000,
		// Next to the orchestrator's own secret, by convention. Not derived from
		// ORCH_HMAC_SECRET_FILE: it is a different secret with a different
		// audience, and coupling them would mean rotating one rotates the other.
		RunnerTokenFile: envOr(getenv, "ORCH_RUNNER_TOKEN_FILE", "/run/secrets/runner_token"),
		PoolSize:        4,
		RunnerTTL:       5 * time.Minute,
		SlotIdleTimeout: 30 * time.Minute,
		RequestTimeout:  15 * time.Second,
		ShutdownGrace:   20 * time.Second,
	}

	secretFile := strings.TrimSpace(getenv("ORCH_HMAC_SECRET_FILE"))
	if secretFile == "" {
		return nil, ErrMissingSecret
	}
	raw, err := readFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: read ORCH_HMAC_SECRET_FILE: %w", err)
	}
	// Trailing newlines are the norm for `openssl rand -hex 32 > secret`, and
	// a secret with a stray newline would still verify against a correctly
	// signed call only if both sides trimmed. Trim here so the value is
	// canonical, and require a minimum length so a truncated file is loud.
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return nil, ErrMissingSecret
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("orchestrator: HMAC secret is %d bytes, want at least 32", len(secret))
	}
	cfg.HMACSecret = []byte(secret)

	if v := strings.TrimSpace(getenv("ORCH_REPLAY_WINDOW_SECONDS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("orchestrator: ORCH_REPLAY_WINDOW_SECONDS %q is not an integer", v)
		}
		if n <= 0 {
			return nil, fmt.Errorf("orchestrator: ORCH_REPLAY_WINDOW_SECONDS must be positive, got %d", n)
		}
		cfg.ReplayWindow = time.Duration(n) * time.Second
	}

	if v := strings.TrimSpace(getenv("ORCH_RUNNER_NANO_CPUS")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("orchestrator: ORCH_RUNNER_NANO_CPUS %q is not an integer", v)
		}
		// 10 000 is one hundredth of a core, which is the Engine's own floor — a
		// request below it is rejected with `Range of CPUs is from 0.01`, so the
		// bound is checked here rather than discovered on every pool top-up.
		if n < 10_000 {
			return nil, fmt.Errorf(
				"orchestrator: ORCH_RUNNER_NANO_CPUS %d is below the Docker minimum of 10000 (0.01 of a core)",
				n)
		}
		cfg.RunnerNanoCpus = n
	}

	if v := strings.TrimSpace(getenv("ORCH_POOL_SIZE")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("orchestrator: ORCH_POOL_SIZE %q is not an integer", v)
		}
		if n <= 0 {
			return nil, fmt.Errorf("orchestrator: ORCH_POOL_SIZE must be positive, got %d", n)
		}
		cfg.PoolSize = n
	}

	for _, root := range []struct {
		name string
		val  string
	}{
		{"ORCH_VAULT_ROOT", cfg.VaultRoot},
		{"ORCH_ARTIFACT_ROOT", cfg.ArtifactRoot},
		{"ORCH_RUNNER_TOKEN_FILE", cfg.RunnerTokenFile},
	} {
		if root.val == "" {
			return nil, fmt.Errorf("orchestrator: %s is empty", root.name)
		}
		if !path.IsAbs(root.val) {
			return nil, fmt.Errorf("orchestrator: %s must be absolute, got %q", root.name, root.val)
		}
		// A trailing slash would make path.Join and the Docker mount source
		// disagree about where the tree ends.
		if strings.HasSuffix(root.val, "/") {
			return nil, fmt.Errorf("orchestrator: %s must not end with a slash, got %q", root.name, root.val)
		}
	}

	// The two runner networks must be different names.
	//
	// If they were the same, `api` would end up on the egress network — which
	// is the one thing this third network exists to avoid — and nothing would
	// say so. A single network name would produce a working deployment with the
	// wrong topology, so it is refused at load rather than at first login.
	if strings.TrimSpace(cfg.RunnerNetwork) == strings.TrimSpace(cfg.RunnerControlNetwork) {
		return nil, fmt.Errorf(
			"orchestrator: ORCH_RUNNER_NETWORK and ORCH_RUNNER_CONTROL_NETWORK are both %q; "+
				"the runner's egress network and the api's control path must be separate, or api "+
				"gains the internet egress PLAN-v3 §2.1 forbids",
			cfg.RunnerNetwork,
		)
	}
	if cfg.RunnerPort <= 0 || cfg.RunnerPort > 65535 {
		return nil, fmt.Errorf("orchestrator: runner port %d is out of range", cfg.RunnerPort)
	}

	// The two trees must not overlap. If ArtifactRoot were inside VaultRoot,
	// the read-only artifact mount Caddy gets (§2.2) would also expose auth.json
	// to whoever can read the artifact tree, which is precisely the leak the
	// vault/artifact split exists to prevent.
	if overlaps(cfg.VaultRoot, cfg.ArtifactRoot) {
		return nil, fmt.Errorf(
			"orchestrator: ORCH_VAULT_ROOT (%q) and ORCH_ARTIFACT_ROOT (%q) overlap; PLAN-v3 §2.2 requires them separated",
			cfg.VaultRoot, cfg.ArtifactRoot,
		)
	}

	if strings.TrimSpace(cfg.RunnerImage) == "" {
		return nil, errors.New("orchestrator: ORCH_RUNNER_IMAGE is empty")
	}

	return cfg, nil
}

// overlaps reports whether one absolute path is the other or is nested inside
// it. Compares cleaned path elements, so "/srv/vault" does not count as the
// parent of "/srv/vault2".
func overlaps(a, b string) bool {
	ae := strings.Split(strings.Trim(path.Clean(a), "/"), "/")
	be := strings.Split(strings.Trim(path.Clean(b), "/"), "/")
	n := len(ae)
	if len(be) < n {
		n = len(be)
	}
	for i := 0; i < n; i++ {
		if ae[i] != be[i] {
			return false
		}
	}
	return true
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return fallback
}
