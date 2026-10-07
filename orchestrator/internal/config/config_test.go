package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// validSecret is a stand-in for `openssl rand -hex 32`, which is 64 hex chars.
const validSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// env builds a getenv function over a map, so each test states only the
// variables it cares about.
func env(pairs map[string]string) func(string) string {
	return func(k string) string { return pairs[k] }
}

// readFileFrom returns a readFile over a map, so a test does not need real files
// for the happy path.
func readFileFrom(content string) func(string) ([]byte, error) {
	return func(string) ([]byte, error) { return []byte(content), nil }
}

// baseEnv is the minimum a valid configuration needs.
func baseEnv() map[string]string {
	return map[string]string{
		"ORCH_HMAC_SECRET_FILE": "/run/secrets/orchestrator_hmac",
	}
}

// T-I6: the orchestrator refuses to start without the secret rather than
// falling back to open access.
func TestLoadRefusesWithoutSecretFileVariable(t *testing.T) {
	_, err := Load(env(map[string]string{}), readFileFrom(validSecret))
	if !errors.Is(err, ErrMissingSecret) {
		t.Fatalf("want ErrMissingSecret, got %v", err)
	}
}

func TestLoadRefusesWhenSecretFileUnreadable(t *testing.T) {
	_, err := Load(env(baseEnv()), func(string) ([]byte, error) {
		return nil, os.ErrNotExist
	})
	if err == nil {
		t.Fatal("want an error for an unreadable secret file")
	}
	if errors.Is(err, ErrMissingSecret) {
		t.Fatal("an unreadable file is not the same as an empty secret")
	}
}

func TestLoadRefusesWhenSecretEmpty(t *testing.T) {
	for _, content := range []string{"", "   ", "\n\n"} {
		_, err := Load(env(baseEnv()), readFileFrom(content))
		if !errors.Is(err, ErrMissingSecret) {
			t.Fatalf("content %q: want ErrMissingSecret, got %v", content, err)
		}
	}
}

// A truncated secret file is worse than an absent one: it authenticates, with a
// weaker key than the operator believes. Reject it loudly.
func TestLoadRejectsShortSecret(t *testing.T) {
	_, err := Load(env(baseEnv()), readFileFrom("tooshort"))
	if err == nil {
		t.Fatal("want an error for a short secret")
	}
	if errors.Is(err, ErrMissingSecret) {
		t.Fatal("a short secret is not the same as a missing one")
	}
}

// A trailing newline from `openssl rand -hex 32 > file` must not become part of
// the key, or every signature would fail against a correctly-configured caller.
func TestLoadTrimsTrailingNewlineFromSecret(t *testing.T) {
	cfg, err := Load(env(baseEnv()), readFileFrom(validSecret+"\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := string(cfg.HMACSecret); got != validSecret {
		t.Fatalf("secret = %q, want %q", got, validSecret)
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(baseEnv()), readFileFrom(validSecret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ReplayWindow.Seconds() != 60 {
		t.Errorf("replay window = %v, want 60s", cfg.ReplayWindow)
	}
	if cfg.RunnerTTL != 5*60*1e9 {
		t.Errorf("runner ttl = %v, want 5m", cfg.RunnerTTL)
	}
	if cfg.DockerSocket != "/var/run/docker.sock" {
		t.Errorf("docker socket = %q", cfg.DockerSocket)
	}
}

// §2.2's vault/artifact split is the reason the orchestrator is a separate
// process. An overlapping pair of roots would let Caddy's read-only artifact
// mount also reach auth.json.
func TestLoadRejectsOverlappingRoots(t *testing.T) {
	cases := []struct{ vault, artifact string }{
		{"/srv/msout/vault", "/srv/msout/vault/artifacts"},
		{"/srv/msout/vault", "/srv/msout/vault"},
		{"/srv/msout/artifacts", "/srv/msout"},
	}
	for _, tc := range cases {
		e := baseEnv()
		e["ORCH_VAULT_ROOT"] = tc.vault
		e["ORCH_ARTIFACT_ROOT"] = tc.artifact
		_, err := Load(env(e), readFileFrom(validSecret))
		if err == nil {
			t.Errorf("vault=%q artifact=%q: want an overlap error", tc.vault, tc.artifact)
		}
	}
}

// The runner's two networks must be distinct, and this is the check that stops
// the whole stack from quietly acquiring egress it must not have.
//
// The failure mode this refuses is not a crash. If both variables named the same
// network, `api` would join the egress network in order to reach a runner, the
// deployment would come up, every test would pass — and PLAN-v3 §2.1's "the api
// has no route to the internet" would be false in production only. That is a
// worse outcome than a refusal at load.
func TestLoadRejectsIdenticalRunnerNetworks(t *testing.T) {
	for _, name := range []string{"msout-runner", "msout-runner-api", "anything"} {
		e := baseEnv()
		e["ORCH_RUNNER_NETWORK"] = name
		e["ORCH_RUNNER_CONTROL_NETWORK"] = name
		_, err := Load(env(e), readFileFrom(validSecret))
		if err == nil {
			t.Errorf("both networks %q: want an error — api would join the egress network", name)
		}
	}
}

// Whitespace must not smuggle two different-looking names past it into the same
// network.
func TestLoadRejectsRunnerNetworksThatDifferOnlyByWhitespace(t *testing.T) {
	e := baseEnv()
	e["ORCH_RUNNER_NETWORK"] = "msout-runner"
	e["ORCH_RUNNER_CONTROL_NETWORK"] = " msout-runner "
	_, err := Load(env(e), readFileFrom(validSecret))
	if err == nil {
		t.Error("a control network differing only by whitespace was accepted")
	}
}

// The defaults must be two distinct names and a usable port, or the runner would
// join nothing the api can reach.
func TestLoadDefaultsGiveTwoRunnerNetworksAndAPort(t *testing.T) {
	cfg, err := Load(env(baseEnv()), readFileFrom(validSecret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RunnerNetwork == cfg.RunnerControlNetwork {
		t.Errorf("both runner networks default to %q", cfg.RunnerNetwork)
	}
	if cfg.RunnerPort <= 0 || cfg.RunnerPort > 65535 {
		t.Errorf("runner port = %d, out of range", cfg.RunnerPort)
	}
}

// A sibling directory sharing a name prefix is not an overlap. /srv/vault must
// not reject /srv/vault2, or the check would be unusable.
func TestLoadAllowsSiblingRoots(t *testing.T) {
	e := baseEnv()
	e["ORCH_VAULT_ROOT"] = "/srv/msout/vault"
	e["ORCH_ARTIFACT_ROOT"] = "/srv/msout/vault-backup"
	if _, err := Load(env(e), readFileFrom(validSecret)); err != nil {
		t.Fatalf("sibling roots rejected: %v", err)
	}
}

func TestLoadRejectsRelativeRoots(t *testing.T) {
	e := baseEnv()
	e["ORCH_VAULT_ROOT"] = "relative/path"
	if _, err := Load(env(e), readFileFrom(validSecret)); err == nil {
		t.Fatal("want an error for a relative vault root")
	}
}

// A trailing slash makes path.Join and the Docker mount source disagree about
// where the tree ends.
func TestLoadRejectsTrailingSlashRoots(t *testing.T) {
	e := baseEnv()
	e["ORCH_ARTIFACT_ROOT"] = "/srv/msout/artifacts/"
	if _, err := Load(env(e), readFileFrom(validSecret)); err == nil {
		t.Fatal("want an error for a trailing slash")
	}
}

func TestLoadRejectsBadNumbers(t *testing.T) {
	for _, key := range []string{"ORCH_REPLAY_WINDOW_SECONDS", "ORCH_POOL_SIZE"} {
		for _, val := range []string{"abc", "0", "-1"} {
			e := baseEnv()
			e[key] = val
			if _, err := Load(env(e), readFileFrom(validSecret)); err == nil {
				t.Errorf("%s=%q: want an error", key, val)
			}
		}
	}
}

func TestLoadAcceptsPoolSize(t *testing.T) {
	e := baseEnv()
	e["ORCH_POOL_SIZE"] = "8"
	cfg, err := Load(env(e), readFileFrom(validSecret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PoolSize != 8 {
		t.Fatalf("pool size = %d, want 8", cfg.PoolSize)
	}
}

// The identifier is joined to a host path, so its shape is a security control.
func TestValidGUID(t *testing.T) {
	good := []string{
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"00000000-0000-0000-0000-000000000000",
	}
	for _, g := range good {
		if !ValidGUID(g) {
			t.Errorf("%q should be valid", g)
		}
	}

	bad := []string{
		"",
		"not-a-guid",
		// Uppercase: not accepted, so a caller cannot get two spellings of the
		// same session past a string comparison.
		"3F2504E0-4F89-11D3-9A0C-0305E82C3301",
		// Traversal attempts. This is the case that matters: the guid is joined
		// to VaultRoot.
		"../../etc",
		"../../../srv/msout/vault/other/auth.json",
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301/../../x",
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301; rm -rf /",
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301\n",
		"3f2504e04f8911d39a0c0305e82c3301", // no dashes
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301a",
	}
	for _, g := range bad {
		if ValidGUID(g) {
			t.Errorf("%q should be rejected", g)
		}
	}
}

// The artifact id appears in a download URL, so it must be 32 random bytes in
// base64url — 43 chars, no separators.
func TestValidArtifactID(t *testing.T) {
	good := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 43 x 'A'
		"aB3-_aB3-_aB3-_aB3-_aB3-_aB3-_aB3-_aB3-_aB3",
	}
	for _, id := range good {
		if len(id) != 43 {
			t.Fatalf("fixture %q is not 43 chars", id)
		}
		if !ValidArtifactID(id) {
			t.Errorf("%q should be valid", id)
		}
	}

	bad := []string{
		"",
		"short",
		"../" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		// Path separators are the traversal vector for a value joined to
		// ArtifactRoot.
		"AAAA/AAAA/AAAA/AAAA/AAAA/AAAA/AAAA/AAAA/AAA",
		"AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA",
		// base64 standard alphabet characters are not base64url.
		"AAAA+AAAA+AAAA+AAAA+AAAA+AAAA+AAAA+AAAA+AA",
		"AAAA/AAAA/AAAA/AAAA/AAAA/AAAA/AAAA/AAAA/AAA",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 44
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",   // 42
	}
	for _, id := range bad {
		if ValidArtifactID(id) {
			t.Errorf("%q should be rejected", id)
		}
	}
}

// A real generated id must be accepted, so the pattern is not accidentally
// narrower than crypto/rand output.
func TestValidArtifactIDAcceptsGenerated(t *testing.T) {
	// 32 zero bytes encodes to exactly 43 'A' characters.
	if !ValidArtifactID(filepath.Base("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) {
		t.Fatal("the canonical 32-zero-byte encoding must be accepted")
	}
}
