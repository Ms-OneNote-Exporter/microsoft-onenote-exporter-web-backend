package main

// The boot-time writability check on the orchestrator's two storage roots.
//
// ## Why this file exists
//
// The runner failed with:
//
//     EACCES: permission denied, mkdir '/data/<guid>'
//
// which is three layers from the cause. The cause was that `ORCH_VAULT_ROOT` named a
// path that existed only *inside* the orchestrator's container: it is the `Source`
// of a bind mount, and a bind source is resolved on the host, so the Engine created
// an empty root-owned directory there and the runner mounted that.
//
// Every container was healthy. `/healthz` said `ok`. The api reported only
// `credential handoff failed`. Nothing in any log named a path.
//
// So the orchestrator checks the two paths it is about to hand the Engine, at boot,
// and fails with the remedy in the message. These tests are about the *message* as
// much as the verdict: a check that fails with `permission denied` has moved the
// error, not improved it.
//
// **What these tests do not cover:** the call site in `run`. They pass identically
// with that call removed, because they exercise `checkWritableRoots` directly.
// Covering it would need `run` to reach the check, which means standing up a
// listener and a Docker socket — so the wiring is two reviewed lines rather than a
// test. Stated here because "there are tests for the boot check" would otherwise be
// read as covering the thing that actually matters at 3am: whether startup calls it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
)

func cfgWithRoots(t *testing.T, vault, artifacts string) *config.Config {
	t.Helper()
	return &config.Config{VaultRoot: vault, ArtifactRoot: artifacts}
}

func TestRootsThatWorkAreAccepted(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithRoots(t, filepath.Join(dir, "vault"), filepath.Join(dir, "artifacts"))
	if err := os.MkdirAll(cfg.VaultRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.ArtifactRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := checkWritableRoots(cfg); err != nil {
		t.Fatalf("two writable roots were rejected: %v", err)
	}
}

// The probe must leave nothing behind. A `.probe-` directory left in a vault root is
// indistinguishable from a session directory to anything that walks the tree, and
// the orchestrator is the thing that walks it.
func TestTheProbeLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithRoots(t, filepath.Join(dir, "vault"), filepath.Join(dir, "artifacts"))
	for _, p := range []string{cfg.VaultRoot, cfg.ArtifactRoot} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := checkWritableRoots(cfg); err != nil {
		t.Fatalf("%v", err)
	}

	for _, root := range []string{cfg.VaultRoot, cfg.ArtifactRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("%s holds %d entries after the probe; it must hold none", root, len(entries))
		}
	}
}

// A root that does not exist is the *common* case here — a named volume mounted
// elsewhere means the configured path is a host directory nobody made — and it must
// say so, with the fix.
func TestAMissingRootIsNamedWithItsRemedy(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithRoots(t, filepath.Join(dir, "absent"), filepath.Join(dir, "artifacts"))
	if err := os.MkdirAll(cfg.ArtifactRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	err := checkWritableRoots(cfg)
	if err == nil {
		t.Fatal("a missing vault root was accepted")
	}
	for _, want := range []string{"ORCH_VAULT_ROOT", "install -d", "bind-mount", cfg.VaultRoot} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q; an operator reading it cannot tell "+
				"what to change", err, want)
		}
	}
}

// A read-only root is the other half. It can be *listed* but not written, which is a
// different failure from a missing one and the message must not conflate them.
func TestAReadOnlyRootIsReportedAsSuch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the permission bit this test depends on")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.MkdirAll(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	cfg := cfgWithRoots(t, locked, filepath.Join(dir, "artifacts"))
	if err := os.MkdirAll(cfg.ArtifactRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	err := checkWritableRoots(cfg)
	if err == nil {
		t.Fatal("a read-only vault root was accepted")
	}
	if !strings.Contains(err.Error(), "install -d") {
		t.Errorf("error %q does not carry the remedy", err)
	}
}

// The artifact root is checked too. It was the *latent* half of the same bug: the
// vault failed at login, and the artifact root would have failed at the first export
// — by which point someone would be looking at a different problem entirely.
func TestTheArtifactRootIsCheckedAsWellAsTheVault(t *testing.T) {
	dir := t.TempDir()
	cfg := cfgWithRoots(t, filepath.Join(dir, "vault"), filepath.Join(dir, "artifacts"))
	if err := os.MkdirAll(cfg.VaultRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	err := checkWritableRoots(cfg)
	if err == nil {
		t.Fatal("a missing artifact root was accepted")
	}
	if !strings.Contains(err.Error(), "ORCH_ARTIFACT_ROOT") {
		t.Errorf("error %q names the wrong root", err)
	}
}
