package pool

// Publishing a staged artifact.
//
// The assertions here are about the **filesystem**, not about a return value:
// `ArtifactStat` decides whether a download is authorised, so the only question
// that matters is whether a directory exists at a path when it is asked. An
// exported function nobody has run is the shape the project has been bitten by
// more than once, so each of these drives real directories in a temp tree and
// then asks the stat path what an api would see.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
)

const (
	testGUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	testID   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 base64url
)

// stagedArchive writes a vault.zip of a given size into the staging directory and
// returns the pool.
func stagedArchive(t *testing.T, artifactID string, size int) *Pool {
	t.Helper()
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)
	dir := filepath.Join(cfg.ArtifactRoot, StagingDir, artifactID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, StagedArchiveName), make([]byte, size), 0o600); err != nil {
		t.Fatalf("stage: %v", err)
	}
	return p
}

func TestFinalizePublishesWhereArtifactStatLooks(t *testing.T) {
	// The whole point, as one assertion: what the api is told.
	//
	// `ArtifactStat` joins ArtifactRoot with the id and requires a *directory*.
	// So the publish has to put a directory at exactly that path, or every
	// download 404s for a reason nothing states.
	p := stagedArchive(t, testID, 128)

	// Before: not published. The runner has streamed bytes nobody can download,
	// which is the correct state and the reason staging exists.
	if stat, err := p.ArtifactStat(testID); err != nil || stat.Exists {
		t.Fatalf("before finalize, stat = %+v (err %v), want exists:false", stat, err)
	}

	if _, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	stat, err := p.ArtifactStat(testID)
	if err != nil {
		t.Fatalf("stat after finalize: %v", err)
	}
	if !stat.Exists {
		t.Fatal("finalize returned success but ArtifactStat cannot find it; every download would 404")
	}
	if stat.Size == 0 {
		t.Error("published artifact reports size 0; ArtifactStat counts the directory, " +
			"so an empty one authorises a download of nothing")
	}

	// And the staging directory is gone, so the same bytes are not present twice
	// on a quota'd volume.
	if _, err := os.Stat(filepath.Join(p.cfg.ArtifactRoot, StagingDir, testID)); !os.IsNotExist(err) {
		t.Error("staging directory still exists after publish; the vault is stored twice")
	}
}

func TestFinalizeNeverPublishesAFileWhereADirectoryIsExpected(t *testing.T) {
	// The failure the first version of the runner had: `<guid>.zip`, a regular
	// file. ArtifactStat's own comment says a regular file there "means something
	// is wrong that exists: true would hide".
	p := stagedArchive(t, testID, 64)
	if _, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID}); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	info, err := os.Stat(filepath.Join(p.cfg.ArtifactRoot, testID))
	if err != nil {
		t.Fatalf("published path missing: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("published path is a %s, want a directory", "file")
	}
}

func TestFinalizeMarksAPartialArchiveUnmistakably(t *testing.T) {
	// PLAN-v3 §5: "A partial vault must not be mistakable for a complete one,
	// and that must not depend on the UI being correct."
	//
	// Three things, because any one alone is insufficient: the filename, the
	// marker file, and the `partial` claim the api already has in its snapshot.
	p := stagedArchive(t, testID, 256)

	result, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID, Partial: true})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if result.ArchiveName != "vault.partial.zip" {
		t.Errorf("archive name = %q, want vault.partial.zip", result.ArchiveName)
	}

	dir := filepath.Join(p.cfg.ArtifactRoot, testID)
	if _, err := os.Stat(filepath.Join(dir, "vault.partial.zip")); err != nil {
		t.Errorf("no vault.partial.zip in the published directory: %v", err)
	}
	// The clean name must be gone, or a listing offers two files and a client
	// picks the wrong one.
	if _, err := os.Stat(filepath.Join(dir, "vault.zip")); !os.IsNotExist(err) {
		t.Error("the un-suffixed archive is still present; a partial vault offers two files")
	}

	marked, err := p.ArtifactMarker(testID)
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	if !marked {
		t.Error("no partial marker; the on-disk half of §5 is missing")
	}
}

func TestACleanArchiveCarriesNoMarker(t *testing.T) {
	// The other direction. A marker on a complete vault trains a user to ignore
	// it, which is the same failure as no marker on a partial one.
	p := stagedArchive(t, testID, 64)
	if _, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID}); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	marked, err := p.ArtifactMarker(testID)
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	if marked {
		t.Error("a complete archive is marked partial")
	}
}

func TestFinalizeRefusesAnEmptyArchive(t *testing.T) {
	// A zero-byte zip is worse than none: `ArtifactStat` would report it as an
	// existing artifact, the api would authorise the download, and the user would
	// get a corrupt file with a 200 and no error.
	p := stagedArchive(t, testID, 0)

	if _, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID}); err == nil {
		t.Fatal("published an empty archive")
	}
	// ...and it must not have been published on the way to failing.
	if stat, _ := p.ArtifactStat(testID); stat.Exists {
		t.Error("the failed finalize still published something")
	}
}

func TestFinalizeRefusesNothingStaged(t *testing.T) {
	// A caller that finalises an export which produced no archive. Its own error,
	// mapped to 409, because the caller's view is stale rather than the request
	// being wrong — a generic 500 would send an operator hunting a disk problem.
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	_, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID})
	if !errors.Is(err, ErrNothingStaged) {
		t.Fatalf("err = %v, want ErrNothingStaged so the server can answer 409", err)
	}
}

func TestFinalizeRefusesAnIdThatCouldEscapeTheArtifactRoot(t *testing.T) {
	// The id reaches path.Join. A traversal here would let a caller publish a
	// directory anywhere the orchestrator can write — including into the vault
	// tree, which is the one tree Caddy must not be able to serve.
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	for _, bad := range []string{
		"..",
		"../" + testID,
		strings.Repeat("../", 12) + "etc",
		strings.Repeat("../", 12) + "escaped",
		"short",
		strings.Repeat("a", 42),
		strings.Repeat("a", 44),
		testID + "/",
		"/" + testID,
		testID + "\x00",
		"." + testID,
		testID + ".",
	} {
		_, err := p.Finalize(FinalizeInput{ArtifactID: bad, SessionGUID: testGUID})
		if !errors.Is(err, ErrArtifactIDInvalid) {
			t.Errorf("id %q: err = %v, want ErrArtifactIDInvalid", bad, err)
		}
	}

	// Nothing escaped, and nothing landed inside the artifact root either. The
	// first version of this staged a `../../../escaped` archive so that a
	// successful publish would have somewhere obvious to appear — which meant the
	// *test setup* tried to mkdir at `/escaped`, and failed with "permission
	// denied" on a container running as non-root. The assertion did not need it:
	// the refusal happens before any path is built, so a non-existent staging
	// directory is the stronger input, not the weaker one.
	for _, probe := range []string{
		filepath.Join(filepath.Dir(cfg.ArtifactRoot), "escaped"),
		filepath.Join(cfg.ArtifactRoot, "escaped"),
	} {
		if _, err := os.Stat(probe); err == nil {
			t.Errorf("a traversal published to %s", probe)
		}
	}
}

func TestFinalizeRefusesToReplaceAPublishedArtifact(t *testing.T) {
	// Ids are caller-supplied, so a retry or a bug can name one that already
	// exists. Overwriting would destroy a vault someone may be downloading.
	p := stagedArchive(t, testID, 64)
	if _, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID}); err != nil {
		t.Fatalf("first finalize: %v", err)
	}
	stagedInto(t, p.cfg, testID, 128)

	_, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID})
	if err == nil {
		t.Fatal("replaced an already-published artifact")
	}
	// The original is intact.
	info, statErr := os.Stat(filepath.Join(p.cfg.ArtifactRoot, testID, StagedArchiveName))
	if statErr != nil {
		t.Fatalf("original archive gone: %v", statErr)
	}
	if info.Size() != 64 {
		t.Errorf("original archive is now %d bytes, want 64", info.Size())
	}
}

func TestFinalizeRefusesAGuidThatIsNotOne(t *testing.T) {
	p := stagedArchive(t, testID, 32)
	_, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: "not-a-guid"})
	if !errors.Is(err, errInvalidGUID) {
		t.Errorf("err = %v, want errInvalidGUID", err)
	}
}

// Deleting a published artifact.
//
// The same rule as the rest of this file applies, and it is the one that matters
// here: the assertions are about the **filesystem**, asked through `ArtifactStat`,
// because that is what the api asks before it tells Caddy to serve a download. A
// `DeleteArtifact` that returned `nil` without removing anything would pass every
// signature-shaped test and leave every erased session's vault on the volume.

func TestDeleteArtifactRemovesWhereArtifactStatLooks(t *testing.T) {
	p := stagedArchive(t, testID, 128)
	if _, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// Before: published, so a download would be authorised.
	if stat, err := p.ArtifactStat(testID); err != nil || !stat.Exists {
		t.Fatalf("before delete, stat = %+v (err %v), want exists:true", stat, err)
	}

	if err := p.DeleteArtifact(testID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	stat, err := p.ArtifactStat(testID)
	if err != nil {
		t.Fatalf("stat after delete: %v", err)
	}
	if stat.Exists {
		t.Error("delete reported success but ArtifactStat still finds the artifact; " +
			"an erased session's vault is still downloadable")
	}
}

// The archive itself, not merely the directory that held it. A directory removed
// but a file left behind would be invisible to `ArtifactStat` (which requires a
// directory) and would still be there on the volume — the exact shape this whole
// change exists to remove.
func TestDeleteArtifactRemovesTheArchiveItself(t *testing.T) {
	p := stagedArchive(t, testID, 512)
	if _, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID}); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	archive := filepath.Join(p.cfg.ArtifactRoot, testID, StagedArchiveName)

	if err := p.DeleteArtifact(testID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Error("the archive is still on the artifact volume after delete")
	}
}

// The same, for a partial vault: the `.partial.zip` name and the marker both live
// inside the published directory, so both have to go with it.
func TestDeleteArtifactRemovesAPartialVault(t *testing.T) {
	p := stagedArchive(t, testID, 256)
	if _, err := p.Finalize(FinalizeInput{
		ArtifactID: testID, SessionGUID: testGUID, Partial: true,
	}); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if marked, err := p.ArtifactMarker(testID); err != nil || !marked {
		t.Fatalf("before delete, marker = %v (err %v), want marked", marked, err)
	}

	if err := p.DeleteArtifact(testID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	marked, err := p.ArtifactMarker(testID)
	if err != nil {
		t.Fatalf("marker after delete: %v", err)
	}
	if marked {
		t.Error("the partial marker survived; the archive is gone but its label is not")
	}
}

// Erase is best-effort and retried, and "the thing I was deleting is already gone"
// is the outcome it wanted. An error here would make every repeated erase report a
// failure and push the machine towards recording a completed deletion as a failed
// one.
func TestDeleteArtifactIsIdempotent(t *testing.T) {
	p := stagedArchive(t, testID, 64)
	if _, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := p.DeleteArtifact(testID); err != nil {
			t.Fatalf("delete %d: %v", i+1, err)
		}
	}
	// And on a tree where nothing was ever published at all.
	cfg := testConfig(t, 1)
	empty := noDockerPool(t, cfg)
	if err := empty.DeleteArtifact(testID); err != nil {
		t.Errorf("delete on an empty artifact root: %v", err)
	}
}

// A staged export belongs to an export that has not finished, and `SweepStaging` is
// what reclaims it by age. A delete that reached into `.staging` would destroy a
// run that is still working.
func TestDeleteArtifactLeavesStagingAlone(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)
	stagedInto(t, cfg, testID, 512)

	if err := p.DeleteArtifact(testID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.ArtifactRoot, StagingDir, testID, StagedArchiveName)); err != nil {
		t.Errorf("a staged archive was removed by a published-artifact delete: %v", err)
	}
}

// The id is joined onto a host path, so it is validated before that happens. This is
// the same argument as `Finalize`'s, and the same list: "reject anything that is not
// exactly 43 base64url characters" is smaller and more complete than stripping the
// bad characters. A traversal here would delete a directory anywhere this process
// can write — including the vault tree, which is the one tree Caddy must not serve
// from.
func TestDeleteArtifactRefusesAnIdThatCouldEscapeTheArtifactRoot(t *testing.T) {
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	for _, bad := range []string{
		"..",
		"../" + testID,
		strings.Repeat("../", 12) + "etc",
		strings.Repeat("../", 12) + "escaped",
		"short",
		strings.Repeat("a", 42),
		strings.Repeat("a", 44),
		testID + "/",
		"/" + testID,
		testID + "\x00",
		"." + testID,
		testID + ".",
	} {
		if err := p.DeleteArtifact(bad); !errors.Is(err, ErrArtifactIDInvalid) {
			t.Errorf("id %q: err = %v, want ErrArtifactIDInvalid", bad, err)
		}
	}

	// Nothing escaped, and the artifact root is intact — the assertion is that the
	// refusals happened *before* any path was built, not that the probes were absent.
	for _, probe := range []string{
		filepath.Join(filepath.Dir(cfg.ArtifactRoot), "escaped"),
		filepath.Join(cfg.ArtifactRoot, "escaped"),
	} {
		if _, err := os.Stat(probe); err == nil {
			t.Errorf("a traversal deleted %s", probe)
		}
	}
}

// One artifact, not the volume. This is the blast-radius property: a mistyped id
// must not take another session's vault with it.
func TestDeleteArtifactRemovesOnlyTheNamedArtifact(t *testing.T) {
	otherID := strings.Repeat("B", 43)
	p := stagedArchive(t, testID, 64)
	if _, err := p.Finalize(FinalizeInput{ArtifactID: testID, SessionGUID: testGUID}); err != nil {
		t.Fatalf("finalize first: %v", err)
	}
	stagedInto(t, p.cfg, otherID, 64)
	if _, err := p.Finalize(FinalizeInput{ArtifactID: otherID, SessionGUID: testGUID}); err != nil {
		t.Fatalf("finalize second: %v", err)
	}

	if err := p.DeleteArtifact(testID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if stat, _ := p.ArtifactStat(testID); stat.Exists {
		t.Error("the named artifact survived")
	}
	if stat, _ := p.ArtifactStat(otherID); !stat.Exists {
		t.Error("deleting one artifact removed another; a mistyped id takes a stranger's vault")
	}
}

func TestSweepStagingRemovesAbandonedVaults(t *testing.T) {
	// A runner that dies between streaming an archive and having it finalised
	// leaves real bytes, holding a vault, reachable by nobody. On a quota'd VPS
	// that accumulates until exports start failing for no visible reason.
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)

	stagedInto(t, cfg, testID, 512)

	root := filepath.Join(cfg.ArtifactRoot, StagingDir)
	// Backdate it: a fresh directory is inside any sane cutoff.
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(root, testID), old, old); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	removed, err := p.SweepStaging(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed %d, want 1", removed)
	}
	if _, err := os.Stat(filepath.Join(root, testID)); !os.IsNotExist(err) {
		t.Error("the abandoned staging directory survived")
	}
}

func TestSweepStagingLeavesAnythingRecent(t *testing.T) {
	// The cutoff is the caller's because only it knows the export timeout. A
	// sweep that removed a directory an export is still writing would destroy a
	// run that is working.
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)
	stagedInto(t, cfg, testID, 512)

	removed, err := p.SweepStaging(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed %d recent staging directories, want 0", removed)
	}
	if _, err := os.Stat(filepath.Join(cfg.ArtifactRoot, StagingDir, testID)); err != nil {
		t.Error("a recent staging directory was removed")
	}
}

func TestSweepStagingLeavesNamesItDoesNotRecognise(t *testing.T) {
	// A stray file or a name an operator put there is more likely to be something
	// this code does not understand than a failed export. Removing it on a
	// timestamp alone would be a way to destroy a thing nobody meant to delete.
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)
	root := filepath.Join(cfg.ArtifactRoot, StagingDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	strays := []string{"notes.txt", "README", "..hidden"}
	for _, name := range strays {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, name := range strays {
		_ = os.Chtimes(filepath.Join(root, name), old, old)
	}

	if _, err := p.SweepStaging(time.Now().Add(-24 * time.Hour)); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	for _, name := range strays {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Errorf("%s was removed; it is not a staging directory this code created", name)
		}
	}
}

func TestSweepStagingIsNotAFailureWhenNothingHasRun(t *testing.T) {
	// No staging directory at all is the normal state before the first export.
	cfg := testConfig(t, 1)
	p := noDockerPool(t, cfg)
	removed, err := p.SweepStaging(time.Now())
	if err != nil {
		t.Fatalf("sweep on an empty tree: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed %d, want 0", removed)
	}
}

func TestPublishedNameAgreesWithTheRunner(t *testing.T) {
	// Two files, two repositories, one filename. The runner writes `vault.zip`
	// into its staging directory; this publishes it. A rename here would publish
	// a directory whose archive the runner never wrote, and ArtifactStat would
	// happily report it as existing.
	if StagedArchiveName != "vault.zip" {
		t.Errorf("StagedArchiveName = %q; the runner writes vault.zip", StagedArchiveName)
	}
	if StagingDir != ".staging" {
		t.Errorf("StagingDir = %q; the runner writes into .staging", StagingDir)
	}
	if PublishedArchiveName(false) != "vault.zip" {
		t.Errorf("PublishedArchiveName(false) = %q, want vault.zip", PublishedArchiveName(false))
	}
	if !config.ValidArtifactID(testID) {
		t.Error("the test's artifact id is not the shape ValidArtifactID accepts; " +
			"these tests would pass without exercising the real path")
	}
}

// stagedInto stages an archive of a given size into a config's tree.
func stagedInto(t *testing.T, cfg *config.Config, artifactID string, size int) {
	t.Helper()
	dir := filepath.Join(cfg.ArtifactRoot, StagingDir, artifactID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, StagedArchiveName), make([]byte, size), 0o600); err != nil {
		t.Fatalf("stage: %v", err)
	}
}
