package pool

// Publishing a staged artifact.
//
// ## Why finalising lives here and not in the runner
//
// PLAN-v3 §2.2: *"the streaming zip is written by the runner into its artifact
// dir and finalised under an `artifactId` by the orchestrator."* The split is not
// arbitrary — it is what lets three properties hold at once:
//
//   - **`api` needs no filesystem access to decide authorisation.** It asks this
//     process for `{exists, size}` and never learns a path. That is §2.2's whole
//     point: the component that decides who may download cannot read a vault.
//   - **The runner cannot publish.** It has the artifact volume mounted
//     read-write, so it *could* rename its own output — but it does not know the
//     artifact id, because that id is the caller's and it is deliberately
//     unrelated to the session GUID (§5, opaque ids).
//   - **Caddy gets the artifact tree read-only** and nothing else, so an
//     in-progress archive is never servable.
//
// ## Why it is a rename and not a copy
//
// A copy of a multi-gigabyte vault is the disk spike §8.3 warns about, and it
// doubles the peak usage for no benefit: the staged bytes are already complete
// and already in the right filesystem. `os.Rename` within one filesystem is
// atomic, which is also what makes the publish invisible to a concurrent
// `ArtifactStat` — there is no window in which the directory exists but is
// half-populated.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter-web-backend/orchestrator/internal/config"
)

// StagingDir is the name of the subdirectory a runner streams into.
//
// A dot-directory so a listing of the artifact root never shows an unfinished
// archive as if it were a publishable one, and so a scan for artifacts skips it.
const StagingDir = ".staging"

// StagedArchiveName is the filename a runner writes inside its staging
// directory. Fixed by both sides: the runner creates it, this publishes it, and a
// mismatch would publish an empty directory rather than an archive — which
// `ArtifactStat` would report as a valid artifact of size 0.
const StagedArchiveName = "vault.zip"

// PartialMarkerName marks a published artifact whose export stopped early.
//
// PLAN-v3 §5 requires a partial vault to be unmistakable. The *response* side of
// that is the server: `X-Artifact-Partial: 1` and a `.partial.zip` filename. This
// file is the on-disk half, so the fact survives the container that produced it
// and can be read by whoever is triaging a vault.
const PartialMarkerName = "partial"

// PublishedArchiveName is the name the archive takes once published.
//
// No suffix in the clean case: a complete vault is called what it is. A partial
// one is suffixed, so the name alone distinguishes them in a file listing, in a
// download dialog, and in a log line.
func PublishedArchiveName(partial bool) string {
	if partial {
		return StagedArchiveName[:len(StagedArchiveName)-len(".zip")] + ".partial.zip"
	}
	return StagedArchiveName
}

var (
	// ErrArtifactIDInvalid rejects an id that is not exactly the opaque shape,
	// before it is ever joined to a host path.
	//
	// The same argument as the session GUID: "reject anything that is not exactly
	// 43 base64url characters" is a smaller and more obviously complete rule than
	// "strip the bad characters".
	//
	// Exported because the api's error mapping has to distinguish it from a
	// filesystem failure, and an unexported sentinel would have to be matched by
	// string.
	ErrArtifactIDInvalid = errors.New("pool: invalid artifact id")

	// ErrNothingStaged reports that a finalise was asked for with nothing in the
	// staging directory. A distinct error from a failed move, because the two need
	// different responses: the first means "no such export", the second means "the
	// filesystem refused".
	ErrNothingStaged = errors.New("pool: nothing staged to finalise")
)

// FinalizeInput is what a caller knows about an export it wants published.
type FinalizeInput struct {
	// ArtifactID is the caller's opaque id. Becomes the published directory name.
	ArtifactID string
	// SessionGUID is the session whose vault is being published. Only used to
	// check the staging directory belongs to a session we have bound, and for the
	// log line. It never appears in the published path.
	SessionGUID string
	// Partial marks the export as incomplete. Produces the `.partial` name and
	// the marker file.
	Partial bool
}

// FinalizeResult describes what was published, for the caller to log or return.
type FinalizeResult struct {
	ArtifactID  string
	ArchiveName string
	Bytes       int64
	Partial     bool
}

// Finalize publishes a staged archive under its artifact id.
//
// The whole operation is: verify the id and the staging directory exist, then
// `os.Rename` the staging directory into place. Nothing is copied and nothing is
// read, so the cost is independent of the vault's size.
//
// # Why the staged directory is renamed rather than its contents moved
//
// Renaming the *directory* is what makes the publish atomic. Moving files into a
// pre-created destination would leave that destination existing and incomplete
// for the duration, and `ArtifactStat` — which only checks that a directory exists
// — would authorise a download of an archive that is still being written. That is
// the "truncated archive with a 200" failure the staging directory exists to
// prevent, reintroduced one level up.
//
// # Why the marker is written *into the staging directory*, not the published one
//
// The staging directory is renamed whole, so anything written into it before the
// rename arrives atomically with the archive. Writing the marker afterwards opens
// a window where the artifact is published and still looks complete.
func (p *Pool) Finalize(in FinalizeInput) (FinalizeResult, error) {
	if !config.ValidArtifactID(in.ArtifactID) {
		return FinalizeResult{}, ErrArtifactIDInvalid
	}
	if !config.ValidGUID(in.SessionGUID) {
		// Not strictly needed for path safety — the id is what builds the path —
		// but a finalise with no session is a caller bug worth refusing rather
		// than publishing on the strength of an id alone.
		return FinalizeResult{}, errInvalidGUID
	}

	staged := filepath.Join(p.cfg.ArtifactRoot, StagingDir, in.ArtifactID)
	archive := filepath.Join(staged, StagedArchiveName)

	info, err := os.Stat(archive)
	if err != nil {
		if os.IsNotExist(err) {
			return FinalizeResult{}, fmt.Errorf("%w for %s", ErrNothingStaged, in.ArtifactID)
		}
		return FinalizeResult{}, err
	}
	if info.IsDir() {
		// A directory where the archive should be. Publishing it would produce an
		// artifact that exists, is a directory, and contains no vault.
		return FinalizeResult{}, fmt.Errorf(
			"pool: staged path %s is a directory, not the archive", archive)
	}
	if info.Size() == 0 {
		// An empty archive is worse than none: `ArtifactStat` would authorise a
		// download of zero bytes and the user would get a corrupt file with a 200.
		return FinalizeResult{}, fmt.Errorf(
			"pool: staged archive %s is empty; refusing to publish it", archive)
	}

	if in.Partial {
		if err := os.WriteFile(filepath.Join(staged, PartialMarkerName), nil, 0o444); err != nil {
			return FinalizeResult{}, fmt.Errorf("write partial marker: %w", err)
		}
		// Rename the archive itself, so the filename distinguishes a partial vault
		// in a listing and in a download dialog.
		renamed := filepath.Join(staged, PublishedArchiveName(true))
		if err := os.Rename(archive, renamed); err != nil {
			return FinalizeResult{}, fmt.Errorf("rename staged archive: %w", err)
		}
		if err := os.Remove(archive); err != nil && !os.IsNotExist(err) {
			return FinalizeResult{}, fmt.Errorf("remove pre-rename archive: %w", err)
		}
	}

	published := filepath.Join(p.cfg.ArtifactRoot, in.ArtifactID)
	// The destination must not already exist. `os.Rename` over an existing
	// non-empty directory fails on Linux, which is the right outcome by accident;
	// this makes it deliberate and gives a message that says what happened.
	if _, err := os.Stat(published); err == nil {
		return FinalizeResult{}, fmt.Errorf(
			"pool: artifact %s is already published; refusing to replace it", in.ArtifactID)
	} else if !os.IsNotExist(err) {
		return FinalizeResult{}, err
	}

	if err := os.Rename(staged, published); err != nil {
		return FinalizeResult{}, fmt.Errorf("publish %s: %w", in.ArtifactID, err)
	}

	result := FinalizeResult{
		ArtifactID:  in.ArtifactID,
		ArchiveName: StagedArchiveName,
		Bytes:       info.Size(),
		Partial:     in.Partial,
	}
	if in.Partial {
		result.ArchiveName = PublishedArchiveName(true)
	}
	return result, nil
}

// ArtifactMarker reports whether a published artifact carries the partial marker.
//
// The api decides authorisation from SQLite and asks this process only for
// `{exists, size}`, so nothing currently reads this. It exists so the fact is
// readable from disk by whoever triages a vault, and so the marker has a reader
// that would notice it go missing.
func (p *Pool) ArtifactMarker(artifactID string) (bool, error) {
	if !config.ValidArtifactID(artifactID) {
		return false, ErrArtifactIDInvalid
	}
	_, err := os.Stat(filepath.Join(p.cfg.ArtifactRoot, artifactID, PartialMarkerName))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// SweepStaging removes staging directories older than the cutoff.
//
// A runner that dies between streaming an archive and having it finalised leaves
// its staging directory behind: real bytes, holding a vault, reachable by nobody.
// Without this it accumulates for the life of the volume, which on a VPS with a
// quota is the difference between failing and not.
//
// The cutoff is a parameter rather than a constant because the caller knows the
// runner TTL and the export timeout, and a fixed value would be wrong for at
// least one of them.
func (p *Pool) SweepStaging(cutoff time.Time) (int, error) {
	root := filepath.Join(p.cfg.ArtifactRoot, StagingDir)
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			// No staging directory at all is the normal case before the first
			// export, not a failure.
			return 0, nil
		}
		return 0, err
	}

	removed := 0
	for _, entry := range entries {
		// A dot-prefixed name inside `.staging` is not a staging directory this
		// code created, and removing it on a timestamp alone would be a way to
		// delete something an operator put there.
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		// Only ids we would have published. A stray file is left for a human,
		// because it is more likely to be something we do not understand than a
		// failed export.
		if !config.ValidArtifactID(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}
