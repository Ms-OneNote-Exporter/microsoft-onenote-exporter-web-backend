#!/usr/bin/env bash
set -euo pipefail

# Keep the latest N tags per repository, remove everything older.
# Also prunes dangling (deref'd) images and shared-image duplicates.

KEEP=2  # number of most recent tags to retain per repo

# --- 1. Prune dangling images (no tag, unreferenced) ---
docker image prune -f
echo "--- dangling prune done ---"

# --- 2. De-duplicate orchestrator (all same IMAGE_ID => only keep the latest tag) ---
orch_tag=$(docker image ls ghcr.io/ms-one-note-exporter/msout-orchestrator \
  --format '{{.Repository}}:{{.Tag}}' |
  awk 'NR>1' | head -1)
if [[ -n "$orch_tag" ]]; then
  docker image rm "$orch_tag"  # rm just the tag, image stays referenced by others
fi

# --- 3. Per-repo: keep only the $KEEP newest tags, remove the rest ---
for repo in ghcr.io/ms-one-note-exporter/msout-runner ghcr.io/ms-one-note-exporter/msout-api; do
  # Sort by "Created" field descending (newest first), skip header
  mapfile -t all_tags < <(
    docker image ls "$repo" --format '{{.Repository}}:{{.Tag}}' |
    awk 'NR>1' | head -n 9999 || true
  )
  # Docker `image ls` is already sorted newest-first, so just take the tail
  keep_tags=( "${all_tags[@]:0:$KEEP}" )
  remove_tags=( "${all_tags[@]:$KEEP}" )

  if (( ${#remove_tags[@]} > 0 )); then
    echo "Removing ${#remove_tags[@]} old tag(s) from $repo:"
    for t in "${remove_tags[@]}"; do
      echo "  $t"
    done
    docker image rm "${remove_tags[@]}"
  fi
done

# --- 4. Final prune (catches any leftover dangling intermediate images) ---
docker system prune -f
echo "=== cleanup complete ==="

