#!/bin/bash
# cleanup-vault-dirs.sh
#
# One-off cleanup of vault directories whose session no longer exists.
#
# The orchestrator's `bindSession` creates /opt/msout/data/vault/<guid>/ at
# claim time, and nothing ever removed it. This script finds the directories
# whose sessions are gone and removes them.
#
# **This script is never part of the deploy.** It is run by an operator, once.
#
# ## Safety
#
#   1. The live guids are read from the api's database, READ-ONLY, at the time
#      the script runs — not from a list baked into this file, because the rows
#      change.
#   2. **If the database cannot be read, the script stops.** A cleanup that
#      cannot tell a live session from a dead one must not remove anything:
#      "no live sessions" and "I could not ask" are different answers, and
#      treating them as the same is how a live session's directory gets deleted.
#   3. Dry run by default. `--force` removes.
#   4. Only a directory whose name is a lowercase uuid is ever a candidate, so a
#      stray file in the vault root is never removed.
#   5. The vault root itself is never a candidate.
#
# ## What it does NOT do
#
# It does not shred. The decision was made: the 43 directories that hold a
# Microsoft session cookie are unlinked rather than overwritten, and on a
# copy-on-write or overlay filesystem the old blocks can survive. It also takes
# **no archive** — a snapshot that preserves what was just deliberately
# destroyed is a second copy, not a safety net.
#
# ## Usage
#
#   cd /opt/msout && ./infra/cleanup-vault-dirs.sh            # dry run
#   cd /opt/msout && ./infra/cleanup-vault-dirs.sh --force    # remove

set -euo pipefail

VAULT_ROOT="${MSOUT_VAULT_ROOT:-/opt/msout/data/vault}"
COMPOSE_DIR="${MSOUT_COMPOSE_DIR:-/opt/msout}"
API_DB_PATH="${MSOUT_API_DB_PATH:-/srv/msout/data/api.db}"
FORCE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --force)
      FORCE=true
      shift
      ;;
    -h | --help)
      sed -n '2,40p' "$0"
      exit 0
      ;;
    *)
      echo "Usage: $0 [--force]" >&2
      exit 1
      ;;
  esac
done

if [ ! -d "$VAULT_ROOT" ]; then
  echo "ERROR: vault root does not exist: $VAULT_ROOT" >&2
  echo "       set MSOUT_VAULT_ROOT if the deployment puts it elsewhere" >&2
  exit 1
fi

# The live guids, read from the api's database, read-only, now.
#
# `node:sqlite` is the api's storage module and its API is **synchronous**
# (`DatabaseSync`) — there is no `open()` and no `await` in it. The path is the
# api's own mount inside its container.
read_live_guids() {
  (cd "$COMPOSE_DIR" && docker compose exec -T api node -e '
    const { DatabaseSync } = require("node:sqlite");
    const db = new DatabaseSync(process.env.MSOUT_API_DB_PATH ?? "/srv/msout/data/api.db", {
      readOnly: true,
    });
    try {
      const rows = db.prepare("SELECT guid FROM sessions").all();
      // The ExperimentalWarning node:sqlite prints goes to stderr, which this
      // script does not capture — so the guids are the only thing on stdout.
      process.stdout.write(rows.map((r) => r.guid).join("\n"));
    } finally {
      db.close();
    }
  ') 2>/dev/null
}

echo "=== vault cleanup ==="
echo "Vault root:   $VAULT_ROOT"
echo "Compose dir:  $COMPOSE_DIR"
echo "Mode:         $([ "$FORCE" = true ] && echo "REMOVE" || echo "dry run")"
echo ""

if ! LIVE_GUIDS="$(read_live_guids)"; then
  echo "ERROR: could not read the api's database." >&2
  echo "       The live sessions are unknown, so nothing can be safely removed." >&2
  echo "       Check that the api container is up and that $API_DB_PATH is readable in it." >&2
  exit 1
fi

LIVE_COUNT=$(printf '%s\n' "$LIVE_GUIDS" | grep -c . || true)
if [ "$LIVE_COUNT" -eq 0 ]; then
  # Zero rows is a legitimate answer (every session has expired) — but it is
  # also what a broken query looks like, and the two are told apart by the
  # query having succeeded. It did, so this is a real zero.
  echo "Live sessions: 0 (the database was read successfully and has no session rows)"
else
  echo "Live sessions: $LIVE_COUNT"
  printf '%s\n' "$LIVE_GUIDS" | sed 's/^/  /'
fi
echo ""

# The directories, by name.
#
# A glob loop rather than `find -printf`: `-printf` is GNU-only, and a script
# that removes directories should be runnable — and testable — on whatever
# machine the operator has.
ALL_DIRS=()
CANDIDATES=()
for entry in "$VAULT_ROOT"/*/; do
  [ -d "$entry" ] || continue
  name="${entry%/}"
  name="${name##*/}"
  ALL_DIRS+=("$name")
  # Only a lowercase uuid is ever a candidate, so a stray file in the vault root
  # is never removed.
  if [[ "$name" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    CANDIDATES+=("$name")
  fi
done
mapfile -t ALL_DIRS < <(printf '%s\n' "${ALL_DIRS[@]}" | sort)
mapfile -t CANDIDATES < <(printf '%s\n' "${CANDIDATES[@]}" | sort)

echo "Directories in the vault root: ${#ALL_DIRS[@]}"
if [ ${#ALL_DIRS[@]} -ne ${#CANDIDATES[@]} ]; then
  echo "  (${#ALL_DIRS[@]} - ${#CANDIDATES[@]} of them are not uuid-named and are never candidates)"
fi
echo ""

TO_REMOVE=()
SKIPPED=()
for dir in "${CANDIDATES[@]}"; do
  if printf '%s\n' "$LIVE_GUIDS" | grep -qxF "$dir"; then
    echo "  $dir  KEPT (a session row still exists)"
    SKIPPED+=("$dir")
  else
    echo "  $dir  remove"
    TO_REMOVE+=("$dir")
  fi
done

echo ""
echo "Summary:"
echo "  Directories:       ${#ALL_DIRS[@]}"
echo "  Kept (live row):   ${#SKIPPED[@]}"
echo "  To remove:         ${#TO_REMOVE[@]}"

if [ ${#TO_REMOVE[@]} -eq 0 ]; then
  echo ""
  echo "Nothing to remove."
  exit 0
fi

if [ "$FORCE" = false ]; then
  echo ""
  echo "This was a dry run. Re-run with --force to remove."
  exit 0
fi

echo ""
echo "=== removal ==="
for dir in "${TO_REMOVE[@]}"; do
  full="$VAULT_ROOT/$dir"
  # Belt and braces: the name came from a uuid filter and the path is inside
  # the vault root, but a removal is not the place to be casual.
  case "$full" in
    "$VAULT_ROOT"/*) ;;
    *)
      echo "ERROR: refusing to remove $full (outside the vault root)" >&2
      exit 1
      ;;
  esac
  rm -rf -- "$full"
  echo "  removed $dir"
done

echo ""
echo "=== verification ==="
LEFTOVERS=()
for entry in "$VAULT_ROOT"/*/; do
  [ -d "$entry" ] || continue
  name="${entry%/}"
  LEFTOVERS+=("${name##*/}")
done
mapfile -t LEFTOVERS < <(printf '%s\n' "${LEFTOVERS[@]}" | sort)
echo "Directories remaining: ${#LEFTOVERS[@]}"
for dir in "${LEFTOVERS[@]}"; do
  echo "  $dir"
done
