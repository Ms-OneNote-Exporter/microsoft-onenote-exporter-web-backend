#!/usr/bin/env bash
# Refuse to commit directly to main.
#
# This exists because it happened twice in one session, both times after a merge:
# the working tree was clean, the next step was an obvious edit, and the commit
# landed on main before the branch was created. Both reached the remote main.
#
# The workflow this repository uses is branch → commit → PR → merge → delete, and
# the reason is not ceremony: every significant bug in this project was found by
# something other than the author — a reviewer, a meta-test, a deploy. A commit on
# main gets none of that. Two of the bugs fixed today would have been cheaper to
# catch in review and were caught only because they were in a diff.
#
# Override deliberately, for the rare case of reverting something on main:
#
#   ALLOW_MAIN_COMMIT=1 git commit -m "..."
#
# Usage: install as .git/hooks/pre-commit, or run `make guard-install`.

set -euo pipefail

branch=$(git symbolic-ref --quiet --short HEAD || echo "")

# Detached HEAD is a bisect or a rebase, not a main commit.
[ -z "$branch" ] && exit 0

if [ "$branch" = "main" ] || [ "$branch" = "master" ]; then
  if [ "${ALLOW_MAIN_COMMIT:-}" = "1" ]; then
    echo "note: committing to $branch because ALLOW_MAIN_COMMIT=1" >&2
    exit 0
  fi
  cat >&2 <<'EOF'
refusing to commit to main.

  This repository works on branches: create one, commit there, open a PR, merge.

  Why this is enforced rather than remembered: every significant bug here was
  found by something other than the author — a reviewer on another repo, a
  meta-test that fed broken config to a check, or a real deployment. A commit
  straight to main sees none of those. Two of the bugs found on the first deploy
  would have been caught in review at near-zero cost, and both were found only
  because they happened to be in a diff someone else could read.

  If you have already committed here:
    git branch fix/whatever && git reset --hard origin/main
  then push the branch and open a PR.

  To override deliberately (a revert on main, say):
    ALLOW_MAIN_COMMIT=1 git commit -m "..."
EOF
  exit 1
fi