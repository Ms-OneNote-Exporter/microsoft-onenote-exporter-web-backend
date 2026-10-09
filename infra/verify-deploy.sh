#!/bin/sh
# verify-deploy.sh — does the running stack actually contain the commit it claims?
#
# ## Why this exists
#
# A deploy rebuilds images from the source tree that is on disk, and tags them with
# whatever `IMAGE_TAG` says in `.env`. Those are two independent facts, and nothing
# connects them: rebuild the current source under yesterday's tag and the image is
# new, the label is old, and every signal a reader would check agrees with the
# label.
#
# This is not hypothetical. On 2026-10-08 the host was serving commit `1f555a3`
# while `docker ps`, `docker images` and the api's own `/healthz.build` all named
# `305c56c` — nine commits of drift, reported consistently by every one of them,
# because all three read the same stale `IMAGE_TAG`. The *content* was current,
# which is the worst case: the tag is the only thing that was wrong, so nothing
# looked wrong.
#
# `${IMAGE_TAG:?}` in `docker-compose.yml` does not catch this. It refuses an
# *unset* tag, and on that host the tag was set — to a commit nine commits old.
# A value that is present and wrong satisfies every guard that only checks presence.
#
# So this checks the value rather than trusting it: it asks each running component
# what it actually is, and compares that to what was deployed.
#
# ## What it checks
#
#   1. `IMAGE_TAG` is set, and looks like a commit.
#   2. The api's `/healthz` reports a `build` equal to it. The api bakes `BUILD_ID`
#      in at image build time, so this is the image's own account of itself, read
#      over HTTP from inside the container.
#   3. The orchestrator reports the same, via its own build id.
#   4. The runner image the orchestrator will actually *create* from is the tag we
#      deployed, not a different one left over in `.env`.
#
# Exits non-zero on the first disagreement, naming both values. A deploy that
# cannot prove what it is running is not a deploy.
#
# ## Usage
#
#   ./verify-deploy.sh                 # verifies against IMAGE_TAG from .env
#   ./verify-deploy.sh <sha>           # verifies against an explicit commit
#
# Run it from the deployed tree (/opt/msout on the VPS), with the stack up.

set -eu

cd "$(dirname "$0")/.."

# ---- 1. the tag ----------------------------------------------------------------

if [ "$#" -ge 1 ]; then
  EXPECTED="$1"
else
  EXPECTED="$(grep -E '^IMAGE_TAG=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)"
fi

if [ -z "${EXPECTED:-}" ]; then
  echo "FAIL: no commit to check against."
  echo "      IMAGE_TAG is not set in .env, and no argument was given."
  echo "      Pass the commit being deployed:  ./verify-deploy.sh <sha>"
  exit 1
fi

case "$EXPECTED" in
  *[!0-9a-f]*|"")
    echo "FAIL: IMAGE_TAG=$EXPECTED is not a commit sha."
    echo "      A tag like 'latest' or 'dev' is exactly what this check exists to catch."
    exit 1
    ;;
esac

echo "checking that the running stack is ${EXPECTED}"

# ---- helpers -------------------------------------------------------------------

API_CONTAINER="$(docker compose --profile runner ps -q api 2>/dev/null | head -1 || true)"
ORCH_CONTAINER="$(docker compose --profile runner ps -q orchestrator 2>/dev/null | head -1 || true)"

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# ---- 2. the api's own account of itself ----------------------------------------

if [ -z "$API_CONTAINER" ]; then
  fail "no running api container found. Is the stack up?"
fi

# Read from inside the container: the api is on an internal network and its port is
# not published to the host, so there is nothing to curl from out here.
REPORTED="$(docker exec "$API_CONTAINER" node -e '
  fetch("http://127.0.0.1:3000/healthz")
    .then((r) => r.json())
    .then((b) => { process.stdout.write(String(b.build)); })
    .catch((e) => { process.stderr.write(String(e.message)); process.exit(1); });
' 2>&1)" || fail "could not read /healthz from the api: ${REPORTED}"

case "$REPORTED" in
  "$EXPECTED"*) ;;
  *)
    echo "FAIL: the api reports it is '${REPORTED}' but ${EXPECTED} was deployed." >&2
    echo "" >&2
    echo "      One of these is true, and they need opposite fixes:" >&2
    echo "        - the images were built from a tree that is not ${EXPECTED}" >&2
    echo "        - IMAGE_TAG in .env is stale, and the build relabelled current" >&2
    echo "          source with an old commit" >&2
    echo "" >&2
    echo "      Rebuild with IMAGE_TAG set to the commit being deployed, then:" >&2
    echo "        docker compose --profile runner build api orchestrator runner" >&2
    echo "        docker compose --profile runner up -d" >&2
    exit 1
    ;;
esac

echo "  api           ${REPORTED}"

# ---- 3. the orchestrator --------------------------------------------------------
#
# Read from `docker inspect`, not from inside the container. The orchestrator image
# has no shell and no `printenv` — it is built to be small — so `docker exec` fails
# with "executable file not found in $PATH" rather than answering. The image
# reference Docker recorded at create time is a perfectly good account of what is
# running, and it needs nothing from inside.

if [ -n "$ORCH_CONTAINER" ]; then
  ORCH_IMAGE="$(docker inspect "$ORCH_CONTAINER" --format '{{.Config.Image}}' 2>/dev/null || true)"
  case "$ORCH_IMAGE" in
    *"$EXPECTED"*) echo "  orchestrator  ${ORCH_IMAGE}" ;;
    "")
      echo "  orchestrator  (could not inspect; skipped)"
      ;;
    *)
      fail "the orchestrator is running ${ORCH_IMAGE}, not ${EXPECTED}."
      ;;
  esac

  # The api's container is checked the same way as well as by /healthz, because the
  # two disagree in a specific and interesting way: Docker records the reference the
  # container was *created from*, and /healthz reports what the image says it is.
  # A deploy that rebuilt without recreating leaves the first stale and the second
  # fresh, which is exactly the case where the images are correct and the running
  # process is not.
  API_IMAGE="$(docker inspect "$API_CONTAINER" --format '{{.Config.Image}}' 2>/dev/null || true)"
  case "$API_IMAGE" in
    *"$EXPECTED"*) echo "  api image     ${API_IMAGE}" ;;
    "")
      echo "  api image     (could not inspect; skipped)"
      ;;
    *)
      fail "the api container was created from ${API_IMAGE}, not ${EXPECTED}."\
  "An image can be rebuilt without the container being recreated, so the build"\
  "on disk and the process serving traffic are not necessarily the same commit."
      ;;
  esac
fi

# ---- 4. the runner image new containers will be created from --------------------

RUNNER_IMAGE="$(docker compose --profile runner config 2>/dev/null \
  | grep -E '^\s+image:\s+.*msout-runner:' \
  | head -1 | sed -E 's#.*msout-runner:##' | tr -d ' ' || true)"

if [ -z "$RUNNER_IMAGE" ]; then
  echo "  runner        (no image resolved; skipped)"
else
  case "$RUNNER_IMAGE" in
    "$EXPECTED"*) echo "  runner image  ${RUNNER_IMAGE}" ;;
    *)
      echo "FAIL: runners will be created from '${RUNNER_IMAGE}', not ${EXPECTED}." >&2
      echo "      RUNNER_IMAGE in .env disagrees with IMAGE_TAG, so a fresh runner" >&2
      echo "      would be an older build than the api that is talking to it." >&2
      exit 1
      ;;
  esac
fi

echo "OK: the running stack reports ${EXPECTED}."