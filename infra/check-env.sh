#!/bin/sh
# Pre-flight for the deploy: is /opt/msout/.env actually usable?
#
# Why this exists
#
# A `.env` line holding an unexpanded shell substitution is a **total, silent**
# outage. Compose interpolates `${VAR}` and never expands `$(...)`, so a line like
#
#     RUNNER_IMAGE=ghcr.io/ms-one-note-exporter/msout-runner:$(git -C /opt/msout rev-parse HEAD)
#
# reaches the orchestrator's environment verbatim, the Docker Engine rejects every
# create with `400 invalid reference format`, the pool holds no containers, and
# every login answers `409 the service's view of its runner pool is out of date`.
# The only signal is a 400 in the orchestrator's log, every ten seconds, in a
# component nobody reads until a user complains. Observed 2026-10-13 on the
# deployed host; it cost the best part of an afternoon.
#
# verify-deploy.sh catches it too, but at the END of a deploy, and with a message
# that names the wrong cause. This runs FIRST, so the failure is one command into
# the sequence rather than one command from the end of it.
#
# Usage: cd /opt/msout && sh infra/check-env.sh
# Exits 0 when the deploy can proceed; 1 with the exact line to fix otherwise.

set -u

ENV_FILE="${1:-.env}"

if [ ! -f "$ENV_FILE" ]; then
    echo "check-env: no $ENV_FILE here (expected to run from /opt/msout)" >&2
    exit 1
fi

fail() {
    echo "check-env: FAIL $1" >&2
    echo "            $2" >&2
    exit 1
}

# A Docker image reference: no whitespace, no shell substitution, no parentheses,
# no leading dash. Deliberately not a full grammar - the Engine's is not worth
# reproducing here - it is the four shapes that occur in practice and the one that
# cannot work.
check_reference() {
    name="$1"
    value="$2"
    [ -n "$value" ] || fail "$name is empty" "set it in $ENV_FILE"
    case "$value" in
        *'$'*|*'('*|*')'*|*' '*|*'	'*)
            fail "$name is not an image reference: '$value'" \
                 "it contains a shell substitution or whitespace; .env values are literal"
            ;;
        -*)
            fail "$name starts with a dash: '$value'" \
                 "an image reference begins with a repository name"
            ;;
    esac
}

IMAGE_TAG="$(sed -n 's/^IMAGE_TAG=//p' "$ENV_FILE" | head -1)"
RUNNER_IMAGE="$(sed -n 's/^RUNNER_IMAGE=//p' "$ENV_FILE" | head -1)"

check_reference "IMAGE_TAG" "$IMAGE_TAG"
check_reference "RUNNER_IMAGE" "$RUNNER_IMAGE"

# The trap verify-deploy.sh already knows about, one step earlier: the two must
# name the same commit. The runner is created from RUNNER_IMAGE while everything
# else runs IMAGE_TAG, so a disagreement ships runners older than the api.
if [ "$RUNNER_IMAGE" != "ghcr.io/ms-one-note-exporter/msout-runner:${IMAGE_TAG}" ]; then
    fail "RUNNER_IMAGE does not match IMAGE_TAG" \
         "set RUNNER_IMAGE=ghcr.io/ms-one-note-exporter/msout-runner:${IMAGE_TAG}"
fi

echo "check-env: OK  IMAGE_TAG=${IMAGE_TAG}"
echo "check-env: OK  RUNNER_IMAGE=${RUNNER_IMAGE}"
