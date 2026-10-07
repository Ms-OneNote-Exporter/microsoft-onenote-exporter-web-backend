# The orchestrator image.
#
# The only container in this project that holds /var/run/docker.sock, so the
# build is minimal on purpose: a static binary on a distroless base, no shell, no
# package manager, no curl. An attacker who reaches code execution in this
# process gets the verb allowlist and nothing else, and an attacker who reaches
# the filesystem gets an image with almost nothing on it.
#
# CGO_ENABLED=0 in the builder makes the binary static, so the runtime stage needs
# no libc at all (orchestrator/README.md#language-go).

# ---- build ----------------------------------------------------------------
FROM golang:1.25-alpine AS build

WORKDIR /src

# go.mod is copied alone first so the dependency layer is cached independently
# of the source. There is no `go mod download` step because there are no
# dependencies to download — the zero-dep property is what makes that possible.
COPY go.mod ./
COPY main.go ./
COPY internal ./internal

# -trimpath strips local filesystem paths from the binary, so a build artifact
# does not carry the builder's directory layout.
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/orchestrator .

# Confirm the zero-dependency property at build time rather than trusting it. A
# stray import of a third-party package fails here with a clear message instead
# of shipping and being discovered during review.
RUN if go list -m all | tail -n +2 | grep -q .; then \
      echo 'FAIL: module graph is not just this module'; \
      go list -m all; \
      exit 1; \
    fi

# The directory tree copied into the runtime image below. Built here because the
# runtime stage has no shell to create it with.
#
# The paths must be exactly `ORCH_VAULT_ROOT` and `ORCH_ARTIFACT_ROOT`'s parent, or
# exactly where `docker-compose.yml` mounts the volumes — all three agree on
# `/srv/msout/{vault,artifacts}`, and this line **was `/out/srv/{vault,artifacts}`**.
# So the directories below were never the ones being mounted, Docker had nothing to
# seed a fresh volume from, and the first real login failed:
#
#     mkdir /srv/msout/vault: permission denied
#
# with `/healthz` reporting `ok` throughout. `.github/assert-compose.mjs` now
# cross-checks this line against the compose mount targets, because three files
# naming the same path independently is how it drifted.
RUN mkdir -p /out/srv/msout/vault /out/srv/msout/artifacts

# ---- runtime --------------------------------------------------------------
# distroless/static has no shell and no package manager. The orchestrator never
# execs anything, so there is no reason to ship the means to.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/orchestrator /usr/local/bin/orchestrator

# The artifact and vault roots, so a fresh named volume inherits their ownership.
#
# Same reasoning as the api's database directory, and the same failure otherwise:
# Docker seeds a new named volume from the image's directory *and its ownership*, so
# a path absent from the image produces a root-owned volume that a container
# running as uid 65532 cannot write to.
#
# Built in the `build` stage and copied, NOT created with a RUN here: distroless has
# no shell, so a `RUN mkdir` in this stage is the same class of bug as the one this
# line exists to fix — a Dockerfile instruction that reads correctly and cannot
# execute. `--chown` sets the ownership at copy time, so nothing needs root at
# runtime.

# `nonroot` is distroless's uid 65532, the same user the container runs as.
#
# Copied to `/srv`, so the image's directories land at `/srv/msout/{vault,artifacts}`
# — the paths `ORCH_VAULT_ROOT` and `ORCH_ARTIFACT_ROOT` default to and the paths
# `docker-compose.yml` mounts. All three names must agree; CI asserts it.
COPY --from=build --chown=nonroot:nonroot /out/srv /srv

# Non-root. The Docker socket is the privilege here, not the uid; running as
# nonroot keeps everything else unprivileged (PLAN-v3 §2.1).
USER nonroot:nonroot

EXPOSE 9100

ENTRYPOINT ["/usr/local/bin/orchestrator"]