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

# ---- runtime --------------------------------------------------------------
# distroless/static has no shell and no package manager. The orchestrator never
# execs anything, so there is no reason to ship the means to.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/orchestrator /usr/local/bin/orchestrator

# Non-root. The Docker socket is the privilege here, not the uid; running as
# nonroot keeps everything else unprivileged (PLAN-v3 §2.1).
USER nonroot:nonroot

EXPOSE 9100

ENTRYPOINT ["/usr/local/bin/orchestrator"]