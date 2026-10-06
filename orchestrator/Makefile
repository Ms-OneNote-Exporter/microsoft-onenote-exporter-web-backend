# Orchestrator build. Zero third-party dependencies, so there is no lockfile and
# no vendor directory — `go.mod` having no `require` block is the assertion, and
# CI checks it.
#
# CGO_ENABLED=0 makes the binary static with no libc, which is what lets the
# runner claim a dependency-free static binary without pulling in a C toolchain
# at build time (orchestrator/README.md#language-go).

GO      ?= go
BIN     ?= dist/orchestrator
PKG     := ./...
LDFLAGS := -s -w

.PHONY: all build test race vet fmt check clean deps-zero

all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) .

test:
	$(GO) test $(PKG)

race:
	$(GO) test -race $(PKG)

vet:
	$(GO) vet $(PKG)

fmt:
	$(GO) fmt $(PKG)

check: deps-zero vet test

# deps-zero fails if go.mod ever grows a require block. This is the mechanical
# form of "the orchestrator's audit surface is its own source" — see
# orchestrator/README.md#language-go.
deps-zero:
	@if grep -qE '^[[:space:]]*require' go.mod; then \
		echo 'FAIL: go.mod has a require block.'; \
		echo 'The orchestrator is the only holder of the Docker socket. A new'; \
		echo 'dependency must come with a line in PLANNING/PLAN-v3.md explaining'; \
		echo 'why the audit surface grew.'; \
		exit 1; \
	fi
	@if [ -d vendor ]; then \
		echo 'FAIL: vendor/ exists. The orchestrator vendors nothing.'; \
		exit 1; \
	fi
	@echo 'ok  zero third-party dependencies'

clean:
	rm -rf dist