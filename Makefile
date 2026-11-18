.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# RPM versions must be X.Y.Z; releases take theirs from the tag.
RPM_VERSION ?= 0.0.0
ARCH ?= x86_64
OWNER ?= owner

# gofmt from the module's toolchain: formatting changes between Go releases.
GOFMT = $(shell go env GOROOT)/bin/gofmt
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: help build test vet fmt fmt-check lint shellcheck bootstrap-test check integration rpm clean

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{ printf "  %-15s %s\n", $$1, $$2 }'

build: ## build ./paddock as a static binary
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o paddock ./cmd/paddock

test: ## run the unit tests with the race detector
	go test -race ./...

vet: ## run go vet, integration tests included
	go vet -tags integration ./...

fmt: ## format the Go code
	$(GOFMT) -s -w .

fmt-check: ## fail if Go code needs formatting
	@out=$$($(GOFMT) -s -l .); if [[ -n $$out ]]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: ## run golangci-lint
	golangci-lint run --build-tags integration ./...

shellcheck: ## lint the shell scripts
	shellcheck -x scripts/*.sh poc/*.sh packaging/*.sh

bootstrap-test: ## test bootstrap.sh's host-independent functions
	packaging/bootstrap_test.sh

check: ## run every check a change must pass (scripts/check.sh)
	scripts/check.sh

integration: ## run the integration tests: as root on the test VM only
	@if [[ $${PADDOCK_INTEGRATION:-} != 1 ]]; then echo "set PADDOCK_INTEGRATION=1 and run as root on the test VM"; exit 1; fi
	go test -tags integration -count=1 ./test/integration/...

rpm: ## build dist/paddock-RPM_VERSION-1.el9.ARCH.rpm (needs rpmbuild)
	scripts/build-rpm.sh $(RPM_VERSION) $(ARCH) $(OWNER)

clean: ## remove build output
	rm -rf paddock dist
