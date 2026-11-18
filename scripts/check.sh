#!/usr/bin/env bash
# Runs the checks every change must pass: formatting, vet, lint, tests.
set -euo pipefail
cd "$(dirname "$0")/.."

# gofmt from the module's toolchain: formatting changes between Go releases.
gofmt="$(go env GOROOT)/bin/gofmt"
unformatted=$("$gofmt" -s -l .)
if [[ -n $unformatted ]]; then
	echo "gofmt needed:" >&2
	echo "$unformatted" >&2
	exit 1
fi
go vet ./...
if command -v golangci-lint >/dev/null; then
	golangci-lint run --build-tags integration ./...
else
	echo "golangci-lint not installed; skipping lint" >&2
fi
if command -v shellcheck >/dev/null; then
	shellcheck -x scripts/*.sh poc/*.sh packaging/*.sh
else
	echo "shellcheck not installed; skipping shell lint" >&2
fi
go test -race ./...
packaging/bootstrap_test.sh
scripts/conventional_test.sh
