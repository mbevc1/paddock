#!/usr/bin/env bash
# Builds the paddock RPM for one architecture from a static binary.
# Usage: scripts/build-rpm.sh VERSION ARCH [OWNER]
#   VERSION  release version without the leading v, for example 0.1.0
#   ARCH     x86_64 or aarch64
#   OWNER    GitHub owner for the package URL (default: owner)
# The binary is built here unless dist/paddock-ARCH exists. RPMs land in dist/.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:?usage: build-rpm.sh VERSION ARCH [OWNER]}
arch=${2:?usage: build-rpm.sh VERSION ARCH [OWNER]}
owner=${3:-owner}
case $arch in
x86_64) goarch=amd64 ;;
aarch64) goarch=arm64 ;;
*) echo "unsupported architecture: $arch" >&2 && exit 2 ;;
esac
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "version must look like 1.2.3, got $version" >&2
	exit 2
fi

mkdir -p dist
binary=dist/paddock-$arch
if [[ ! -x $binary ]]; then
	CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -trimpath \
		-ldflags "-s -w -X main.version=$version" -o "$binary" ./cmd/paddock
fi

top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT
stage=$top/paddock-$version
mkdir -p "$stage" "$top/SOURCES"
cp "$binary" "$stage/paddock"
cp -r deploy LICENSE README.md "$stage/"
tar -C "$top" -czf "$top/SOURCES/paddock-$version.tar.gz" "paddock-$version"
cp deploy/sysusers.d/paddock.conf "$top/SOURCES/paddock.sysusers"

# RPM_EXTRA_ARGS adds rpmbuild options, for example a macro file on hosts without
# systemd-rpm-macros.
read -ra extra <<<"${RPM_EXTRA_ARGS:-}"
rpmbuild -bb packaging/paddock.spec \
	--target "$arch" \
	--define "_topdir $top" \
	--define "pkg_version $version" \
	--define "owner $owner" \
	"${extra[@]}"
find "$top/RPMS" -name '*.rpm' -exec cp {} dist/ \;
ls -1 dist/*.rpm
