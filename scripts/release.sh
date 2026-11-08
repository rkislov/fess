#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${FESS_VERSION:?Set FESS_VERSION}"
export FESS_VERSION
scripts/build.sh
release_dir="$(pwd)/dist/releases/$FESS_VERSION"
mkdir -p "$release_dir"
for target in 386 amd64 arm5 arm7 arm64 loong64 mips mipsle mips64 mips64le ppc64 ppc64le riscv64 s390x; do
 scripts/package-linux.sh "$target" "$release_dir"
done
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/darwin/docs" "$stage/source"
cp LICENSE NOTICE README.md "$stage/darwin/"
cp docs/admin-guide.md docs/waf-feed.md docs/openapi.yaml "$stage/darwin/docs/"
for arch in amd64 arm64; do
 CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$FESS_VERSION" -o "$stage/darwin/fess" ./cmd/fess
 tar -czf "$release_dir/fess_${FESS_VERSION}_darwin_$arch.tar.gz" -C "$stage/darwin" .
done
# Include the built UI and both checked-in BPF objects for native source builds.
git archive -o "$stage/tracked.tar" HEAD
tar -xf "$stage/tracked.tar" -C "$stage/source"
cp -R ui/dist/. "$stage/source/ui/dist/"
tar -czf "$release_dir/fess_${FESS_VERSION}_source.tar.gz" -C "$stage/source" .
(cd "$release_dir" && shasum -a 256 *.tar.gz *.deb *.rpm > SHA256SUMS)
