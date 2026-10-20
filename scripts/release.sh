#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${FESS_VERSION:?Set FESS_VERSION}"
export FESS_VERSION
scripts/build.sh
for arch in amd64 arm64; do
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$FESS_VERSION" -o "dist/fess-linux-$arch" ./cmd/fess
 CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$FESS_VERSION" -o "dist/fess-darwin-$arch" ./cmd/fess
 for platform in linux darwin; do
  stage=$(mktemp -d)
  cp "dist/fess-$platform-$arch" "$stage/fess"
  cp LICENSE NOTICE README.md "$stage/"
  tar -czf "dist/fess_${FESS_VERSION}_${platform}_${arch}.tar.gz" -C "$stage" .
  rm -rf "$stage"
 done
 (cd packaging && FESS_ARCH="$arch" nfpm package --packager deb --target ../dist/ && FESS_ARCH="$arch" nfpm package --packager rpm --target ../dist/)
done
(cd dist && shasum -a 256 *.tar.gz *.deb *.rpm > SHA256SUMS)
