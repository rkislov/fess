#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${FESS_VERSION:?Set FESS_VERSION}"
export FESS_VERSION
scripts/build.sh
release_dir="$(pwd)/dist/releases/$FESS_VERSION"
mkdir -p "$release_dir"
for arch in amd64 arm64; do
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$FESS_VERSION" -o "dist/fess-linux-$arch" ./cmd/fess
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$FESS_VERSION" -o "dist/fess-xdp-linux-$arch" ./cmd/fess-xdp
 CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$FESS_VERSION" -o "dist/fess-darwin-$arch" ./cmd/fess
 for platform in linux darwin; do
  stage=$(mktemp -d)
  cp "dist/fess-$platform-$arch" "$stage/fess"
  cp LICENSE NOTICE README.md "$stage/"
  mkdir -p "$stage/docs"
  cp docs/admin-guide.md docs/openapi.yaml "$stage/docs/"
  tar -czf "$release_dir/fess_${FESS_VERSION}_${platform}_${arch}.tar.gz" -C "$stage" .
  rm -rf "$stage"
 done
 stage=$(mktemp -d)
 cp "dist/fess-xdp-linux-$arch" "$stage/fess-xdp"
 cp LICENSE NOTICE "$stage/"
 cp docs/xdp.md "$stage/README.md"
 cp packaging/xdp.json.example packaging/systemd/fess-xdp.service packaging/systemd/fess-xdp-control.service "$stage/"
 tar -czf "$release_dir/fess-xdp_${FESS_VERSION}_linux_${arch}.tar.gz" -C "$stage" .
 rm -rf "$stage"
 for config in nfpm.yaml nfpm-xdp.yaml; do
  (cd packaging && FESS_ARCH="$arch" nfpm package -f "$config" --packager deb --target "$release_dir/" && FESS_ARCH="$arch" nfpm package -f "$config" --packager rpm --target "$release_dir/")
 done
done
(cd "$release_dir" && shasum -a 256 *.tar.gz *.deb *.rpm > SHA256SUMS)
