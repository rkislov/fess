#!/bin/sh
# Build the static Linux binaries and distribution artifacts for one CPU ABI.
set -eu
cd "$(dirname "$0")/.."
: "${FESS_VERSION:?Set FESS_VERSION}"
target=${1:?Specify a Linux target}
out=${2:?Specify an absolute output directory}
export CGO_ENABLED=0 GOOS=linux GOARCH="$target" FESS_ARCH="$target"
case "$target" in
 arm5) export GOARCH=arm GOARM=5,softfloat ;;
 arm7) export GOARCH=arm GOARM=7,hardfloat ;;
 386) export GO386=softfloat ;;
 mips|mipsle) export GOMIPS=softfloat ;;
 mips64|mips64le) export GOMIPS64=softfloat ;;
esac
mkdir -p dist "$out"
for app in fess fess-xdp; do
 go build -trimpath -ldflags "-s -w -X main.version=$FESS_VERSION" -o "dist/$app-linux-$target" "./cmd/$app"
done
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/fess/docs" "$stage/xdp"
cp "dist/fess-linux-$target" "$stage/fess/fess"
cp LICENSE NOTICE README.md "$stage/fess/"
cp docs/admin-guide.md docs/openapi.yaml "$stage/fess/docs/"
tar -czf "$out/fess_${FESS_VERSION}_linux_$target.tar.gz" -C "$stage/fess" .
cp "dist/fess-xdp-linux-$target" "$stage/xdp/fess-xdp"
cp LICENSE NOTICE packaging/xdp.json.example packaging/systemd/fess-xdp*.service "$stage/xdp/"
cp docs/xdp.md "$stage/xdp/README.md"
tar -czf "$out/fess-xdp_${FESS_VERSION}_linux_$target.tar.gz" -C "$stage/xdp" .
for config in nfpm.yaml nfpm-xdp.yaml; do
 for format in deb rpm; do
  pack_config=$config
  if [ "$target:$format" = loong64:rpm ]; then
   pack_config="$stage/$config"
   sed 's/^arch: .*/arch: loongarch64/' "packaging/$config" > "$pack_config"
  fi
  (cd packaging && nfpm package -f "$pack_config" --packager "$format" --target "$out/")
 done
done
