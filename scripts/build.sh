#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
(cd ui && npm ci && npm run generate)
rm -rf ui/dist
cp -R ui/.output/public ui/dist
mkdir -p dist
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${FESS_VERSION:-dev}" -o dist/fess ./cmd/fess
