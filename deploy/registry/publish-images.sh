#!/usr/bin/env bash
# Собрать образы FESS и зеркалировать postgres/redis/clamav в свой registry.
# Запуск с машины, где есть сеть до Docker Hub / GOPROXY:
#   docker login 85.137.24.140:5000 -u fess
#   ./deploy/registry/publish-images.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REG="${FENCE_REGISTRY:-85.137.24.140:5000}"
TAG="${FENCE_IMAGE_TAG:-latest}"
cd "$ROOT"

echo ">> mirror Hub images → ${REG}"
for src_dst in \
  "postgres:15|${REG}/library/postgres:15" \
  "redis:7|${REG}/library/redis:7" \
  "opencloudeu/clamav-icap:latest|${REG}/opencloudeu/clamav-icap:latest"
do
  src="${src_dst%%|*}"
  dst="${src_dst##*|}"
  docker pull "$src"
  docker tag "$src" "$dst"
  docker push "$dst"
done

echo ">> build FESS images (tag ${TAG})"
export FENCE_REGISTRY="$REG" FENCE_IMAGE_TAG="$TAG"
docker compose -f deploy/docker-compose.yml build policy-api waf-gateway ui
for svc in policy-api waf-gateway ui; do
  docker push "${REG}/fess/${svc}:${TAG}"
  if [ "$TAG" != "latest" ]; then
    docker tag "${REG}/fess/${svc}:${TAG}" "${REG}/fess/${svc}:latest"
    docker push "${REG}/fess/${svc}:latest"
  fi
done
echo ">> done. Install: FENCE_IMAGE_TAG=${TAG} docker compose -f deploy/docker-compose.yml pull && up -d"
