# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder

# Official proxy.golang.org is often unreachable (DNS timeout). Override via compose/env:
#   GOPROXY=https://goproxy.io,direct
ARG GOPROXY=https://goproxy.io,https://goproxy.cn,direct
ARG GOSUMDB=off
ENV GOPROXY=${GOPROXY} GOSUMDB=${GOSUMDB}

WORKDIR /src
COPY go.mod go.sum ./
RUN apk add --no-cache git ca-certificates \
  && go mod download \
  || GOPROXY=https://goproxy.io,direct GOSUMDB=off go mod download \
  || GOPROXY=https://goproxy.cn,direct GOSUMDB=off go mod download \
  || GOPROXY=direct GOSUMDB=off go mod download

COPY . .
# Multi-arch: BuildKit sets TARGETARCH (e.g. arm64 on Apple Silicon). Fallback uses builder uname.
ARG TARGETOS=linux
ARG TARGETARCH
RUN set -eux; \
  arch="${TARGETARCH:-$(uname -m)}"; \
  case "$arch" in arm64|aarch64) GOARCH=arm64 ;; amd64|x86_64) GOARCH=amd64 ;; riscv64) GOARCH=riscv64 ;; ppc64le) GOARCH=ppc64le ;; *) echo "unsupported TARGETARCH/uname: $arch" >&2; exit 1 ;; esac; \
  CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${GOARCH}" go build -o /out/policy-api ./services/policy-api

FROM alpine:3.20
RUN apk add --no-cache wget
RUN adduser -D -g "" appuser && addgroup appuser root
RUN mkdir -p /var/lib/fence/geoip && chown appuser:appuser /var/lib/fence/geoip
WORKDIR /app
COPY --from=builder /out/policy-api /usr/local/bin/policy-api
USER appuser
EXPOSE 8082
ENTRYPOINT ["/usr/local/bin/policy-api"]
