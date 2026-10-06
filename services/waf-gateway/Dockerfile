# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder

# If proxy.golang.org times out (common on restricted networks), set at build:
#   docker compose -f deploy/docker-compose.yml build --build-arg GOPROXY=https://goproxy.io,direct
ARG GOPROXY=https://proxy.golang.org,direct
ARG GOSUMDB=sum.golang.org
ENV GOPROXY=${GOPROXY} GOSUMDB=${GOSUMDB}

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
RUN set -eux; \
  arch="${TARGETARCH:-$(uname -m)}"; \
  case "$arch" in arm64|aarch64) GOARCH=arm64 ;; amd64|x86_64) GOARCH=amd64 ;; riscv64) GOARCH=riscv64 ;; ppc64le) GOARCH=ppc64le ;; *) echo "unsupported TARGETARCH/uname: $arch" >&2; exit 1 ;; esac; \
  CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${GOARCH}" go build -o /out/waf-gateway ./services/waf-gateway

FROM alpine:3.20
RUN apk add --no-cache libcap \
  && adduser -D -g "" appuser
RUN mkdir -p /var/lib/fence/geoip && chown appuser:appuser /var/lib/fence/geoip
WORKDIR /app
COPY --from=builder /out/waf-gateway /usr/local/bin/waf-gateway
# Allow non-root bind to :80 / :443
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/waf-gateway
USER appuser
EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/waf-gateway"]
