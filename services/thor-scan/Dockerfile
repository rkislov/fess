# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
RUN set -eux; \
  arch="${TARGETARCH:-$(uname -m)}"; \
  case "$arch" in arm64|aarch64) GOARCH=arm64 ;; amd64|x86_64) GOARCH=amd64 ;; *) echo "unsupported: $arch" >&2; exit 1 ;; esac; \
  CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${GOARCH}" go build -o /out/thor-scan ./services/thor-scan

FROM alpine:3.20
RUN apk add --no-cache wget ca-certificates
WORKDIR /opt/thor
ENV THOR_DIR=/opt/thor
ENV THOR_BIN=/opt/thor/thor64
EXPOSE 8830
COPY --from=builder /out/thor-scan /usr/local/bin/thor-scan
ENTRYPOINT ["/usr/local/bin/thor-scan"]
