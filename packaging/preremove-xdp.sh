#!/bin/sh
set -eu
case "${1:-}" in remove|purge|0)
 if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  systemctl disable --now fess-xdp-control.service fess-xdp.service || true
 fi
 ;; esac
