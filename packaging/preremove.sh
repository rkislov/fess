#!/bin/sh
set -eu
# Preserve running services on package upgrades (deb: upgrade; rpm: 1).
case "${1:-}" in remove|purge|0)
 if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  systemctl disable --now fess.service fess-clamd.service fess-freshclam.service || true
 fi
 ;; esac
