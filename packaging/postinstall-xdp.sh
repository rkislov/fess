#!/bin/sh
set -eu
# Explicit opt-in: never enable or attach a packet filter during installation.
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
 systemctl daemon-reload
 systemctl try-restart fess-xdp.service || true
fi
