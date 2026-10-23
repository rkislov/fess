#!/bin/sh
set -eu
# Start only the local controller. Packet filtering remains explicit opt-in.
getent group fess >/dev/null || groupadd --system fess
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
 systemctl daemon-reload
 systemctl enable fess-xdp-control.service
 systemctl restart fess-xdp-control.service
 systemctl try-restart fess-xdp.service || true
fi
