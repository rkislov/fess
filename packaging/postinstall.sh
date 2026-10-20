#!/bin/sh
set -eu
getent group fess >/dev/null || groupadd --system fess
getent group fess-av >/dev/null || groupadd --system fess-av
id fess >/dev/null 2>&1 || useradd --system --gid fess --home-dir /var/lib/fess --shell /usr/sbin/nologin fess
id fess-av >/dev/null 2>&1 || useradd --system --gid fess-av --home-dir /var/lib/fess-clamav --shell /usr/sbin/nologin fess-av
usermod -a -G fess-av fess
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
 systemctl daemon-reload
 systemctl enable fess.service
 # try-restart updates an existing installation; first installation is started explicitly.
 systemctl try-restart fess.service || true
fi
