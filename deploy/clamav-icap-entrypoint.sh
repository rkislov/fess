#!/bin/sh
# opencloudeu/clamav-icap ships clamd with LocalSocket only; policy-api cannot read VERSION
# (signature / engine line) from another container. Append TCPSocket so clamd also listens
# on 3310 inside the Docker network. Do not publish 3310 to the host unless you trust the network.
#
# The image runs as USER clamav — /etc/clamav/clamd.conf is not writable. Use a copy under /tmp
# and clamd --config-file=… instead of appending to /etc.
set -e
CLAMD_CFG=/etc/clamav/clamd.conf
if ! grep -qE '^[[:space:]]*TCPSocket[[:space:]]' "$CLAMD_CFG" 2>/dev/null; then
  CLAMD_CFG=/tmp/clamd-fence-tcp.conf
  cp /etc/clamav/clamd.conf "$CLAMD_CFG"
  printf '\n# fence: clamd TCP for diagnostics (VERSION) from policy-api on Docker network\nTCPSocket 3310\nTCPAddr 0.0.0.0\n' >> "$CLAMD_CFG"
fi

echo "INFO: Starting freshclam"
freshclam -d -c 6

echo "INFO: Starting clamd (config $CLAMD_CFG)"
clamd -c "$CLAMD_CFG"

echo "INFO: Starting c-icap"
exec c-icap -f /etc/c-icap/c-icap.conf -D -N
