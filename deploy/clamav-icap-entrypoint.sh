#!/bin/sh
# opencloudeu/clamav-icap ships clamd with LocalSocket only; policy-api cannot read VERSION
# (signature / engine line) from another container. Append TCPSocket so clamd also listens
# on 3310 inside the Docker network. Do not publish 3310 to the host unless you trust the network.
set -e
if ! grep -qE '^[[:space:]]*TCPSocket[[:space:]]' /etc/clamav/clamd.conf 2>/dev/null; then
  printf '\n# fence: clamd TCP for diagnostics (VERSION) from policy-api on Docker network\nTCPSocket 3310\nTCPAddr 0.0.0.0\n' >> /etc/clamav/clamd.conf
fi

echo "INFO: Starting freshclam"
freshclam -d -c 6

echo "INFO: Starting clamd"
clamd

echo "INFO: Starting c-icap"
exec c-icap -f /etc/c-icap/c-icap.conf -D -N
