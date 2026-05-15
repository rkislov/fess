#!/bin/sh
# opencloudeu/clamav-icap ships clamd with LocalSocket only; policy-api cannot read VERSION
# (signature / engine line) from another container. Append TCPSocket so clamd also listens
# on 3310 inside the Docker network. Do not publish 3310 to the host unless you trust the network.
#
# The image runs as USER clamav — /etc/clamav/clamd.conf is not writable. Use a copy under /tmp
# and clamd --config-file=… instead of appending to /etc.
#
# c-icap: do NOT append MaxObjectSize / clamav_mod.* to the main c-icap.conf (fatal parse error).
# This image sets virus_scan MaxObjectSize in /etc/c-icap/virus_scan.conf (see c-icap startup logs).
set -e

CLAMD_SOCKET=/var/run/clamav/clamd.ctl

wait_clamd_ready() {
  n=0
  while [ "$n" -lt 90 ]; do
    if [ -S "$CLAMD_SOCKET" ]; then
      return 0
    fi
    n=$((n + 1))
    sleep 2
  done
  echo "WARN: clamd socket $CLAMD_SOCKET not ready after 180s; starting c-icap anyway"
  return 0
}

CLAMD_CFG=/etc/clamav/clamd.conf
if ! grep -qE '^[[:space:]]*TCPSocket[[:space:]]' "$CLAMD_CFG" 2>/dev/null; then
  CLAMD_CFG=/tmp/clamd-fence-tcp.conf
  cp /etc/clamav/clamd.conf "$CLAMD_CFG"
  printf '\n# fence: clamd TCP for diagnostics (VERSION) from policy-api on Docker network\nTCPSocket 3310\nTCPAddr 0.0.0.0\n' >> "$CLAMD_CFG"
fi
if ! grep -qE '^[[:space:]]*StreamMaxLength[[:space:]]' "$CLAMD_CFG" 2>/dev/null; then
  printf '\n# fence: allow scanning bodies up to waf-gateway body_scan.max_bytes\nStreamMaxLength 32M\nMaxFileSize 32M\n' >> "$CLAMD_CFG"
fi

# Do not block ICAP on a full freshclam run (can take 15+ minutes on first boot).
echo "INFO: Starting freshclam (background; ICAP will start with bundled DB)"
freshclam -d -c 6 &

echo "INFO: Starting clamd (config $CLAMD_CFG)"
clamd -c "$CLAMD_CFG"
wait_clamd_ready

echo "INFO: Starting c-icap (stock /etc/c-icap/c-icap.conf; limits in virus_scan.conf)"
exec c-icap -f /etc/c-icap/c-icap.conf -D -N
