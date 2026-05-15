#!/bin/sh
# opencloudeu/clamav-icap ships clamd with LocalSocket only; policy-api cannot read VERSION
# (signature / engine line) from another container. Append TCPSocket so clamd also listens
# on 3310 inside the Docker network. Do not publish 3310 to the host unless you trust the network.
#
# The image runs as USER clamav — /etc/clamav/clamd.conf is not writable. Use a copy under /tmp
# and clamd --config-file=… instead of appending to /etc.
#
# c-icap default MaxObjectSize is ~5MB; Fence body_scan allows up to 20MB — raise limits here
# or ICAP closes the TCP session (connection reset by peer) on larger uploads.
set -e

# Match deploy default body_scan.max_bytes (20 MiB) with headroom for ICAP overhead.
FENCE_MAX_OBJECT_BYTES=33554432

CLAMD_CFG=/etc/clamav/clamd.conf
if ! grep -qE '^[[:space:]]*TCPSocket[[:space:]]' "$CLAMD_CFG" 2>/dev/null; then
  CLAMD_CFG=/tmp/clamd-fence-tcp.conf
  cp /etc/clamav/clamd.conf "$CLAMD_CFG"
  printf '\n# fence: clamd TCP for diagnostics (VERSION) from policy-api on Docker network\nTCPSocket 3310\nTCPAddr 0.0.0.0\n' >> "$CLAMD_CFG"
fi
if ! grep -qE '^[[:space:]]*StreamMaxLength[[:space:]]' "$CLAMD_CFG" 2>/dev/null; then
  printf '\n# fence: allow scanning bodies up to waf-gateway body_scan.max_bytes\nStreamMaxLength 32M\nMaxFileSize 32M\n' >> "$CLAMD_CFG"
fi

echo "INFO: Starting freshclam"
freshclam -d -c 6

echo "INFO: Starting clamd (config $CLAMD_CFG)"
clamd -c "$CLAMD_CFG"

CICAP_CFG=/tmp/c-icap-fence.conf
cp /etc/c-icap/c-icap.conf "$CICAP_CFG"
{
  echo ""
  echo "# fence: default c-icap MaxObjectSize is 5MB — Nextcloud uploads exceed that without this"
  echo "MaxObjectSize ${FENCE_MAX_OBJECT_BYTES}"
} >> "$CICAP_CFG"

if [ -f /etc/c-icap/c-icap_modules.conf ]; then
  CICAP_MOD=/tmp/c-icap-modules-fence.conf
  cp /etc/c-icap/c-icap_modules.conf "$CICAP_MOD"
  if ! grep -q 'clamav_mod.MaxScanSize' "$CICAP_MOD" 2>/dev/null; then
    {
      echo ""
      echo "# fence"
      echo "clamav_mod.MaxScanSize ${FENCE_MAX_OBJECT_BYTES}"
    } >> "$CICAP_MOD"
  fi
  if ! grep -q 'Include.*c-icap-modules-fence' "$CICAP_CFG" 2>/dev/null; then
    echo "Include $CICAP_MOD" >> "$CICAP_CFG"
  fi
fi

echo "INFO: Starting c-icap (config $CICAP_CFG, MaxObjectSize=${FENCE_MAX_OBJECT_BYTES})"
exec c-icap -f "$CICAP_CFG" -D -N
