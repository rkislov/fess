#!/bin/sh
set -eu
getent group fess >/dev/null || groupadd --system fess
getent group fess-av >/dev/null || groupadd --system fess-av
id fess >/dev/null 2>&1 || useradd --system --gid fess --home-dir /var/lib/fess --shell /usr/sbin/nologin fess
id fess-av >/dev/null 2>&1 || useradd --system --gid fess-av --home-dir /var/lib/fess-clamav --shell /usr/sbin/nologin fess-av
usermod -a -G fess-av fess
# Keep Ubuntu's packaged ClamAV AppArmor profiles enabled with native FESS paths.
if command -v apparmor_parser >/dev/null 2>&1; then
 for daemon in clamd freshclam; do
  case "$daemon" in clamd) profile=usr.sbin.clamd;; freshclam) profile=usr.bin.freshclam;; esac
  if [ -f "/etc/apparmor.d/$profile" ]; then
   mkdir -p /etc/apparmor.d/local
   local_profile="/etc/apparmor.d/local/$profile"
   if ! grep -q '^# BEGIN FESS native paths$' "$local_profile" 2>/dev/null; then
    cat >> "$local_profile" <<EOF
# BEGIN FESS native paths
/etc/fess/$daemon.conf r,
/var/lib/fess-clamav/ r,
/var/lib/fess-clamav/** krw,
/run/fess-clamav/ rw,
/run/fess-clamav/** rw,
# END FESS native paths
EOF
   fi
   apparmor_parser -r "/etc/apparmor.d/$profile"
  fi
 done
fi
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
 systemctl daemon-reload
 systemctl enable fess.service
 # try-restart updates an existing installation; first installation is started explicitly.
 systemctl try-restart fess.service || true
fi
