#!/usr/bin/env bash
set -euo pipefail

# Run on the target host as root:
#   ./install.sh /path/to/bercert /path/to/.env
BIN="${1:-./bercert}"
ENVFILE="${2:-./.env}"
APP_DIR=/opt/bercert
UNIT_DIR=/etc/systemd/system
HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -x "$BIN" ]]; then
  echo "binary not found or not executable: $BIN" >&2
  exit 1
fi
if [[ ! -f "$ENVFILE" ]]; then
  echo "env file not found: $ENVFILE" >&2
  exit 1
fi

install -d -m 0755 "$APP_DIR"
install -m 0755 "$BIN" "$APP_DIR/bercert"
install -m 0600 "$ENVFILE" "$APP_DIR/.env"
install -m 0644 "$HERE/bercert.service" "$UNIT_DIR/bercert.service"

# Migrate from the old timer-based deployment, if present.
systemctl disable --now bercert.timer >/dev/null 2>&1 || true
rm -f "$UNIT_DIR/bercert.timer"

systemctl daemon-reload
systemctl enable bercert.service
systemctl restart bercert.service

echo "installed. service status:"
systemctl status bercert.service --no-pager -l | head -12 || true
echo
echo "logs:     journalctl -u bercert.service -f"
echo "restart:  systemctl restart bercert.service"
echo "disable:  systemctl disable --now bercert.service"
