#!/bin/bash
# OpenNoFrp Server uninstaller (Linux, cloud machine).
#
# Whitelist-only removal, per docs/02-risk-assessment.md section 5:
#   - stops + disables opennofrp-server.service
#   - removes exactly: /etc/systemd/system/opennofrp-server.service,
#     /opt/opennofrp/
#   - does NOT remove /etc/opennofrp/server.toml by default (pass
#     --purge-config to also remove it)
#   - does NOT remove the 'opennofrp' system user by default (pass
#     --remove-user if you're sure nothing else depends on it)
#   - never touches iptables/nftables/routing (the Server never created any)

set -euo pipefail

PURGE_CONFIG=0
REMOVE_USER=0
for arg in "$@"; do
  case "$arg" in
    --purge-config) PURGE_CONFIG=1 ;;
    --remove-user) REMOVE_USER=1 ;;
    *) ;;
  esac
done

INSTALL_DIR="/opt/opennofrp"
CONFIG_DIR="/etc/opennofrp"
SYSTEMD_UNIT="/etc/systemd/system/opennofrp-server.service"
SERVICE_USER="opennofrp"

log() { echo "[opennofrp-uninstall] $*"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "[opennofrp-uninstall] ERROR: must be run as root" >&2
  exit 1
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^opennofrp-server\.service'; then
  log "stopping and disabling opennofrp-server.service"
  systemctl stop opennofrp-server.service 2>/dev/null || true
  systemctl disable opennofrp-server.service 2>/dev/null || true
fi

if [ -f "$SYSTEMD_UNIT" ]; then
  log "removing $SYSTEMD_UNIT"
  rm -f "$SYSTEMD_UNIT"
  systemctl daemon-reload
fi

if [ -d "$INSTALL_DIR" ]; then
  log "removing $INSTALL_DIR"
  rm -rf "$INSTALL_DIR"
fi

if [ "$PURGE_CONFIG" -eq 1 ]; then
  if [ -d "$CONFIG_DIR" ]; then
    log "--purge-config given: removing $CONFIG_DIR"
    rm -rf "$CONFIG_DIR"
  fi
else
  log "keeping $CONFIG_DIR (pass --purge-config to also remove it)"
fi

if [ "$REMOVE_USER" -eq 1 ]; then
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    log "--remove-user given: removing system user '$SERVICE_USER'"
    userdel "$SERVICE_USER" 2>/dev/null || log "userdel failed (user may still own files elsewhere); leaving it"
  fi
else
  log "keeping system user '$SERVICE_USER' (pass --remove-user to also remove it)"
fi

log "uninstall complete."
