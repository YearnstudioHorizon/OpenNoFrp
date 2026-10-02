#!/bin/bash
# OpenNoFrp Client uninstaller (Linux).
#
# Whitelist-only removal, per docs/02-risk-assessment.md section 5:
#   - stops + disables the opennofrp-client systemd unit (which itself runs
#     "opennofrp-client tproxy-teardown" via ExecStopPost, removing every
#     TPROXY iptables rule / ip rule / ip route / sysctl change this Client
#     instance ever made -- based on its own persisted state file, not
#     guesswork)
#   - as a defense-in-depth belt-and-suspenders step, explicitly runs
#     tproxy-teardown again directly in case the service was already dead
#     and ExecStopPost never fired
#   - removes exactly: /etc/systemd/system/opennofrp-client.service,
#     /opt/opennofrp/, /var/lib/opennofrp/
#   - does NOT remove /etc/opennofrp/client.toml by default (your config,
#     and any secrets in it, are left alone unless you pass --purge-config)
#   - never runs a blanket "iptables -F" / "nft flush ruleset" / "ip route
#     flush" -- only ever the exact rules opennofrp itself tracks

set -euo pipefail

PURGE_CONFIG=0
for arg in "$@"; do
  case "$arg" in
    --purge-config) PURGE_CONFIG=1 ;;
    *) ;;
  esac
done

INSTALL_DIR="/opt/opennofrp"
CONFIG_DIR="/etc/opennofrp"
STATE_DIR="/var/lib/opennofrp"
SYSTEMD_UNIT="/etc/systemd/system/opennofrp-client.service"
BINARY_DEST="$INSTALL_DIR/opennofrp-client"

log() { echo "[opennofrp-uninstall] $*"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "[opennofrp-uninstall] ERROR: must be run as root" >&2
  exit 1
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^opennofrp-client\.service'; then
  log "stopping and disabling opennofrp-client.service"
  systemctl stop opennofrp-client.service 2>/dev/null || true
  systemctl disable opennofrp-client.service 2>/dev/null || true
else
  log "opennofrp-client.service not registered, skipping"
fi

if [ -x "$BINARY_DEST" ]; then
  log "running tproxy-teardown directly (belt-and-suspenders, in case the service's ExecStopPost didn't run)"
  "$BINARY_DEST" tproxy-teardown -state-dir "$STATE_DIR" || log "teardown reported an error (see above); continuing with file removal"
else
  log "binary not found at $BINARY_DEST, cannot run tproxy-teardown -- if TPROXY rules are still active, remove them manually (see docs/01-architecture.md section 6.1 for what to look for: iptables-legacy mangle rules commented 'opennofrp-port-*', ip rule for fwmark 0x1, ip route table 100)"
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

if [ -d "$STATE_DIR" ]; then
  log "removing $STATE_DIR"
  rm -rf "$STATE_DIR"
fi

if [ "$PURGE_CONFIG" -eq 1 ]; then
  if [ -d "$CONFIG_DIR" ]; then
    log "--purge-config given: removing $CONFIG_DIR"
    rm -rf "$CONFIG_DIR"
  fi
else
  log "keeping $CONFIG_DIR (pass --purge-config to also remove it)"
fi

log "uninstall complete. Verifying no leftover TPROXY rules:"
if command -v iptables-legacy >/dev/null 2>&1; then
  LEFTOVER=$(iptables-legacy -t mangle -L -n -v 2>/dev/null | grep -c 'opennofrp-' || true)
  if [ "${LEFTOVER:-0}" -gt 0 ]; then
    echo "[opennofrp-uninstall] WARNING: $LEFTOVER opennofrp-tagged mangle rule(s) still present:" >&2
    iptables-legacy -t mangle -L -n -v | grep 'opennofrp-' >&2
    echo "[opennofrp-uninstall] remove manually with: iptables-legacy -t mangle -D <CHAIN> <matching rule spec>" >&2
  else
    log "clean: no opennofrp-tagged mangle rules remain"
  fi
fi
