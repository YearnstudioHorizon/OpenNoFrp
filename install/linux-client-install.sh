#!/bin/bash
# OpenNoFrp Client installer (Linux).
#
# What this script does (and nothing else):
#   1. Copies the opennofrp-client binary to /opt/opennofrp/opennofrp-client
#   2. Writes a starter config to /etc/opennofrp/client.toml (if not present)
#   3. Installs a systemd unit (not started automatically -- see below)
#   4. Runs "opennofrp-client envcheck" so you know BEFORE starting the
#      service whether preserve_source_ip will actually work on this host
#
# This script deliberately does NOT:
#   - touch iptables/nftables/ip route directly (the Client binary itself
#     does that, only once started, and only within its own dedicated
#     fwmark/table/chain-comment namespace -- see docs/01-architecture.md)
#   - enable or start the systemd service for you. You must edit
#     /etc/opennofrp/client.toml first (set server.addr/token and your
#     [[proxy]] rules), then run:
#       systemctl enable --now opennofrp-client
#   - overwrite an existing config file
#
# Safe to re-run: every step below checks for existing state first.

set -euo pipefail

BINARY_SRC="${1:-./opennofrp-client}"
INSTALL_DIR="/opt/opennofrp"
CONFIG_DIR="/etc/opennofrp"
CONFIG_FILE="$CONFIG_DIR/client.toml"
STATE_DIR="/var/lib/opennofrp"
SYSTEMD_UNIT="/etc/systemd/system/opennofrp-client.service"
BINARY_DEST="$INSTALL_DIR/opennofrp-client"

log() { echo "[opennofrp-install] $*"; }
err() { echo "[opennofrp-install] ERROR: $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
  err "this installer must be run as root (TPROXY requires root/CAP_NET_ADMIN+CAP_NET_RAW)"
  exit 1
fi

if [ ! -f "$BINARY_SRC" ]; then
  err "binary not found at $BINARY_SRC"
  err "usage: $0 /path/to/opennofrp-client"
  exit 1
fi

log "installing binary to $BINARY_DEST"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$BINARY_SRC" "$BINARY_DEST"

log "ensuring config directory $CONFIG_DIR exists"
mkdir -p "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"

if [ -f "$CONFIG_FILE" ]; then
  log "config already exists at $CONFIG_FILE, leaving it untouched"
else
  log "writing starter config to $CONFIG_FILE"
  "$BINARY_DEST" init-config -path "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
  log "*** IMPORTANT: edit $CONFIG_FILE before starting the service ***"
fi

mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

log "installing systemd unit to $SYSTEMD_UNIT"
cat > "$SYSTEMD_UNIT" <<UNIT
[Unit]
Description=OpenNoFrp Client (local TPROXY-based source-IP-preserving forwarder)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BINARY_DEST -c $CONFIG_FILE -state-dir $STATE_DIR
# TPROXY and IP_TRANSPARENT require these capabilities. We intentionally do
# NOT run this as a non-root user with just these caps by default, because
# setting file capabilities on the binary is a separate opt-in hardening
# step left to the operator (see docs/02-risk-assessment.md); running as
# root is the documented default so "it just works" out of the box.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
Restart=on-failure
RestartSec=2
# ExecStopPost runs the exact same teardown path the uninstaller uses, so
# that "systemctl stop" alone already leaves no dangling TPROXY rules,
# routes, or modified sysctls behind -- not just full uninstallation.
ExecStopPost=$BINARY_DEST tproxy-teardown -state-dir $STATE_DIR

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload

log "running environment check (read-only, does not modify anything)"
set +e
"$BINARY_DEST" envcheck
ENVCHECK_RC=$?
set -e

echo ""
log "install complete. Next steps:"
log "  1. edit $CONFIG_FILE (set server.addr, server.port, server.token from the panel's install command)"
log "  2. systemctl enable --now opennofrp-client"
log "  3. journalctl -u opennofrp-client -f   # to watch logs"
log "  (note: no [[proxy]] rules live here anymore -- create rules in the panel; they are pushed over the control connection)"
if [ "$ENVCHECK_RC" -ne 0 ]; then
  err "envcheck reported FATAL issues above -- preserve_source_ip will not work until those are fixed"
fi
