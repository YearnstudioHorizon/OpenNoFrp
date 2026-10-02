#!/bin/bash
# OpenNoFrp Server installer (Linux, cloud machine).
#
# The Server is a pure userspace TCP forwarder -- this installer never
# touches iptables/nftables/routing/sysctls (see docs/01-architecture.md
# "Security boundary"). It only copies a binary, writes a config, and
# registers a systemd unit that runs as an unprivileged user.

set -euo pipefail

BINARY_SRC="${1:-./opennofrp-server}"
INSTALL_DIR="/opt/opennofrp"
CONFIG_DIR="/etc/opennofrp"
CONFIG_FILE="$CONFIG_DIR/server.toml"
SYSTEMD_UNIT="/etc/systemd/system/opennofrp-server.service"
BINARY_DEST="$INSTALL_DIR/opennofrp-server"
SERVICE_USER="opennofrp"

log() { echo "[opennofrp-install] $*"; }
err() { echo "[opennofrp-install] ERROR: $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
  err "this installer must be run as root (to install the systemd unit and create a dedicated service user); the Server process itself will drop to an unprivileged user"
  exit 1
fi

if [ ! -f "$BINARY_SRC" ]; then
  err "binary not found at $BINARY_SRC"
  err "usage: $0 /path/to/opennofrp-server"
  exit 1
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  log "creating unprivileged service user '$SERVICE_USER' (no login shell, no home directory needed)"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
  log "service user '$SERVICE_USER' already exists, reusing it"
fi

log "installing binary to $BINARY_DEST"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$BINARY_SRC" "$BINARY_DEST"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" "$BINARY_DEST"

log "ensuring config directory $CONFIG_DIR exists"
mkdir -p "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"

if [ -f "$CONFIG_FILE" ]; then
  log "config already exists at $CONFIG_FILE, leaving it untouched"
else
  log "writing starter config to $CONFIG_FILE"
  "$BINARY_DEST" init-config -path "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
  log "*** IMPORTANT: edit $CONFIG_FILE if you want a different bind address / db path / panel port ***"
fi
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE"
# Data + binary directories the service user needs to write to:
mkdir -p /var/lib/opennofrp /opt/opennofrp/client-bins
chown "$SERVICE_USER:$SERVICE_USER" /var/lib/opennofrp /opt/opennofrp/client-bins

log "installing systemd unit to $SYSTEMD_UNIT"
cat > "$SYSTEMD_UNIT" <<UNIT
[Unit]
Description=OpenNoFrp Server (pure userspace forwarder, no kernel network changes)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$BINARY_DEST -c $CONFIG_FILE
# Only needed if allowed_port_range_min is below 1024. If every port you
# plan to forward is >= 1024 (the default example config uses 17000/18000+),
# you can remove this line entirely for maximum least-privilege.
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload

echo ""
log "install complete. Next steps:"
log "  1. (optional) edit $CONFIG_FILE for panel port / db path / client binary dir"
log "  2. drop prebuilt client binaries into /opt/opennofrp/client-bins/ (opennofrp-client-linux-amd64, opennofrp-client-linux-arm64)"
log "  3. make sure your cloud firewall/security group allows inbound on the control port and panel port"
log "  4. systemctl enable --now opennofrp-server"
log "  5. check the journal for the initial admin password: journalctl -u opennofrp-server | grep password"
log "     (also saved to /var/lib/opennofrp/opennofrp-initial-password.txt)"
log "  6. log into the panel, register your internal machine(s), create rules"
