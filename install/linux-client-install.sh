#!/bin/bash
# OpenNoFrp 客户端安装脚本 (Linux)。
#
# 本脚本只做以下几件事（除此之外不做任何事）：
#   1. 将 opennofrp-client 二进制文件复制到 /opt/opennofrp/opennofrp-client
#   2. 将初始配置写入 /etc/opennofrp/client.toml（若尚不存在）
#   3. 安装 systemd 单元（不会自动启动 -- 见下文）
#   4. 运行 "opennofrp-client envcheck"，让你在启动服务之前就知道
#      preserve_source_ip 在本机上能否真正生效
#
# 本脚本刻意不会：
#   - 直接修改 iptables/nftables/ip route（这些由 Client 二进制自身负责，
#     且仅在启动后进行，并只在其专属的
#     fwmark/table/chain-comment 命名空间内操作 -- 见 docs/01-architecture.md）
#   - 替你启用或启动 systemd 服务。你必须先编辑
#     /etc/opennofrp/client.toml（设置 server.addr/token 以及你的
#     [[proxy]] 规则），然后运行：
#       systemctl enable --now opennofrp-client
#   - 覆盖已存在的配置文件
#
# 可安全重复运行：下面的每一步都会先检查现有状态。

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
if systemctl is-active --quiet opennofrp-client 2>/dev/null; then
  log "检测到客户端服务正在运行，正在停止旧服务进行平滑升级..."
  systemctl stop opennofrp-client || true
fi
install -m 0755 "$BINARY_SRC" "$BINARY_DEST"

log "ensuring config directory $CONFIG_DIR exists"
mkdir -p "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"

if [ -f "$CONFIG_FILE" ]; then
  log "配置文件 $CONFIG_FILE 已存在，严格保留现有配置 (不覆盖)"
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
