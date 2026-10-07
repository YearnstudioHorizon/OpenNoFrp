#!/bin/bash
# OpenNoFrp 客户端安装脚本 (Linux)。
#
# 本脚本只做以下几件事（除此之外不做任何事）：
#   1. 将 opennofrp-client 二进制文件复制到 /opt/opennofrp/opennofrp-client
#   2. 将初始配置写入 /etc/opennofrp/client.toml（若尚不存在）
#   3. 安装 systemd 单元（全新安装时不会自动启动 -- 见下文）
#   4. 运行 "opennofrp-client envcheck"，让你在启动服务之前就知道
#      preserve_source_ip 在本机上能否真正生效
#
# 升级流程（服务正在运行时）：
#   1. 先将新二进制暂存到临时目录并校验（此阶段不影响正在运行的服务）
#   2. 备份旧二进制与 systemd 单元，再停止旧服务
#   3. 替换二进制与单元文件并重新拉起服务
#   4. 健康检查：若新版本拉起失败，自动回退到旧版本并恢复运行
#
# 本脚本刻意不会：
#   - 直接修改 iptables/nftables/ip route（这些由 Client 二进制自身负责，
#     且仅在启动后进行，并只在其专属的
#     fwmark/table/chain-comment 命名空间内操作 -- 见 docs/01-architecture.md）
#   - 替你启用或启动 systemd 服务（全新安装时）。你必须先编辑
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
SERVICE_NAME="opennofrp-client"
SYSTEMD_UNIT="/etc/systemd/system/$SERVICE_NAME.service"
BINARY_DEST="$INSTALL_DIR/opennofrp-client"
BINARY_BAK="$BINARY_DEST.bak"
UNIT_BAK="$INSTALL_DIR/$SERVICE_NAME.service.bak"
HEALTH_CHECK_SECONDS="${HEALTH_CHECK_SECONDS:-8}"

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

SWAP_STARTED=0
ROLLBACK_DONE=0
WAS_ACTIVE=0

TMP_DIR="$(mktemp -d)"
STAGE_BIN="$TMP_DIR/opennofrp-client"

print_recent_logs() {
  err "---------------- 最近的服务日志 ----------------"
  journalctl -u "$SERVICE_NAME" -n 30 --no-pager >&2 2>/dev/null || true
  err "------------------------------------------------"
}

verify_service() {
  local i restarts
  sleep 1
  for i in $(seq 1 "$HEALTH_CHECK_SECONDS"); do
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
      return 1
    fi
    restarts="$(systemctl show -p NRestarts "$SERVICE_NAME" 2>/dev/null | cut -d'=' -f2 || true)"
    case "$restarts" in
      ''|*[!0-9]*) restarts=0 ;;
    esac
    if [ "$restarts" -gt 0 ]; then
      return 1
    fi
    sleep 1
  done
  return 0
}

rollback() {
  set +e
  ROLLBACK_DONE=1
  err "新版本替换/拉起失败，正在自动回退到旧版本..."
  print_recent_logs

  systemctl stop "$SERVICE_NAME" 2>/dev/null

  if [ -f "$BINARY_BAK" ]; then
    mv -f "$BINARY_BAK" "$BINARY_DEST"
    log "已恢复旧版本二进制: $BINARY_DEST"
  fi
  if [ -f "$UNIT_BAK" ]; then
    mv -f "$UNIT_BAK" "$SYSTEMD_UNIT"
    log "已恢复旧版本 systemd 单元: $SYSTEMD_UNIT"
  fi
  systemctl daemon-reload

  if [ "$WAS_ACTIVE" -eq 1 ]; then
    systemctl reset-failed "$SERVICE_NAME" 2>/dev/null
    if systemctl start "$SERVICE_NAME" && verify_service; then
      log "已回退到旧版本，服务已恢复运行。"
    else
      err "回退后旧版本服务仍无法启动，请手动检查: systemctl status $SERVICE_NAME"
    fi
  fi
  set -e
}

on_exit() {
  local rc=$?
  set +e
  if [ "$rc" -ne 0 ] && [ "$SWAP_STARTED" -eq 1 ] && [ "$ROLLBACK_DONE" -eq 0 ]; then
    rollback
  fi
  rm -rf "$TMP_DIR"
  exit "$rc"
}
trap on_exit EXIT

# ----------------------------------------------------------------------
# 1. 暂存新二进制 (不触碰正在运行的服务)
# ----------------------------------------------------------------------
cp "$BINARY_SRC" "$STAGE_BIN"
if [ ! -s "$STAGE_BIN" ]; then
  err "binary at $BINARY_SRC is empty; nothing was changed"
  exit 1
fi
chmod 0755 "$STAGE_BIN"

mkdir -p "$INSTALL_DIR"

log "ensuring config directory $CONFIG_DIR exists"
mkdir -p "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"

if [ -f "$CONFIG_FILE" ]; then
  log "配置文件 $CONFIG_FILE 已存在，严格保留现有配置 (不覆盖)"
else
  log "writing starter config to $CONFIG_FILE"
  "$STAGE_BIN" init-config -path "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
  log "*** IMPORTANT: edit $CONFIG_FILE before starting the service ***"
fi

mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# ----------------------------------------------------------------------
# 2. 备份旧版本并停止旧服务
# ----------------------------------------------------------------------
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  WAS_ACTIVE=1
fi

rm -f "$BINARY_BAK" "$UNIT_BAK"
if [ -f "$BINARY_DEST" ]; then
  cp -a "$BINARY_DEST" "$BINARY_BAK"
  log "已备份旧版本二进制: $BINARY_BAK"
fi
if [ -f "$SYSTEMD_UNIT" ]; then
  cp -a "$SYSTEMD_UNIT" "$UNIT_BAK"
  log "已备份旧版本 systemd 单元: $UNIT_BAK"
fi

if [ -f "$BINARY_BAK" ] || [ -f "$UNIT_BAK" ]; then
  SWAP_STARTED=1
fi

if [ "$WAS_ACTIVE" -eq 1 ]; then
  log "检测到客户端服务正在运行，正在停止旧服务进行平滑升级..."
  systemctl stop "$SERVICE_NAME"
fi

# ----------------------------------------------------------------------
# 3. 替换二进制与 systemd 单元
# ----------------------------------------------------------------------
log "installing binary to $BINARY_DEST"
install -m 0755 "$STAGE_BIN" "$BINARY_DEST.new"
mv -f "$BINARY_DEST.new" "$BINARY_DEST"

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

# ----------------------------------------------------------------------
# 4. 若升级前服务在运行，则拉起新版本并健康检查，失败自动回退
# ----------------------------------------------------------------------
if [ "$WAS_ACTIVE" -eq 1 ]; then
  systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
  log "正在拉起新版本客户端服务并进行健康检查 (约 ${HEALTH_CHECK_SECONDS} 秒)..."
  START_OK=1
  systemctl start "$SERVICE_NAME" || START_OK=0
  if [ "$START_OK" -eq 1 ] && ! verify_service; then
    START_OK=0
  fi
  if [ "$START_OK" -ne 1 ]; then
    rollback
    err "本次升级失败，已回退到旧版本。"
    exit 1
  fi
  log "✓ 新版本客户端服务运行正常"
fi

# 替换完成，不再需要回退
SWAP_STARTED=0

log "running environment check (read-only, does not modify anything)"
set +e
"$BINARY_DEST" envcheck
ENVCHECK_RC=$?
set -e

echo ""
if [ "$WAS_ACTIVE" -eq 1 ]; then
  log "upgrade complete. service restarted with the new binary."
  if [ -f "$BINARY_BAK" ]; then
    log "旧版本二进制已备份于 $BINARY_BAK (如需手动回退可使用)"
  fi
else
  log "install complete. Next steps:"
  log "  1. edit $CONFIG_FILE (set server.addr, server.port, server.token from the panel's install command)"
  log "  2. systemctl enable --now opennofrp-client"
  log "  3. journalctl -u opennofrp-client -f   # to watch logs"
  log "  (note: no [[proxy]] rules live here anymore -- create rules in the panel; they are pushed over the control connection)"
fi
if [ "$ENVCHECK_RC" -ne 0 ]; then
  err "envcheck reported FATAL issues above -- preserve_source_ip will not work until those are fixed"
fi
