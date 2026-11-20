#!/bin/bash
# OpenNoFrp Server 一键安装/重装脚本 (Linux)
# 支持从 GitHub Releases 自动检测系统架构并下载最新服务端程序，
# 支持在直连超时时自动使用国内镜像加速 (https://mirror.yearnstudio.cn/)。
#
# 升级流程 (严格保留所有配置与数据库文件)：
#   1. 先下载新版本服务端与客户端二进制到临时目录 (此阶段不影响正在运行的服务)
#   2. 下载全部成功后，备份旧二进制与 systemd 单元，再停止旧服务
#   3. 替换二进制与单元文件并重新拉起服务
#   4. 健康检查：若新版本拉起失败，自动回退到旧版本并恢复其运行状态
#
# 使用方式:
#   curl -fsSL https://raw.githubusercontent.com/YearnstudioHorizon/OpenNoFrp/main/install/linux-server-install.sh | sudo bash
# 加速方式:
#   curl -fsSL https://mirror.yearnstudio.cn/https://raw.githubusercontent.com/YearnstudioHorizon/OpenNoFrp/main/install/linux-server-install.sh | sudo bash

set -euo pipefail

INSTALL_DIR="/opt/opennofrp-server"
CONFIG_DIR="/etc/opennofrp-server"
CONFIG_FILE="$CONFIG_DIR/server.toml"
DATA_DIR="/var/lib/opennofrp-server"
CLIENT_BINS_DIR="$INSTALL_DIR/client-bins"
SERVICE_NAME="opennofrp-server"
SYSTEMD_UNIT="/etc/systemd/system/$SERVICE_NAME.service"
BINARY_DEST="$INSTALL_DIR/opennofrp-server"
BINARY_BAK="$BINARY_DEST.bak"
UNIT_BAK="$INSTALL_DIR/$SERVICE_NAME.service.bak"
SERVICE_USER="opennofrp"
# 新版本拉起后持续观察的秒数，期间服务必须保持 active 且未发生自动重启
HEALTH_CHECK_SECONDS="${HEALTH_CHECK_SECONDS:-8}"

log() { echo "[opennofrp-server-install] $*"; }
warn() { echo "[opennofrp-server-install] 警告: $*" >&2; }
err() { echo "[opennofrp-server-install] 错误: $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
  err "本安装脚本必须以 root 权限运行 (以管理专用服务用户和注册 systemd 服务)"
  exit 1
fi

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac
}

ARCH="$(detect_arch)"
LOCAL_SRC="${1:-}"

# Keep legacy server data in place. The low-privilege process may read its old
# configuration, but root never rewrites paths inside its previous shared tree.
LEGACY_CONFIG=0
if [ ! -f "$CONFIG_FILE" ] && [ -f /etc/opennofrp/server.toml ]; then
  CONFIG_FILE=/etc/opennofrp/server.toml
  LEGACY_CONFIG=1
fi

IS_UPGRADE=0
if [ -f "$BINARY_DEST" ] || [ -f "$SYSTEMD_UNIT" ]; then
  IS_UPGRADE=1
fi

# 运行状态记录 (用于失败回退)
SWAP_STARTED=0     # 1 = 已开始停服/替换，此后任何失败都需要回退
ROLLBACK_DONE=0
WAS_ACTIVE=0
WAS_ENABLED=0

TMP_DIR="$(mktemp -d)"
STAGE_SERVER="$TMP_DIR/opennofrp-server"
STAGE_CLIENT_DIR="$TMP_DIR/client-bins"
mkdir -p "$STAGE_CLIENT_DIR"

# ----------------------------------------------------------------------
# 回退逻辑
# ----------------------------------------------------------------------
print_recent_logs() {
  err "---------------- 最近的服务日志 ----------------"
  journalctl -u "$SERVICE_NAME" -n 30 --no-pager >&2 2>/dev/null || true
  err "------------------------------------------------"
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

  if [ "$WAS_ENABLED" -eq 0 ]; then
    systemctl disable "$SERVICE_NAME" >/dev/null 2>&1
  fi

  if [ "$WAS_ACTIVE" -eq 1 ]; then
    systemctl reset-failed "$SERVICE_NAME" 2>/dev/null
    if systemctl start "$SERVICE_NAME" && verify_service; then
      log "已回退到旧版本，服务已恢复运行。"
    else
      err "回退后旧版本服务仍无法启动，请手动检查: systemctl status $SERVICE_NAME"
    fi
  else
    log "已回退到旧版本 (升级前服务未在运行，保持停止状态)。"
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

# 健康检查：服务需在观察期内持续处于 active 且未被 systemd 自动重启
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

# ----------------------------------------------------------------------
# 网络下载工具函数
# ----------------------------------------------------------------------
# 缓存获取到的最新发布标签
if ! declare -F release_metadata >/dev/null; then
  # Source checkout mode. The published installer embeds this helper.
  source "$(dirname -- "${BASH_SOURCE[0]}")/../pkg/updater/release.sh"
fi

# ----------------------------------------------------------------------
# 1. 先下载全部新版本文件到临时目录 (此阶段不触碰正在运行的服务)
# ----------------------------------------------------------------------
if [ "$IS_UPGRADE" -eq 1 ]; then
  log "================================================================="
  log "⚡ 检测到本机已存在 OpenNoFrp 服务端旧版本"
  log "将先下载新版本，下载成功后再停止旧服务并替换 (失败自动回退，配置与数据库严格保留)"
  log "================================================================="
fi

if [ -n "$LOCAL_SRC" ] && [ -f "$LOCAL_SRC" ]; then
  log "使用本地指定的服务端文件: $LOCAL_SRC"
  cp "$LOCAL_SRC" "$STAGE_SERVER"
else
  log "未指定本地文件，正在联网自动匹配 linux/$ARCH 对应最新版本..."
  release_metadata "$TMP_DIR"
  if ! download_release_asset "opennofrp-server-linux-$ARCH" "$STAGE_SERVER"; then
    err "新版本下载失败，未对现有服务做任何改动。"
    exit 1
  fi
fi

if [ ! -s "$STAGE_SERVER" ]; then
  err "新版本服务端文件为空或不存在，未对现有服务做任何改动。"
  exit 1
fi
chmod 0755 "$STAGE_SERVER"

# Cache only client binaries that match the same signed release manifest.
if [ -n "${RELEASE_TAG:-}" ]; then
  for platform in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
    asset="opennofrp-client-$platform"
    download_release_asset "$asset" "$STAGE_CLIENT_DIR/$asset" || warn "无法缓存 $asset"
  done
fi

# ----------------------------------------------------------------------
# 2. 创建专用低权限服务账户与持久化目录 (不影响运行中的服务)
# ----------------------------------------------------------------------
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  log "创建无特权专用运行账户: '$SERVICE_USER'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
  log "专用账户 '$SERVICE_USER' 已存在，直接复用"
fi

for dir in "$INSTALL_DIR" "$CLIENT_BINS_DIR" "$CONFIG_DIR" "$DATA_DIR"; do
  if [ -L "$dir" ]; then err "Refusing symlink: $dir"; exit 1; fi
done
install -d -m 0755 -o root -g root "$INSTALL_DIR" "$CLIENT_BINS_DIR"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"

if [ -f "$CONFIG_FILE" ]; then
  log "✓ 检查到已有配置文件 $CONFIG_FILE，已为您完整保留，绝不覆盖！"
else
  log "生成全新服务端初始配置文件 $CONFIG_FILE"
  "$STAGE_SERVER" init-config -path "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
fi
if [ "$LEGACY_CONFIG" -eq 0 ]; then
  chown "root:$SERVICE_USER" "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
fi

# ----------------------------------------------------------------------
# 3. 备份旧版本并停止旧服务
# ----------------------------------------------------------------------
if [ "$IS_UPGRADE" -eq 1 ]; then
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    WAS_ACTIVE=1
  fi
  if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    WAS_ENABLED=1
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

  # 从此刻起，任何失败都会触发自动回退
  SWAP_STARTED=1

  if [ "$WAS_ACTIVE" -eq 1 ]; then
    log "正在停止旧版本服务进程..."
    systemctl stop "$SERVICE_NAME"
  fi
fi

# ----------------------------------------------------------------------
# 4. 替换二进制与 systemd 单元
# ----------------------------------------------------------------------
install -m 0755 "$STAGE_SERVER" "$BINARY_DEST.new"
mv -f "$BINARY_DEST.new" "$BINARY_DEST"
chown root:root "$BINARY_DEST"

log "配置系统守护进程单元: $SYSTEMD_UNIT"
cat > "$SYSTEMD_UNIT" <<UNIT
[Unit]
Description=OpenNoFrp Server (Pure userspace forwarder with TLS & Fingerprint verification)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$BINARY_DEST -c $CONFIG_FILE
# 允许非 root 服务绑定 1024 以下端口 (若有需要)
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure
RestartSec=2
# Keep tunnel resource exhaustion inside this service, preserving host access.
MemoryHigh=40%
MemoryMax=50%

[Install]
WantedBy=multi-user.target
UNIT

# ----------------------------------------------------------------------
# 5. 拉起新版本并进行健康检查，失败则自动回退
# ----------------------------------------------------------------------
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

log "正在拉起新版本服务并进行健康检查 (约 ${HEALTH_CHECK_SECONDS} 秒)..."
START_OK=1
systemctl restart "$SERVICE_NAME" || START_OK=0
if [ "$START_OK" -eq 1 ] && ! verify_service; then
  START_OK=0
fi

if [ "$START_OK" -ne 1 ]; then
  if [ "$IS_UPGRADE" -eq 1 ] && [ "$SWAP_STARTED" -eq 1 ]; then
    rollback
    err "本次升级失败，已回退到旧版本。"
  else
    print_recent_logs
    err "OpenNoFrp 服务端启动失败，请检查: systemctl status $SERVICE_NAME"
  fi
  exit 1
fi

# 新版本已稳定运行，此后不再需要回退
SWAP_STARTED=0
log "✓ 新版本服务运行正常"

# 落盘预拉取的客户端二进制文件
for f in "$STAGE_CLIENT_DIR"/*; do
  [ -s "$f" ] || continue
  install -m 0755 "$f" "$CLIENT_BINS_DIR/$(basename "$f")"
done

# ----------------------------------------------------------------------
# 6. 汇总并展示结果
# ----------------------------------------------------------------------
PW_FILE="$DATA_DIR/opennofrp-initial-password.txt"
PASSWORD="可在日志中查看"
if [ -f "$PW_FILE" ]; then
  PASSWORD="$(runuser -u "$SERVICE_USER" -- grep '^password=' "$PW_FILE" | cut -d'=' -f2 || true)"
fi

echo ""
echo "================================================================="
if [ "$IS_UPGRADE" -eq 1 ]; then
  log "🎉 OpenNoFrp 服务端已成功平滑重装/更新！原有配置与数据库均已完好保留。"
  if [ -f "$BINARY_BAK" ]; then
    log "旧版本二进制已备份于 $BINARY_BAK (如需手动回退可使用)"
  fi
else
  log "🎉 OpenNoFrp 服务端安装完成并已成功启动！"
fi
echo "================================================================="
echo "  Web 管理控制台:  http://127.0.0.1:8080（远程使用 SSH 转发或配置 HTTPS 反向代理）"
if [ "$IS_UPGRADE" -eq 1 ]; then
  echo "  管理员账号密码:  已保留您之前设置的管理员密码"
else
  echo "  默认管理员账号:  admin"
  echo "  初始管理员密码:  $PASSWORD"
fi
echo "  配置文件位置:    $CONFIG_FILE (已保留现有配置)"
echo "  数据与证书目录:  $DATA_DIR (数据库与 TLS 证书指纹完好无损)"
echo "  服务状态查看:    sudo systemctl status $SERVICE_NAME"
echo "  日志实时查看:    sudo journalctl -u $SERVICE_NAME -f"
echo "  在线一键自更新:  sudo opennofrp-server update"
echo "================================================================="
echo ""
