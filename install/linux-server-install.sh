#!/bin/bash
# OpenNoFrp Server 一键安装/重装脚本 (Linux)
# 支持从 GitHub Releases 自动检测系统架构并下载最新服务端程序，
# 支持在直连超时时自动使用国内镜像加速 (https://mirror.yearnstudio.cn/)。
# 若存在旧版本，会自动平滑卸载旧程序并重新安装，且【严格保留所有配置与数据库文件】。
#
# 使用方式:
#   curl -fsSL https://raw.githubusercontent.com/YearnstudioHorizon/OpenNoFrp/main/install/linux-server-install.sh | sudo bash
# 加速方式:
#   curl -fsSL https://mirror.yearnstudio.cn/https://raw.githubusercontent.com/YearnstudioHorizon/OpenNoFrp/main/install/linux-server-install.sh | sudo bash

set -euo pipefail

REPO="YearnstudioHorizon/OpenNoFrp"
MIRROR_PREFIX="https://mirror.yearnstudio.cn/"
INSTALL_DIR="/opt/opennofrp"
CONFIG_DIR="/etc/opennofrp"
CONFIG_FILE="$CONFIG_DIR/server.toml"
DATA_DIR="/var/lib/opennofrp"
CLIENT_BINS_DIR="$INSTALL_DIR/client-bins"
SYSTEMD_UNIT="/etc/systemd/system/opennofrp-server.service"
BINARY_DEST="$INSTALL_DIR/opennofrp-server"
SERVICE_USER="opennofrp"

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

# ----------------------------------------------------------------------
# 1. 检查是否存在旧版本，并执行平滑卸载 (保留所有配置与数据)
# ----------------------------------------------------------------------
IS_UPGRADE=0
if [ -f "$BINARY_DEST" ] || [ -f "$SYSTEMD_UNIT" ]; then
  IS_UPGRADE=1
  log "================================================================="
  log "⚡ 检测到本机已存在 OpenNoFrp 服务端旧版本"
  log "正在执行平滑卸载与重新安装流程 (将严格保留您的原有配置与数据库)..."
  log "================================================================="

  # 停止正在运行的服务
  if systemctl is-active --quiet opennofrp-server 2>/dev/null; then
    log "正在停止旧版本服务进程..."
    systemctl stop opennofrp-server || true
  fi

  # 卸载旧的可执行程序文件
  if [ -f "$BINARY_DEST" ]; then
    log "卸载旧版本二进制文件: $BINARY_DEST"
    rm -f "$BINARY_DEST"
  fi
  log "旧程序已卸载，现有配置、证书和数据库完好保留！"
fi

# ----------------------------------------------------------------------
# 2. 获取/下载最新版本的二进制程序
# ----------------------------------------------------------------------
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

download_from_gh() {
  local asset_name="$1"
  local dest_path="$2"
  local gh_url="https://github.com/$REPO/releases/latest/download/$asset_name"
  local mirror_url="${MIRROR_PREFIX}${gh_url}"

  log "正在获取 $asset_name ..."
  # 优先尝试 GitHub 直连 (超时限制 8 秒)
  if curl -fsSL --connect-timeout 8 -m 120 "$gh_url" -o "$dest_path" 2>/dev/null; then
    log "已从 GitHub Releases 官方源下载成功"
    return 0
  fi

  # 直连超时，切换至国内镜像加速
  log "GitHub 直连超时，正在自动切换至国内加速镜像 ($MIRROR_PREFIX) ..."
  if curl -fsSL --connect-timeout 10 -m 180 "$mirror_url" -o "$dest_path"; then
    log "已通过 YearnStudio 加速镜像下载成功"
    return 0
  fi

  err "从官方源和加速镜像下载 $asset_name 均失败，请检查网络连接！"
  return 1
}

if [ -n "$LOCAL_SRC" ] && [ -f "$LOCAL_SRC" ]; then
  log "使用本地指定的服务端文件: $LOCAL_SRC"
  cp "$LOCAL_SRC" "$TMP_DIR/opennofrp-server"
else
  log "未指定本地文件，正在联网自动匹配 linux/$ARCH 对应最新版本..."
  download_from_gh "opennofrp-server-linux-$ARCH" "$TMP_DIR/opennofrp-server"
fi

# ----------------------------------------------------------------------
# 3. 创建专用低权限服务账户
# ----------------------------------------------------------------------
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  log "创建无特权专用运行账户: '$SERVICE_USER'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
  log "专用账户 '$SERVICE_USER' 已存在，直接复用"
fi

# ----------------------------------------------------------------------
# 4. 安装全新二进制并分发客户端包
# ----------------------------------------------------------------------
mkdir -p "$INSTALL_DIR" "$CLIENT_BINS_DIR"
install -m 0755 "$TMP_DIR/opennofrp-server" "$BINARY_DEST"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# 预拉取客户端二进制文件到托管目录，加速内网客户端一键安装
log "正在预拉取客户端二进制文件到服务器托管目录 ($CLIENT_BINS_DIR)..."
download_from_gh "opennofrp-client-linux-$ARCH" "$CLIENT_BINS_DIR/opennofrp-client-linux-$ARCH" || true
if [ "$ARCH" = "amd64" ]; then
  download_from_gh "opennofrp-client-linux-arm64" "$CLIENT_BINS_DIR/opennofrp-client-linux-arm64" 2>/dev/null || true
else
  download_from_gh "opennofrp-client-linux-amd64" "$CLIENT_BINS_DIR/opennofrp-client-linux-amd64" 2>/dev/null || true
fi
chmod 0755 "$CLIENT_BINS_DIR"/* 2>/dev/null || true
chown -R "$SERVICE_USER:$SERVICE_USER" "$CLIENT_BINS_DIR"

# ----------------------------------------------------------------------
# 5. 配置与数据持久化目录管理 (严格保护已有数据)
# ----------------------------------------------------------------------
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chmod 0750 "$CONFIG_DIR"
chmod 0700 "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR" "$DATA_DIR"

if [ -f "$CONFIG_FILE" ]; then
  log "✓ 检查到已有配置文件 $CONFIG_FILE，已为您完整保留，绝不覆盖！"
else
  log "生成全新服务端初始配置文件 $CONFIG_FILE"
  "$BINARY_DEST" init-config -path "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
fi
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE"

# ----------------------------------------------------------------------
# 6. 配置并重新启动 systemd 守护进程
# ----------------------------------------------------------------------
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

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now opennofrp-server

sleep 1

# ----------------------------------------------------------------------
# 7. 汇总并展示结果
# ----------------------------------------------------------------------
PW_FILE="$DATA_DIR/opennofrp-initial-password.txt"
PASSWORD="可在日志中查看"
if [ -f "$PW_FILE" ]; then
  PASSWORD="$(grep '^password=' "$PW_FILE" | cut -d'=' -f2)"
fi

echo ""
echo "================================================================="
if [ "$IS_UPGRADE" -eq 1 ]; then
  log "🎉 OpenNoFrp 服务端已成功平滑重装/更新！原有配置与数据库均已完好保留。"
else
  log "🎉 OpenNoFrp 服务端安装完成并已成功启动！"
fi
echo "================================================================="
echo "  Web 管理控制台:  http://$(curl -s4 ip.sb 2>/dev/null || echo "您的服务器公网IP"):8080"
if [ "$IS_UPGRADE" -eq 1 ]; then
  echo "  管理员账号密码:  已保留您之前设置的管理员密码"
else
  echo "  默认管理员账号:  admin"
  echo "  初始管理员密码:  $PASSWORD"
fi
echo "  配置文件位置:    $CONFIG_FILE (已保留现有配置)"
echo "  数据与证书目录:  $DATA_DIR (数据库与 TLS 证书指纹完好无损)"
echo "  服务状态查看:    sudo systemctl status opennofrp-server"
echo "  日志实时查看:    sudo journalctl -u opennofrp-server -f"
echo "  在线一键自更新:  sudo opennofrp-server update"
echo "================================================================="
echo ""
