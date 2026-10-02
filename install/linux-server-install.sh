#!/bin/bash
# OpenNoFrp Server 一键安装脚本 (Linux)
# 支持从 GitHub Releases 自动检测系统架构并下载最新服务端程序，
# 同时支持在直连超时时自动使用国内镜像加速 (https://mirror.yearnstudio.cn/)。
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
err() { echo "[opennofrp-server-install] 错误: $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
  err "本安装脚本必须以 root 权限运行 (以创建专用服务用户并注册 systemd 服务)"
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

# 1. 获取/下载二进制文件
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
  log "未指定本地文件，正在联网自动匹配 linux/$ARCH 对应版本..."
  download_from_gh "opennofrp-server-linux-$ARCH" "$TMP_DIR/opennofrp-server"
fi

# 2. 创建专用低权限服务用户
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  log "创建无特权专用运行账户: '$SERVICE_USER'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
  log "专用账户 '$SERVICE_USER' 已存在，直接复用"
fi

# 3. 安装二进制文件
mkdir -p "$INSTALL_DIR" "$CLIENT_BINS_DIR"
install -m 0755 "$TMP_DIR/opennofrp-server" "$BINARY_DEST"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# 顺便预下载对应架构的客户端二进制并放置到 client-bins 目录，方便内网机器接入
log "正在预拉取客户端二进制文件到服务器托管目录 ($CLIENT_BINS_DIR)..."
download_from_gh "opennofrp-client-linux-$ARCH" "$CLIENT_BINS_DIR/opennofrp-client-linux-$ARCH" || true
if [ "$ARCH" = "amd64" ]; then
  download_from_gh "opennofrp-client-linux-arm64" "$CLIENT_BINS_DIR/opennofrp-client-linux-arm64" 2>/dev/null || true
else
  download_from_gh "opennofrp-client-linux-amd64" "$CLIENT_BINS_DIR/opennofrp-client-linux-amd64" 2>/dev/null || true
fi
chmod 0755 "$CLIENT_BINS_DIR"/* 2>/dev/null || true
chown -R "$SERVICE_USER:$SERVICE_USER" "$CLIENT_BINS_DIR"

# 4. 配置与数据持久化目录
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chmod 0750 "$CONFIG_DIR"
chmod 0700 "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR" "$DATA_DIR"

if [ -f "$CONFIG_FILE" ]; then
  log "配置文件 $CONFIG_FILE 已存在，保留现有配置"
else
  log "生成初始服务端配置文件 $CONFIG_FILE"
  "$BINARY_DEST" init-config -path "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
fi
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE"

# 5. 安装 systemd 服务
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

# 6. 获取初始管理员账密与 TLS 证书指纹
PW_FILE="$DATA_DIR/opennofrp-initial-password.txt"
PASSWORD="可在日志中查看"
if [ -f "$PW_FILE" ]; then
  PASSWORD="$(grep '^password=' "$PW_FILE" | cut -d'=' -f2)"
fi

echo ""
echo "================================================================="
log "🎉 OpenNoFrp 服务端安装完成并已成功启动！"
echo "================================================================="
echo "  Web 管理控制台:  http://$(curl -s4 ip.sb 2>/dev/null || echo "您的服务器公网IP"):8080"
echo "  默认管理员账号:  admin"
echo "  初始管理员密码:  $PASSWORD"
echo "  配置文件位置:    $CONFIG_FILE"
echo "  服务管理命令:    sudo systemctl status opennofrp-server"
echo "  日志实时查看:    sudo journalctl -u opennofrp-server -f"
echo "  在线一键自更新:  sudo opennofrp-server update"
echo "================================================================="
echo ""
