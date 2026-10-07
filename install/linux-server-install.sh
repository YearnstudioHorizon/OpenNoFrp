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

REPO="YearnstudioHorizon/OpenNoFrp"
MIRROR_PREFIX="https://mirror.yearnstudio.cn/"
INSTALL_DIR="/opt/opennofrp"
CONFIG_DIR="/etc/opennofrp"
CONFIG_FILE="$CONFIG_DIR/server.toml"
DATA_DIR="/var/lib/opennofrp"
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
LATEST_TAG=""

# safe_curl 封装高可靠网络请求：优先使用 IPv4 (-4) 规避国内部分双栈网络下 IPv6 路由黑洞导致的 SSL 连接超时 (SSL connection timeout)
safe_curl_get() {
  local url="$1"
  local timeout="${2:-10}"
  # 优先 IPv4
  curl -4 -s --connect-timeout 6 -m "$timeout" "$url" 2>/dev/null || curl -s --connect-timeout 6 -m "$timeout" "$url" 2>/dev/null
}

safe_curl_download() {
  local url="$1"
  local dest="$2"
  local timeout="${3:-180}"
  # 优先 IPv4 规避 Cloudflare IPv6 握手超时，并附带重试机制
  if curl -4 -fsSL --connect-timeout 15 -m "$timeout" --retry 2 --retry-delay 1 "$url" -o "$dest" 2>/dev/null; then
    return 0
  fi
  # 兼容纯 IPv6 环境的回退
  if curl -fsSL --connect-timeout 15 -m "$timeout" "$url" -o "$dest" 2>/dev/null; then
    return 0
  fi
  rm -f "$dest"
  return 1
}

get_latest_tag() {
  if [ -n "$LATEST_TAG" ]; then
    echo "$LATEST_TAG"
    return 0
  fi

  local tag=""
  # 1. 优先尝试从 releases/latest 的 HTTP Location 头提取 (无 API 限额限制)
  local loc
  loc=$(curl -4 -sI --connect-timeout 6 -m 8 "https://github.com/$REPO/releases/latest" 2>/dev/null | grep -i "^location:" | tr -d "\r\n" || true)
  if [ -z "$loc" ]; then
    loc=$(curl -sI --connect-timeout 6 -m 8 "https://github.com/$REPO/releases/latest" 2>/dev/null | grep -i "^location:" | tr -d "\r\n" || true)
  fi
  if [ -n "$loc" ]; then
    tag=$(echo "$loc" | awk -F"/tag/" '{print $2}' | tr -d " \r\n")
  fi

  # 2. 次选尝试官方 API 直连
  if [ -z "$tag" ]; then
    tag=$(safe_curl_get "https://api.github.com/repos/$REPO/releases/latest" 8 | grep '"tag_name":' | head -n1 | cut -d'"' -f4 || true)
  fi

  # 3. 直连超时，通过国内镜像加速访问官方 API 提取 tag
  if [ -z "$tag" ]; then
    tag=$(safe_curl_get "${MIRROR_PREFIX}https://api.github.com/repos/$REPO/releases/latest" 10 | grep '"tag_name":' | head -n1 | cut -d'"' -f4 || true)
  fi

  LATEST_TAG="$tag"
  echo "$tag"
}

# 记录是否应优先走镜像：一旦某次下载直连失败而镜像成功，后续下载 (如客户端预拉取) 直接优先使用镜像，避免重复等待直连超时
PREFER_MIRROR=0

download_from_gh() {
  local asset_name="$1"
  local dest_path="$2"
  local tag
  # 注意：不在 $(...) 子 shell 中赋值缓存，否则 LATEST_TAG 无法跨调用保留
  if [ -z "$LATEST_TAG" ]; then
    LATEST_TAG="$(get_latest_tag)"
  fi
  tag="$LATEST_TAG"

  log "正在获取 $asset_name ..."

  # 若成功解析到 Tag，构造确切的 Release 资源路径（镜像对确切路径支持最佳，不会因 302 跨域重定向报 502）
  if [ -n "$tag" ]; then
    local gh_url="https://github.com/$REPO/releases/download/$tag/$asset_name"
    local mirror_url="${MIRROR_PREFIX}${gh_url}"

    if [ "$PREFER_MIRROR" -eq 1 ]; then
      # 之前直连已超时，本次优先走镜像，失败再回退直连
      log "此前 GitHub 直连超时，本次优先使用国内加速镜像 ($MIRROR_PREFIX) ..."
      if safe_curl_download "$mirror_url" "$dest_path" 180; then
        log "已通过 YearnStudio 加速镜像 ($tag) 下载成功"
        return 0
      fi
      log "加速镜像下载失败，尝试回退 GitHub 直连 ..."
      if safe_curl_download "$gh_url" "$dest_path" 120; then
        log "已从 GitHub Releases 官方源 ($tag) 下载成功"
        PREFER_MIRROR=0
        return 0
      fi
    else
      # 优先尝试 GitHub 直连
      if safe_curl_download "$gh_url" "$dest_path" 120; then
        log "已从 GitHub Releases 官方源 ($tag) 下载成功"
        return 0
      fi

      # 直连超时，切换至国内镜像加速 (优先走稳定的 IPv4 Anycast 节点)
      log "GitHub 直连超时，正在自动切换至国内加速镜像 ($MIRROR_PREFIX) ..."
      if safe_curl_download "$mirror_url" "$dest_path" 180; then
        log "已通过 YearnStudio 加速镜像 ($tag) 下载成功，后续下载将优先使用镜像"
        PREFER_MIRROR=1
        return 0
      fi
    fi
  else
    # 极端未解析到 tag 时的直连兜底
    local gh_latest="https://github.com/$REPO/releases/latest/download/$asset_name"
    if safe_curl_download "$gh_latest" "$dest_path" 120; then
      log "已从 GitHub Releases 官方源直接下载成功"
      return 0
    fi
  fi

  err "从官方源和加速镜像下载 $asset_name 均失败，请检查网络连接！"
  return 1
}

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
  if ! download_from_gh "opennofrp-server-linux-$ARCH" "$STAGE_SERVER"; then
    err "新版本下载失败，未对现有服务做任何改动。"
    exit 1
  fi
fi

if [ ! -s "$STAGE_SERVER" ]; then
  err "新版本服务端文件为空或不存在，未对现有服务做任何改动。"
  exit 1
fi
chmod 0755 "$STAGE_SERVER"

# 预拉取客户端二进制文件 (先放在临时目录，替换成功后再落盘)
log "正在预拉取客户端二进制文件 (用于服务器托管分发)..."
download_from_gh "opennofrp-client-linux-$ARCH" "$STAGE_CLIENT_DIR/opennofrp-client-linux-$ARCH" || warn "客户端 linux/$ARCH 预拉取失败，将保留现有托管文件"
if [ "$ARCH" = "amd64" ]; then
  download_from_gh "opennofrp-client-linux-arm64" "$STAGE_CLIENT_DIR/opennofrp-client-linux-arm64" 2>/dev/null || true
else
  download_from_gh "opennofrp-client-linux-amd64" "$STAGE_CLIENT_DIR/opennofrp-client-linux-amd64" 2>/dev/null || true
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

mkdir -p "$INSTALL_DIR" "$CLIENT_BINS_DIR" "$CONFIG_DIR" "$DATA_DIR"
chmod 0750 "$CONFIG_DIR"
chmod 0700 "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR" "$DATA_DIR"

if [ -f "$CONFIG_FILE" ]; then
  log "✓ 检查到已有配置文件 $CONFIG_FILE，已为您完整保留，绝不覆盖！"
else
  log "生成全新服务端初始配置文件 $CONFIG_FILE"
  "$STAGE_SERVER" init-config -path "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE"
fi
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE"

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
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" "$BINARY_DEST"

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
chown -R "$SERVICE_USER:$SERVICE_USER" "$CLIENT_BINS_DIR"

# ----------------------------------------------------------------------
# 6. 汇总并展示结果
# ----------------------------------------------------------------------
PW_FILE="$DATA_DIR/opennofrp-initial-password.txt"
PASSWORD="可在日志中查看"
if [ -f "$PW_FILE" ]; then
  PASSWORD="$(grep '^password=' "$PW_FILE" | cut -d'=' -f2 || true)"
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
echo "  Web 管理控制台:  http://$(curl -s4 ip.sb 2>/dev/null || echo "您的服务器公网IP"):8080"
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
