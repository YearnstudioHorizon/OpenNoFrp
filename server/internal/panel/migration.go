// Panel 迁移功能：把整台 OpenNoFrp 服务端（配置 + SQLite 数据库 + TLS 证书）
// 一键迁移到另一台 Linux 机器。全程点对点：新机器直接从旧服务器的面板 HTTP
// 接口拉取一个一次性 bundle，无需任何中转存储。
//
// 流程：
//  1. 管理员在旧服务器的面板「账号设置」页点击生成迁移命令；
//  2. 面板创建一次性 migration token 并渲染一条 curl | sudo bash 命令；
//  3. 管理员把该命令粘贴到新 Linux 机器上执行：
//     migrate.sh 安装最新版 server 二进制 → 从旧面板下载 bundle.tar.gz →
//     校验并落盘数据 → 注册 systemd 服务并启动；
//  4. 确认新服务器工作正常后，管理员自行停用旧服务器。
package panel

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// MigrationPaths 汇总导出迁移 bundle 所需的全部服务端本地文件路径。
type MigrationPaths struct {
	ConfigFile string // server.toml
	DBPath     string // opennofrp.db（WAL 的 -wal/-shm 同伴文件一并导出）
	TLSCert    string // 控制通道 TLS 证书
	TLSKey     string // 控制通道 TLS 私钥
	ACMEDir    string // ACME 证书缓存目录（可不存在）
	DataDir    string // 其余数据文件所在目录（初始密码文件等，可不存在）
}

const migrationTokenTTL = 30 * time.Minute

// handleCreateMigrationToken 生成一次性迁移令牌并渲染迁移命令。
func (p *Panel) handleCreateMigrationToken(w http.ResponseWriter, r *http.Request) {
	tok, err := p.Store.CreateMigrationToken(r.Context(), migrationTokenTTL)
	if err != nil {
		p.redirectErr(w, r, "/account?err="+url.QueryEscape(err.Error()))
		return
	}
	base := p.baseURLOf(r)
	cmd := fmt.Sprintf("curl -fsSL \"%s/migrate.sh?token=%s\" | sudo bash", base, tok)
	data := p.workspaceData(r, "account")
	data["MigrationCommand"] = cmd
	p.tmpl.ExecuteTemplate(w, "index.html", data)
}

// handleMigrateScript 下发在新 Linux 机器上执行的迁移引导脚本。
// 令牌仅做格式校验（真正的消费发生在下载数据时），未消费前可反复获取脚本。
func (p *Panel) handleMigrateScript(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" || len(token) > 64 || !validTokenRegex.MatchString(token) {
		http.Error(w, "missing or invalid token format", http.StatusBadRequest)
		return
	}

	base := p.baseURLOf(r)
	host := p.ControlHost
	if host == "" || host == "0.0.0.0" {
		host = sanitizeHost(r.Host)
	}

	w.Header().Set("Content-Type", "text/x-shellscript")
	fmt.Fprintf(w, migrationScriptTemplate,
		escapeShellSingleQuote(base),
		escapeShellSingleQuote(token),
		escapeShellSingleQuote(host),
	)
}

// handleMigrateData 校验并消费迁移令牌，然后流式返回打包好的 tar.gz bundle。
// 令牌一次性：下载中断也不会重放（需管理员重新生成），因为 bundle 内含
// TLS 私钥与全部客户端凭据哈希。
func (p *Panel) handleMigrateData(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" || len(token) > 64 || !validTokenRegex.MatchString(token) {
		http.Error(w, "missing or invalid token format", http.StatusBadRequest)
		return
	}
	if err := p.Store.ConsumeMigrationToken(r.Context(), token); err != nil {
		http.Error(w, "invalid, expired or already-used migration token", http.StatusForbidden)
		return
	}

	mp := p.MigrationPaths
	if mp == nil || mp.DBPath == "" {
		http.Error(w, "migration not configured on this server", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=opennofrp-migration.tar.gz")
	if err := writeMigrationBundle(w, *mp); err != nil {
		p.Logger.Error("panel: write migration bundle failed", "error", err)
		// 头部已写出，只能中断连接让脚本端报错。
		panic(http.ErrAbortHandler)
	}
}

// writeMigrationBundle 把服务端的全部持久化状态打包为 tar.gz 写入 w。
// 数据库在 WAL 模式下的 -wal/-shm 同伴文件必须与主库文件一起导出，
// 否则最近的事务会丢失。
func writeMigrationBundle(w io.Writer, mp MigrationPaths) error {
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	addFile := func(name, path string) error {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // 可选文件（证书/密码文件等）缺失时跳过
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		hdr.Mode = 0o600
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	}

	// 1. 配置文件与数据库（含 WAL 同伴）。
	if err := addFile("server.toml", mp.ConfigFile); err != nil {
		return err
	}
	if err := addFile("opennofrp.db", mp.DBPath); err != nil {
		return fmt.Errorf("export database: %w", err)
	}
	if err := addFile("opennofrp.db-wal", mp.DBPath+"-wal"); err != nil {
		return err
	}
	if err := addFile("opennofrp.db-shm", mp.DBPath+"-shm"); err != nil {
		return err
	}

	// 2. 控制通道 TLS 证书（客户端凭指纹/TOFU 绑定，迁移后原样保留）。
	if err := addFile("server.crt", mp.TLSCert); err != nil {
		return err
	}
	if err := addFile("server.key", mp.TLSKey); err != nil {
		return err
	}

	// 3. ACME 证书缓存目录（HTTPS 规则使用的证书私钥）。
	if mp.ACMEDir != "" {
		entries, err := os.ReadDir(mp.ACMEDir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				if err := addFile(filepath.ToSlash(filepath.Join("acme", e.Name())), filepath.Join(mp.ACMEDir, e.Name())); err != nil {
					return err
				}
			}
		}
	}

	// 4. 数据目录中的初始密码文件等辅助文件。
	if mp.DataDir != "" && mp.DataDir != filepath.Dir(mp.DBPath) {
		entries, err := os.ReadDir(mp.DataDir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || !e.Type().IsRegular() {
					continue
				}
				if err := addFile(filepath.ToSlash(filepath.Join("data", e.Name())), filepath.Join(mp.DataDir, e.Name())); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// migrationScriptTemplate 是在新 Linux 机器上执行的迁移脚本模板。
// 参数：base（旧面板 URL）、token、host（旧控制地址，仅用于提示）。
const migrationScriptTemplate = `#!/bin/bash
# OpenNoFrp server migration script (generated by the source panel).
# Installs the latest server binary, pulls a one-shot data bundle from
# the source panel, restores it locally and starts the service.
set -euo pipefail
BASE_URL=%s
TOKEN=%s
SOURCE_HOST=%s

log() { echo "[opennofrp-migrate] $*"; }
err() { echo "[opennofrp-migrate] 错误: $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
  err "本脚本必须以 root 权限运行"
  exit 1
fi
case "$(uname -s)" in
  Linux) ;;
  *) err "目标迁移机器仅支持 Linux"; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) err "unsupported arch: $(uname -m)"; exit 1 ;;
esac

INSTALL_DIR="/opt/opennofrp"
CONFIG_DIR="/etc/opennofrp"
DATA_DIR="/var/lib/opennofrp"
CONFIG_FILE="$CONFIG_DIR/server.toml"
SERVICE_NAME="opennofrp-server"

if [ -f "$CONFIG_FILE" ] || systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  err "目标机器上已存在 OpenNoFrp 服务端。迁移脚本不会覆盖现有安装；请先卸载（或换一台干净机器）后重试。"
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- 1. 安装最新版 server 二进制（复用官方安装脚本的前半段逻辑） ---
REPO="YearnstudioHorizon/OpenNoFrp"
MIRROR_PREFIX="https://mirror.yearnstudio.cn/"
STAGE_SERVER="$TMP/opennofrp-server"

get_latest_tag() {
  local tag="" loc
  loc=$(curl -4 -sI --connect-timeout 6 -m 8 "https://github.com/$REPO/releases/latest" 2>/dev/null | grep -i "^location:" | tr -d "\r\n" || true)
  [ -z "$loc" ] && loc=$(curl -sI --connect-timeout 6 -m 8 "https://github.com/$REPO/releases/latest" 2>/dev/null | grep -i "^location:" | tr -d "\r\n" || true)
  [ -n "$loc" ] && tag=$(echo "$loc" | awk -F"/tag/" '{print $2}' | tr -d " \r\n")
  if [ -z "$tag" ]; then
    tag=$(curl -4 -s --connect-timeout 6 -m 10 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name":' | head -n1 | cut -d'"' -f4 || true)
  fi
  if [ -z "$tag" ]; then
    tag=$(curl -4 -s --connect-timeout 6 -m 12 "${MIRROR_PREFIX}https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name":' | head -n1 | cut -d'"' -f4 || true)
  fi
  echo "$tag"
}

download_server() {
  local tag gh_url mirror_url
  tag="$(get_latest_tag)"
  if [ -n "$tag" ]; then
    gh_url="https://github.com/$REPO/releases/download/$tag/opennofrp-server-linux-$ARCH"
    mirror_url="${MIRROR_PREFIX}${gh_url}"
    if curl -4 -fsSL --connect-timeout 15 -m 120 --retry 2 "$gh_url" -o "$STAGE_SERVER" 2>/dev/null; then
      log "已从 GitHub Releases 下载服务端 ($tag)"
      return 0
    fi
    log "GitHub 直连超时，切换国内加速镜像..."
    if curl -4 -fsSL --connect-timeout 15 -m 180 "$mirror_url" -o "$STAGE_SERVER" 2>/dev/null; then
      log "已通过加速镜像下载服务端 ($tag)"
      return 0
    fi
  else
    if curl -fsSL --connect-timeout 15 -m 120 "https://github.com/$REPO/releases/latest/download/opennofrp-server-linux-$ARCH" -o "$STAGE_SERVER" 2>/dev/null; then
      log "已从 GitHub Releases 下载服务端"
      return 0
    fi
  fi
  err "服务端二进制下载失败"
  return 1
}

log "正在下载最新版服务端二进制 (linux/$ARCH)..."
download_server
chmod 0755 "$STAGE_SERVER"

# --- 2. 从旧面板拉取一次性迁移 bundle ---
BUNDLE="$TMP/bundle.tar.gz"
log "正在从源服务器 $BASE_URL 拉取迁移数据（令牌一次性，中断后需重新生成）..."
if ! curl -4 -fsSL --connect-timeout 10 -m 600 "$BASE_URL/migrate/data?token=$TOKEN" -o "$BUNDLE"; then
  err "迁移数据下载失败。请确认：1) 令牌未过期（30 分钟）且未用过；2) 新机器可访问旧面板端口。"
  exit 1
fi
if [ ! -s "$BUNDLE" ] || [ "$(stat -c%%s "$BUNDLE")" -lt 200 ]; then
  err "迁移数据为空或过小，可能令牌已失效"
  exit 1
fi
MAGIC=$(head -c 2 "$BUNDLE" 2>/dev/null || true)
if [ "$MAGIC" != $'\x1f\x8b' ]; then
  err "迁移数据不是有效的 gzip 文件（可能令牌失效返回了错误页）"
  exit 1
fi

EXTRACT="$TMP/extract"
mkdir -p "$EXTRACT"
tar -xzf "$BUNDLE" -C "$EXTRACT"
[ -f "$EXTRACT/opennofrp.db" ] || { err "迁移数据中缺少数据库文件"; exit 1; }
[ -f "$EXTRACT/server.toml" ] || { err "迁移数据中缺少配置文件"; exit 1; }

# --- 3. 创建账户与目录、落盘数据 ---
SERVICE_USER="opennofrp"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"
chmod 0750 "$CONFIG_DIR"
chmod 0700 "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR" "$DATA_DIR"

install -m 0755 "$STAGE_SERVER" "$INSTALL_DIR/opennofrp-server"
install -m 0600 "$EXTRACT/server.toml" "$CONFIG_FILE"
chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_FILE" "$INSTALL_DIR" "$INSTALL_DIR/opennofrp-server"

DB_NAME="$(basename "$EXTRACT/opennofrp.db")"
install -m 0600 "$EXTRACT/opennofrp.db" "$DATA_DIR/$DB_NAME"
if [ -f "$EXTRACT/opennofrp.db-wal" ]; then install -m 0600 "$EXTRACT/opennofrp.db-wal" "$DATA_DIR/$DB_NAME-wal"; fi
if [ -f "$EXTRACT/opennofrp.db-shm" ]; then install -m 0600 "$EXTRACT/opennofrp.db-shm" "$DATA_DIR/$DB_NAME-shm"; fi
if [ -f "$EXTRACT/server.crt" ]; then install -m 0600 "$EXTRACT/server.crt" "$DATA_DIR/server.crt"; fi
if [ -f "$EXTRACT/server.key" ]; then install -m 0600 "$EXTRACT/server.key" "$DATA_DIR/server.key"; fi
if [ -d "$EXTRACT/acme" ]; then
  mkdir -p "$DATA_DIR/acme"
  cp -a "$EXTRACT/acme/." "$DATA_DIR/acme/"
fi
if [ -d "$EXTRACT/data" ]; then
  cp -a "$EXTRACT/data/." "$DATA_DIR/" 2>/dev/null || true
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"

log "迁移数据已落盘：数据库 / 规则 / 客户端凭据 / TLS 证书 / ACME 缓存均已保留"

# --- 4. 注册并启动 systemd 服务 ---
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<UNIT
[Unit]
Description=OpenNoFrp Server (Pure userspace forwarder with TLS & Fingerprint verification)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$INSTALL_DIR/opennofrp-server -c $CONFIG_FILE
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure
RestartSec=2
MemoryHigh=40%%
MemoryMax=50%%

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
systemctl start "$SERVICE_NAME"

sleep 2
for i in $(seq 1 8); do
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    sleep 1
  else
    err "服务启动失败，请检查: journalctl -u $SERVICE_NAME -n 30"
    exit 1
  fi
done

log "迁移完成！服务已在新机器上运行。"
echo "================================================================="
echo "  下一步："
echo "   1. 确认面板与隧道工作正常（客户端会自动重连新控制端口）"
echo "   2. DNS / 防火墙放行端口切换到新机器后，停用旧服务器："
echo "      旧机器: sudo systemctl disable --now opennofrp-server"
echo "   3. 管理员密码、规则、客户端凭据与旧机完全一致，无需重新配置"
echo "================================================================="
`
