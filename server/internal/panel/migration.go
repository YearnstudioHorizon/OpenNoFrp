// Panel 迁移功能：把整台 OpenNoFrp 服务端（配置 + SQLite 数据库 + TLS 证书）
// 一键迁移到另一台 Linux 机器。全程点对点：新机器直接从旧服务器的面板 HTTPS
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
	"github.com/BurntSushi/toml"
	"io"
	"net/http"
	"net/url"
	"opennofrp/pkg/updater"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// MigrationPaths 汇总导出迁移 bundle 所需的全部服务端本地文件路径。
type MigrationPaths struct {
	ConfigFile   string // server.toml
	DBPath       string // opennofrp.db
	TLSCert      string // 控制通道 TLS 证书
	TLSKey       string // 控制通道 TLS 私钥
	PanelTLSCert string
	PanelTLSKey  string
	ACMEDir      string // ACME 证书缓存目录（可不存在）
	DataDir      string // 其余数据文件所在目录（初始密码文件等，可不存在）
}

const migrationTokenTTL = 30 * time.Minute

// handleCreateMigrationToken 生成一次性迁移令牌并渲染迁移命令。
func (p *Panel) handleCreateMigrationToken(w http.ResponseWriter, r *http.Request) {
	base, ok := p.bootstrapURL(w, r)
	if !ok {
		return
	}
	tok, err := p.Store.CreateMigrationToken(r.Context(), migrationTokenTTL)
	if err != nil {
		p.redirectErr(w, r, "/account?err="+url.QueryEscape(err.Error()))
		return
	}
	cmd := bootstrapCommand(base.String() + "/migrate.sh?token=" + tok)
	data := p.workspaceData(r, "account")
	data["MigrationCommand"] = cmd
	p.tmpl.ExecuteTemplate(w, "index.html", data)
}

// handleMigrateScript 下发在新 Linux 机器上执行的迁移引导脚本。
// 令牌仅做格式校验（真正的消费发生在下载数据时），未消费前可反复获取脚本。
func (p *Panel) handleMigrateScript(w http.ResponseWriter, r *http.Request) {
	base, ok := p.bootstrapURL(w, r)
	if !ok {
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" || len(token) > 64 || !validTokenRegex.MatchString(token) {
		http.Error(w, "missing or invalid token format", http.StatusBadRequest)
		return
	}

	if !p.Store.CheckMigrationToken(r.Context(), token) {
		http.Error(w, "invalid or expired migration token", http.StatusForbidden)
		return
	}
	host := p.controlHost(base)

	w.Header().Set("Content-Type", "text/x-shellscript")
	fmt.Fprintf(w, migrationScriptTemplate,
		escapeShellSingleQuote(base.String()),
		escapeShellSingleQuote(token),
		escapeShellSingleQuote(host),
		updater.ReleaseScript,
	)
}

// handleMigrateData 校验并消费迁移令牌，然后流式返回打包好的 tar.gz bundle。
// 令牌一次性：下载中断也不会重放（需管理员重新生成），因为 bundle 内含
// TLS 私钥与全部客户端凭据哈希。
func (p *Panel) handleMigrateData(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.bootstrapURL(w, r); !ok {
		return
	}
	// HEAD must never consume the download token.
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	if len(token) != 48 || !validTokenRegex.MatchString(token) {
		http.Error(w, "missing or invalid token format", http.StatusBadRequest)
		return
	}
	if !p.Store.CheckMigrationToken(r.Context(), token) {
		http.Error(w, "invalid, expired or already-used migration token", http.StatusForbidden)
		return
	}
	if p.MigrationPaths == nil {
		http.Error(w, "migration not configured", http.StatusServiceUnavailable)
		return
	}
	select {
	case p.migrationSlot <- struct{}{}:
		defer func() { <-p.migrationSlot }()
	default:
		http.Error(w, "migration export in progress", http.StatusTooManyRequests)
		return
	}
	send := func() error {
		dir, err := os.MkdirTemp("", "opennofrp-migration-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		snapshot := filepath.Join(dir, "snapshot.db")
		if err := p.Store.SnapshotForMigration(r.Context(), snapshot); err != nil {
			return err
		}
		bundle, err := os.Create(filepath.Join(dir, "bundle"))
		if err != nil {
			return err
		}
		defer bundle.Close()
		if err := writeMigrationBundle(bundle, *p.MigrationPaths, snapshot); err != nil {
			return err
		}
		size, err := bundle.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
		if _, err := bundle.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := p.Store.ConsumeMigrationToken(r.Context(), token); err != nil {
			http.Error(w, "invalid, expired or already-used migration token", http.StatusForbidden)
			return nil
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", "attachment; filename=opennofrp-migration.tar.gz")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		if _, err := io.Copy(w, bundle); err != nil {
			p.Logger.Error("panel: send migration bundle", "error", err)
			panic(http.ErrAbortHandler)
		}
		return nil
	}
	if err := send(); err != nil {
		p.Logger.Error("panel: prepare migration bundle", "error", err)
		http.Error(w, "migration export failed, retry the download", http.StatusInternalServerError)
	}
}

// writeMigrationBundle 把服务端的全部持久化状态打包为 tar.gz 写入 w。
func writeMigrationBundle(w io.Writer, mp MigrationPaths, snapshot string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

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

	migratedConfig := filepath.Join(filepath.Dir(snapshot), "server.toml")
	if err := writeMigratedConfig(migratedConfig, mp); err != nil {
		return err
	}
	if err := addFile("server.toml", migratedConfig); err != nil {
		return err
	}
	if err := addFile("opennofrp.db", snapshot); err != nil {
		return fmt.Errorf("export database: %w", err)
	}

	// 2. 控制通道 TLS 证书（客户端凭指纹/TOFU 绑定，迁移后原样保留）。
	if err := addFile("server.crt", mp.TLSCert); err != nil {
		return err
	}
	if err := addFile("server.key", mp.TLSKey); err != nil {
		return err
	}

	if mp.PanelTLSCert != "" && mp.PanelTLSKey != "" {
		if err := addFile("panel.crt", mp.PanelTLSCert); err != nil {
			return err
		}
		if err := addFile("panel.key", mp.PanelTLSKey); err != nil {
			return err
		}
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

	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func writeMigratedConfig(path string, mp MigrationPaths) error {
	var config map[string]any
	if _, err := toml.DecodeFile(mp.ConfigFile, &config); err != nil {
		return err
	}
	server, ok := config["server"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing server config section")
	}
	server["db_path"] = "/var/lib/opennofrp-server/opennofrp.db"
	server["tls_cert_path"] = "/var/lib/opennofrp-server/server.crt"
	server["tls_key_path"] = "/var/lib/opennofrp-server/server.key"
	server["acme_cache_dir"] = "/var/lib/opennofrp-server/acme"
	server["client_bin_dir"] = "/opt/opennofrp-server/client-bins"
	if mp.PanelTLSCert != "" && mp.PanelTLSKey != "" {
		server["panel_tls_cert"] = "/var/lib/opennofrp-server/panel.crt"
		server["panel_tls_key"] = "/var/lib/opennofrp-server/panel.key"
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	encodeErr := toml.NewEncoder(file).Encode(config)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
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

INSTALL_DIR="/opt/opennofrp-server"
CONFIG_DIR="/etc/opennofrp-server"
DATA_DIR="/var/lib/opennofrp-server"
CONFIG_FILE="$CONFIG_DIR/server.toml"
SERVICE_NAME="opennofrp-server"

if [ -e "$CONFIG_FILE" ] || [ -e /etc/opennofrp/server.toml ] || [ -e "$DATA_DIR/opennofrp.db" ] || systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  err "目标机器上已存在 OpenNoFrp 服务端。迁移脚本不会覆盖现有安装；请先卸载（或换一台干净机器）后重试。"
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT


%s

STAGE_SERVER="$TMP/opennofrp-server"
release_metadata "$TMP"
download_release_asset "opennofrp-server-linux-$ARCH" "$STAGE_SERVER"
chmod 0755 "$STAGE_SERVER"

# --- 2. 从旧面板拉取一次性迁移 bundle ---
BUNDLE="$TMP/bundle.tar.gz"
log "正在从源服务器 $BASE_URL 拉取迁移数据（令牌一次性，中断后需重新生成）..."
if ! curl --proto '=https' -fsS --connect-timeout 10 -m 600 "$BASE_URL/migrate/data?token=$TOKEN" -o "$BUNDLE"; then
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
tar -xzf "$BUNDLE" --no-same-owner --no-same-permissions -C "$EXTRACT"
[ -f "$EXTRACT/opennofrp.db" ] || { err "迁移数据中缺少数据库文件"; exit 1; }
[ -f "$EXTRACT/server.toml" ] || { err "迁移数据中缺少配置文件"; exit 1; }

# --- 3. 创建账户与目录、落盘数据 ---
SERVICE_USER="opennofrp"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
for dir in "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"; do
  if [ -L "$dir" ]; then err "Refusing symlink: $dir"; exit 1; fi
done
install -d -m 0755 -o root -g root "$INSTALL_DIR"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"

install -m 0755 "$STAGE_SERVER" "$INSTALL_DIR/opennofrp-server"
install -m 0640 -o root -g "$SERVICE_USER" "$EXTRACT/server.toml" "$CONFIG_FILE"

DB_NAME="$(basename "$EXTRACT/opennofrp.db")"
install -m 0600 "$EXTRACT/opennofrp.db" "$DATA_DIR/$DB_NAME"
if [ -f "$EXTRACT/server.crt" ]; then install -m 0600 "$EXTRACT/server.crt" "$DATA_DIR/server.crt"; fi
if [ -f "$EXTRACT/server.key" ]; then install -m 0600 "$EXTRACT/server.key" "$DATA_DIR/server.key"; fi
if [ -f "$EXTRACT/panel.crt" ]; then install -m 0600 "$EXTRACT/panel.crt" "$DATA_DIR/panel.crt"; fi
if [ -f "$EXTRACT/panel.key" ]; then install -m 0600 "$EXTRACT/panel.key" "$DATA_DIR/panel.key"; fi
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
