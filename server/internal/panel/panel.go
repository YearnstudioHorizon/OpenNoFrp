// Package panel implements the embedded web administration UI of the
// OpenNoFrp Server. It is served by the same binary (same process, same
// port namespace as the control listener but on its own port) and shares
// the same SQLite store. Everything that mutates rules also notifies the
// Server core via OnRulesChanged so public listeners and connected Clients
// can be reconciled immediately.
package panel

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"opennofrp/pkg/updater"
	"opennofrp/pkg/version"
	"opennofrp/server/internal/store"
)

//go:embed templates static
var templateFS embed.FS

// OnRulesChanged is called after any panel mutation that can change which
// public listeners or which rule-set should be live for a Client.
type OnRulesChanged func()

type Panel struct {
	Store   *store.Store
	Logger  *slog.Logger
	OnRules OnRulesChanged

	// BaseURL is how the panel reaches itself from the internet (e.g.
	// "http://1.2.3.4:8080"); falls back to the request's Host header.
	BaseURL string
	// ControlHost/ControlPort identify the control endpoint the client
	// will dial; rendered into the install command/script.
	ControlHost string
	ControlPort int
	// Fingerprint is the SHA-256 fingerprint of the server's TLS certificate.
	Fingerprint string
	// ClientBinDir serves /dl/opennofrp-client-<os>-<arch>
	ClientBinDir string

	tmpl *template.Template

	mu       sync.Mutex
	sessions map[string]time.Time
}

func New(st *store.Store, logger *slog.Logger, onRules OnRulesChanged, baseURL, controlHost string, controlPort int, fingerprint, clientBinDir string) *Panel {
	tpl := template.Must(template.ParseFS(templateFS, "templates/*"))
	return &Panel{
		Store: st, Logger: logger, OnRules: onRules,
		BaseURL: baseURL, ControlHost: controlHost, ControlPort: controlPort,
		Fingerprint: fingerprint, ClientBinDir: clientBinDir, tmpl: tpl,
		sessions: map[string]time.Time{},
	}
}

// Handler returns the root http.Handler for the panel.
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", p.handleLoginGet)
	mux.HandleFunc("POST /login", p.handleLoginPost)
	mux.HandleFunc("POST /logout", p.handleLogout)

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !p.authed(r) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("GET /", auth(p.handleIndex))
	mux.HandleFunc("POST /register-token", auth(p.handleCreateToken))
	mux.HandleFunc("GET /clients/{id}", auth(p.handleClientPage))
	mux.HandleFunc("POST /clients/{id}/rules", auth(p.handleCreateRule))
	mux.HandleFunc("POST /clients/{id}/rename", auth(p.handleRenameClient))
	mux.HandleFunc("POST /clients/{id}/delete", auth(p.handleDeleteClient))
	mux.HandleFunc("POST /rules/{id}/toggle", auth(p.handleToggleRule))
	mux.HandleFunc("POST /rules/{id}/delete", auth(p.handleDeleteRule))
	mux.HandleFunc("POST /reserved/add", auth(p.handleAddReserved))
	mux.HandleFunc("POST /reserved/remove", auth(p.handleRemoveReserved))
	mux.HandleFunc("POST /admin/password", auth(p.handleChangePassword))
	mux.HandleFunc("GET /api/check-update", auth(p.handleCheckUpdate))
	mux.HandleFunc("GET /install_client.sh", p.handleInstallScript)
	mux.HandleFunc("GET /dl/{name}", p.handleDownload)
	static, _ := fs.Sub(templateFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	return mux
}

// ---- auth -----------------------------------------------------------------

func (p *Panel) authed(r *http.Request) bool {
	c, err := r.Cookie("onfr_session")
	if err != nil || c.Value == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	exp, ok := p.sessions[c.Value]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(p.sessions, c.Value)
		return false
	}
	return true
}

func (p *Panel) setSessionCookie(w http.ResponseWriter) {
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	p.mu.Lock()
	p.sessions[tok] = time.Now().Add(12 * time.Hour)
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "onfr_session", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (p *Panel) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	p.tmpl.ExecuteTemplate(w, "login.html", nil)
}

func (p *Panel) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ok, err := p.Store.VerifyAdmin(r.Context(), r.FormValue("username"), r.FormValue("password"))
	if err != nil || !ok {
		p.tmpl.ExecuteTemplate(w, "login.html", map[string]any{"Error": friendlyMsg("invalid credentials")})
		return
	}
	p.setSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *Panel) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("onfr_session"); err == nil {
		p.mu.Lock()
		delete(p.sessions, c.Value)
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "onfr_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- dashboard --------------------------------------------------------------

type clientRow struct {
	ID        string
	Name      string
	LastSeen  string
	Online    bool
	RuleCount int
}

// friendlyMsg 翻译重定向里携带的 err/ok 参数，输出用户可读的中文提示；
// 未识别的原始信息按解码后的内容直接展示。
func friendlyMsg(s string) string {
	switch s {
	case "":
		return ""
	case "invalid credentials":
		return "用户名或密码错误"
	case "bad protocol":
		return "协议无效，仅支持 TCP 或 UDP"
	case "bad port":
		return "端口无效，请填写 1–65535 之间的数字"
	case "password too short":
		return "新密码长度至少 6 位"
	case "password changed":
		return "密码修改成功"
	}
	if strings.HasPrefix(s, "remote_port ") {
		if i := strings.Index(s, " is reserved ("); i > 0 && strings.HasSuffix(s, ")") {
			port := strings.TrimPrefix(s[:i], "remote_port ")
			reason := s[i+len(" is reserved (") : len(s)-1]
			return fmt.Sprintf("公网端口 %s 是保留端口（%s），不能用于转发", port, reason)
		}
		if strings.HasSuffix(s, " already used") {
			port := strings.TrimSuffix(strings.TrimPrefix(s, "remote_port "), " already used")
			return fmt.Sprintf("公网端口 %s 已被其他规则占用", port)
		}
	}
	return s
}

// indexData 构造首页模板数据（首页与"生成令牌"后回显共用）。
func (p *Panel) indexData(r *http.Request) map[string]any {
	clients, _ := p.Store.ListClients(r.Context())
	rows := []clientRow{}
	onlineCount, totalRules := 0, 0
	for _, c := range clients {
		rules, _ := p.Store.ListRulesForClient(r.Context(), c.ID)
		online := !c.LastSeenAt.IsZero() && time.Since(c.LastSeenAt) < 2*time.Minute
		lastSeen := "从未连接"
		if !c.LastSeenAt.IsZero() {
			lastSeen = c.LastSeenAt.Format("2006-01-02 15:04")
		}
		if online {
			onlineCount++
		}
		totalRules += len(rules)
		rows = append(rows, clientRow{ID: c.ID, Name: c.Name, LastSeen: lastSeen, Online: online, RuleCount: len(rules)})
	}
	reserved, _ := p.Store.ReservedPorts(r.Context())
	return map[string]any{
		"Clients": rows, "Reserved": reserved,
		"OnlineCount": onlineCount, "ClientCount": len(rows), "TotalRules": totalRules,
		"Fingerprint": p.Fingerprint, "Version": version.Version,
		"Error":  friendlyMsg(r.URL.Query().Get("err")),
		"Notice": friendlyMsg(r.URL.Query().Get("ok")),
	}
}

func (p *Panel) handleIndex(w http.ResponseWriter, r *http.Request) {
	p.tmpl.ExecuteTemplate(w, "index.html", p.indexData(r))
}

func (p *Panel) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ttlMin, _ := strconv.Atoi(r.FormValue("ttl"))
	if ttlMin <= 0 {
		ttlMin = 60
	}
	tok, err := p.Store.CreateRegisterToken(r.Context(), r.FormValue("label"), time.Duration(ttlMin)*time.Minute)
	if err != nil {
		p.redirectErr(w, r, "/?err="+url.QueryEscape(err.Error()))
		return
	}
	base := p.baseURLOf(r)
	cmd := fmt.Sprintf("curl -fsSL \"%s/install_client.sh?token=%s&fingerprint=%s\" | sudo bash", base, tok.Token, url.QueryEscape(p.Fingerprint))
	data := p.indexData(r)
	data["NewToken"] = cmd
	p.tmpl.ExecuteTemplate(w, "index.html", data)
}

func (p *Panel) handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	info, err := updater.CheckUpdate(r.Context(), version.Version)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{
			"ok":              false,
			"error":           err.Error(),
			"current_version": version.Version,
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"ok":   true,
		"info": info,
	})
}

// ---- client page ----------------------------------------------------------

func (p *Panel) handleClientPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := p.Store.GetClient(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rules, _ := p.Store.ListRulesForClient(r.Context(), id)
	lastSeen := "从未连接"
	if !c.LastSeenAt.IsZero() {
		lastSeen = c.LastSeenAt.Format("2006-01-02 15:04")
	}
	online := !c.LastSeenAt.IsZero() && time.Since(c.LastSeenAt) < 2*time.Minute
	p.tmpl.ExecuteTemplate(w, "client.html", map[string]any{
		"Client": struct {
			ID, Name, LastSeen string
		}{ID: c.ID, Name: c.Name, LastSeen: lastSeen},
		"Online": online,
		"Rules":  rules,
		"Error":  friendlyMsg(r.URL.Query().Get("err")),
		"Notice": friendlyMsg(r.URL.Query().Get("ok")),
	})
}

func (p *Panel) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	clientID := r.PathValue("id")

	protocol := r.FormValue("protocol")
	if protocol != "tcp" && protocol != "udp" {
		p.redirectErr(w, r, fmt.Sprintf("/clients/%s?err=bad+protocol", clientID))
		return
	}
	localPort, _ := strconv.Atoi(r.FormValue("local_port"))
	remotePort, _ := strconv.Atoi(r.FormValue("remote_port"))
	if localPort <= 0 || localPort > 65535 || remotePort <= 0 || remotePort > 65535 {
		p.redirectErr(w, r, fmt.Sprintf("/clients/%s?err=bad+port", clientID))
		return
	}
	reserved, _ := p.Store.ReservedPorts(r.Context())
	if reason, reserved := reserved[uint16(remotePort)]; reserved {
		p.redirectErr(w, r, "/clients/"+clientID+"?err="+url.QueryEscape(fmt.Sprintf("remote_port %d is reserved (%s)", remotePort, reason)))
		return
	}
	used, err := p.Store.RemotePortInUse(r.Context(), uint16(remotePort), 0)
	if err == nil && used {
		p.redirectErr(w, r, "/clients/"+clientID+"?err="+url.QueryEscape(fmt.Sprintf("remote_port %d already used", remotePort)))
		return
	}
	localIP := r.FormValue("local_ip")
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	enabled := r.FormValue("enabled") == "1"
	_, err = p.Store.CreateRule(r.Context(), store.Rule{
		ClientID: clientID, Name: r.FormValue("name"), Protocol: protocol,
		LocalIP: localIP, LocalPort: uint16(localPort), RemotePort: uint16(remotePort),
		PreserveSourceIP: r.FormValue("preserve_source_ip") == "1", Enabled: enabled,
	})
	if err != nil {
		p.redirectErr(w, r, "/clients/"+clientID+"?err="+url.QueryEscape(err.Error()))
		return
	}
	p.rulesChanged()
	http.Redirect(w, r, "/clients/"+clientID, http.StatusSeeOther)
}

func (p *Panel) handleRenameClient(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	p.Store.RenameClient(r.Context(), r.PathValue("id"), r.FormValue("name"))
	http.Redirect(w, r, "/clients/"+r.PathValue("id"), http.StatusSeeOther)
}

func (p *Panel) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	p.Store.DeleteClient(r.Context(), r.PathValue("id"))
	p.rulesChanged()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *Panel) handleToggleRule(w http.ResponseWriter, r *http.Request) {
	id64, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rule, err := p.Store.GetRule(r.Context(), id64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p.Store.SetRuleEnabled(r.Context(), id64, !rule.Enabled)
	p.rulesChanged()
	http.Redirect(w, r, "/clients/"+rule.ClientID, http.StatusSeeOther)
}

func (p *Panel) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id64, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rule, err := p.Store.GetRule(r.Context(), id64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p.Store.DeleteRule(r.Context(), id64)
	p.rulesChanged()
	http.Redirect(w, r, "/clients/"+rule.ClientID, http.StatusSeeOther)
}

func (p *Panel) handleAddReserved(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	port, _ := strconv.Atoi(r.FormValue("port"))
	if port > 0 && port <= 65535 {
		p.Store.AddReservedPort(r.Context(), uint16(port), r.FormValue("reason"))
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *Panel) handleRemoveReserved(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	port, _ := strconv.Atoi(r.FormValue("port"))
	if port > 0 && port <= 65535 {
		p.Store.RemoveReservedPort(r.Context(), uint16(port))
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *Panel) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	pw := r.FormValue("new_password")
	if len(pw) < 6 {
		p.redirectErr(w, r, "/?err=password+too+short")
		return
	}
	p.Store.SetAdminPassword(r.Context(), pw)
	http.Redirect(w, r, "/?ok=password+changed", http.StatusSeeOther)
}

func (p *Panel) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	fp := r.URL.Query().Get("fingerprint")
	if fp == "" {
		fp = p.Fingerprint
	}
	base := p.baseURLOf(r)
	host := p.ControlHost
	if host == "" || host == "0.0.0.0" {
		host = r.Host // fallback: whatever host header the admin used
		host = strings.Split(host, ":")[0]
	}
	w.Header().Set("Content-Type", "text/x-shellscript")
	fmt.Fprintf(w, clientInstallScriptTemplate,
		host, p.ControlPort, token, fp, base)
}

func (p *Panel) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := path.Base(r.PathValue("name")) // guard against traversal
	http.ServeFile(w, r, p.ClientBinDir+"/"+name)
}

// ---- helpers -------------------------------------------------------------

func (p *Panel) rulesChanged() {
	if p.OnRules != nil {
		p.OnRules()
	}
}

func (p *Panel) redirectErr(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (p *Panel) baseURLOf(r *http.Request) string {
	if p.BaseURL != "" {
		return p.BaseURL
	}
	return "http://" + r.Host
}

const clientInstallScriptTemplate = `#!/bin/bash
# OpenNoFrp internal-client one-time install script, generated by the
# admin panel. The --token baked below is SINGLE-USE: after this machine
# completes its first registration it persists permanent credentials to
# /etc/opennofrp/client_credentials.toml and any later copy of this command
# will fail to re-register a second machine.
set -euo pipefail
SERVER_HOST="%s"
SERVER_PORT="%d"
TOKEN="%s"
FINGERPRINT="%s"
BASE_URL="%s"

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac
}

ARCH="$(detect_arch)"
echo "[opennofrp] downloading client for linux/$ARCH"
TMP="$(mktemp -d)"
CLIENT_BIN="$TMP/opennofrp-client"

download_client() {
  # 1. 尝试从服务端本地 client_bin_dir 托管路径下载
  if curl -fsSL --connect-timeout 5 -m 60 "$BASE_URL/dl/opennofrp-client-linux-$ARCH" -o "$CLIENT_BIN" 2>/dev/null; then
    echo "[opennofrp] downloaded from server local storage ($BASE_URL/dl)"
    return 0
  fi

  echo "[opennofrp] local server binary not found, falling back to GitHub Releases..."

  GH_URL="https://github.com/YearnstudioHorizon/OpenNoFrp/releases/latest/download/opennofrp-client-linux-$ARCH"
  MIRROR_URL="https://mirror.yearnstudio.cn/$GH_URL"

  # 2. 尝试从 GitHub 官方下载 (超时限制 8 秒)
  if curl -fsSL --connect-timeout 8 -m 120 "$GH_URL" -o "$CLIENT_BIN" 2>/dev/null; then
    echo "[opennofrp] downloaded from GitHub Releases"
    return 0
  fi

  # 3. GitHub 直连超时或受限，自动切换至 mirror.yearnstudio.cn 镜像加速
  echo "[opennofrp] GitHub direct download timed out, switching to mirror accelerator (https://mirror.yearnstudio.cn/)..."
  if curl -fsSL --connect-timeout 10 -m 120 "$MIRROR_URL" -o "$CLIENT_BIN"; then
    echo "[opennofrp] downloaded via YearnStudio mirror accelerator"
    return 0
  fi

  echo "[opennofrp] ERROR: could not download client binary from server, GitHub, or mirror!" >&2
  exit 1
}

download_client
chmod +x "$CLIENT_BIN"

mkdir -p /opt/opennofrp /etc/opennofrp /var/lib/opennofrp
if systemctl is-active --quiet opennofrp-client 2>/dev/null; then
  echo "[opennofrp] stopping running client service before upgrade..."
  systemctl stop opennofrp-client || true
fi
install -m 0755 "$CLIENT_BIN" /opt/opennofrp/opennofrp-client

if [ -f /etc/opennofrp/client.toml ]; then
  echo "[opennofrp] existing /etc/opennofrp/client.toml kept (config preserved)"
else
  cat > /etc/opennofrp/client.toml <<EOF
[server]
addr = "$SERVER_HOST"
port = $SERVER_PORT
token = "$TOKEN"
fingerprint = "$FINGERPRINT"
heartbeat_interval_seconds = 10
reconnect_min_seconds = 1
reconnect_max_seconds = 60

[log]
level = "info"
EOF
  chmod 0600 /etc/opennofrp/client.toml
fi

cat > /etc/systemd/system/opennofrp-client.service <<UNIT
[Unit]
Description=OpenNoFrp Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/opennofrp/opennofrp-client -c /etc/opennofrp/client.toml -state-dir /var/lib/opennofrp
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now opennofrp-client
echo "[opennofrp] client installed and started"
echo "[opennofrp] watch: journalctl -u opennofrp-client -f"
`
