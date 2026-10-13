package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"opennofrp/pkg/crypto/tlsutil"
	"opennofrp/pkg/protocol"
	"opennofrp/pkg/tempvpn"
	"opennofrp/pkg/updater"
)

type vpnTarget struct {
	ID, Name string
	Ready    bool
}
type vpnLease struct {
	ID                            int64
	Name, Client, Expires, Status string
	Active                        bool
}

func (p *Panel) handleVPNGet(w http.ResponseWriter, r *http.Request) { p.renderVPN(w, r, "", "") }

func (p *Panel) renderVPN(w http.ResponseWriter, r *http.Request, message, config string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	clients, err := p.Store.ListClients(r.Context())
	if err != nil {
		http.Error(w, "读取内网机器失败", 500)
		return
	}
	targets := make([]vpnTarget, 0, len(clients))
	for _, c := range clients {
		ready := false
		if p.ClientStatus != nil {
			online, _, caps := p.ClientStatus(c.ID)
			for _, cap := range caps {
				if online && cap == protocol.CapTemporaryVPN {
					ready = true
				}
			}
		}
		targets = append(targets, vpnTarget{c.ID, c.Name, ready})
	}
	rows, err := p.Store.ListTemporaryVPN(r.Context())
	if err != nil {
		http.Error(w, "读取临时接入失败", 500)
		return
	}
	leases := make([]vpnLease, 0, len(rows))
	for _, v := range rows {
		status, active := "有效", true
		if v.Revoked {
			status, active = "已撤销", false
		} else if !v.ExpiresAt.After(time.Now()) {
			status, active = "已过期", false
		}
		leases = append(leases, vpnLease{v.ID, v.Name, v.ClientName, v.ExpiresAt.Local().Format("2006-01-02 15:04:05 MST"), status, active})
	}
	data := map[string]any{"PageTitle": "临时 VPN", "CSRF": csrfFrom(r), "Error": message, "Config": config, "Targets": targets, "Leases": leases}
	var rendered bytes.Buffer
	if err := p.tmpl.ExecuteTemplate(&rendered, "vpn.html", data); err != nil {
		p.Logger.Error("render VPN page", "error", err)
		http.Error(w, "页面加载失败", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(rendered.Bytes())
}

func (p *Panel) handleVPNCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		p.renderVPN(w, r, "表单无效，请重新填写。", "")
		return
	}
	name, clientID := strings.TrimSpace(r.FormValue("name")), r.FormValue("client_id")
	aliases := []string{}
	if value := strings.TrimSpace(r.FormValue("hosts")); value != "" {
		aliases = strings.FieldsFunc(value, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\t' || c == '\r' })
	}
	aliases, err := tempvpn.NormalizeHosts(aliases)
	if err != nil {
		p.renderVPN(w, r, err.Error(), "")
		return
	}
	minutes, err := strconv.Atoi(r.FormValue("minutes"))
	if err != nil || (minutes != 15 && minutes != 60 && minutes != 240 && minutes != 1440) || name == "" || len(name) > 120 {
		p.renderVPN(w, r, "请填写名称并选择有效期；名称最多 120 字节。", "")
		return
	}
	ready := false
	if p.ClientStatus != nil {
		online, _, caps := p.ClientStatus(clientID)
		for _, cap := range caps {
			if online && cap == protocol.CapTemporaryVPN {
				ready = true
			}
		}
	}
	if !ready {
		p.renderVPN(w, r, "目标机器必须在线，且 Client 已更新到支持临时 VPN 的版本。", "")
		return
	}
	host := strings.TrimSpace(p.ControlHost)
	if host == "" {
		u, err := url.Parse(p.baseURLOf(r))
		if err == nil {
			host = u.Hostname()
		}
	}
	if host == "" || p.ControlPort < 1 || p.ControlPort > 65535 || len(tlsutil.NormalizeFingerprint(p.Fingerprint)) != 64 {
		p.renderVPN(w, r, "请先配置服务端对外控制地址、端口及 TLS 指纹。", "")
		return
	}
	for _, alias := range aliases {
		if strings.EqualFold(strings.TrimSuffix(host, "."), alias) {
			p.renderVPN(w, r, "HOST 别名不能与服务端控制地址相同。", "")
			return
		}
	}
	lease, token, err := p.Store.CreateTemporaryVPN(r.Context(), clientID, name, time.Duration(minutes)*time.Minute)
	if err != nil {
		p.Logger.Error("create temporary VPN", "error", err)
		p.renderVPN(w, r, "创建失败，请检查目标机器是否存在。", "")
		return
	}
	config, _ := json.MarshalIndent(tempvpn.Config{Server: net.JoinHostPort(host, strconv.Itoa(p.ControlPort)), Fingerprint: p.Fingerprint, Token: token, ExpiresAt: lease.ExpiresAt.Unix(), Hosts: aliases}, "", "  ")
	p.renderVPN(w, r, "", string(config))
}

func (p *Panel) handleVPNRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "无效的接入编号", 400)
		return
	}
	if err := p.Store.RevokeTemporaryVPN(r.Context(), id); err != nil {
		http.Error(w, "撤销失败", 500)
		return
	}
	http.Redirect(w, r, "/vpn", http.StatusSeeOther)
}

func (p *Panel) handleVPNDownload(w http.ResponseWriter, r *http.Request) {
	names := map[string]string{
		"windows-amd64": "opennofrp-vpn-windows-amd64.exe",
		"windows-arm64": "opennofrp-vpn-windows-arm64.exe",
		"windows-386":   "opennofrp-vpn-windows-386.exe",
		"linux-amd64":   "opennofrp-vpn-linux-amd64",
		"linux-arm64":   "opennofrp-vpn-linux-arm64",
	}
	name, ok := names[r.PathValue("platform")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("source") == "local" {
		if p.ClientBinDir == "" {
			http.NotFound(w, r)
			return
		}
		file := filepath.Join(p.ClientBinDir, name)
		if info, err := os.Stat(file); err == nil && info.Mode().IsRegular() {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
			http.ServeFile(w, r, file)
			return
		}
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "https://github.com/"+updater.GitHubRepo+"/releases/latest/download/"+name, http.StatusFound)
}
