// Package panel 实现了 OpenNoFrp Server 内嵌的 Web 管理界面。它由同一个
// 二进制程序提供服务（与控制监听器同进程、同端口命名空间，但使用独立端口），
// 并共享同一个 SQLite 存储。所有会修改规则的操作都会通过 OnRulesChanged
// 通知 Server 核心，以便立即对公网监听器和已连接的 Client 进行同步调整。
package panel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"opennofrp/pkg/protocol"
	"opennofrp/pkg/updater"
	"opennofrp/pkg/version"
	"opennofrp/server/internal/listener"
	"opennofrp/server/internal/store"
)

//go:embed templates static
var templateFS embed.FS

// OnRulesChanged 在任何可能改变公网监听器集合、或改变某个 Client 应生效的
// 规则集的面板变更操作之后被调用。
type OnRulesChanged func()

type loginAttempt struct {
	failedCount int
	lockedUntil time.Time
}

type Panel struct {
	Store   *store.Store
	Logger  *slog.Logger
	OnRules OnRulesChanged

	// BaseURL 是从互联网访问面板自身的地址（例如
	// "http://1.2.3.4:8080"）；为空时回退为请求的 Host 标头。
	BaseURL string
	// ControlHost/ControlPort 标识客户端将要连接的控制端点；会被渲染进
	// 安装命令/脚本中。
	ControlHost string
	ControlPort int
	// Fingerprint 是服务端 TLS 证书的 SHA-256 指纹。
	Fingerprint string
	// ClientBinDir 用于提供 /dl/opennofrp-client-<os>-<arch> 下载
	ClientBinDir string
	// ClientStatus 返回某个 Client 当前是否有活跃会话、其上报的版本与能力列表。
	// 由 Server 核心在构造后注入；为 nil 时面板回退为基于 LastSeen 的判断。
	ClientStatus func(clientID string) (online bool, version string, caps []string)
	// RuleStats 返回各规则的实时统计（活跃连接、流量、后端错误等），由 Server 核心注入；
	// 为 nil 时面板不显示统计，/metrics 只输出客户端在线状态。
	RuleStats func() []listener.RuleStats
	// MetricsToken 非空时，/metrics 允许使用 "Authorization: Bearer <token>" 免登录抓取
	// （供 Prometheus 使用）；为空时 /metrics 需要面板登录会话。
	MetricsToken string

	tmpl *template.Template

	mu            sync.Mutex
	loginAttempts map[string]*loginAttempt // IP -> 登录失败限速
}

func New(st *store.Store, logger *slog.Logger, onRules OnRulesChanged, baseURL, controlHost string, controlPort int, fingerprint, clientBinDir string) *Panel {
	tpl := template.Must(template.New("").Funcs(template.FuncMap{
		// humanBytes 把字节数格式化为 B / KB / MB / GB / TB。
		"humanBytes": func(n uint64) string {
			const unit = 1024
			if n < unit {
				return fmt.Sprintf("%d B", n)
			}
			div, exp := uint64(unit), 0
			for v := n / unit; v >= unit && exp < 3; v /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
		},
		// ruleStat 按规则 ID 取统计；不存在时返回零值。
		"ruleStat": func(m map[int64]listener.RuleStats, id int64) listener.RuleStats {
			return m[id]
		},
	}).ParseFS(templateFS, "templates/*"))
	return &Panel{
		Store: st, Logger: logger, OnRules: onRules,
		BaseURL: baseURL, ControlHost: controlHost, ControlPort: controlPort,
		Fingerprint: fingerprint, ClientBinDir: clientBinDir, tmpl: tpl,
		loginAttempts: map[string]*loginAttempt{},
	}
}

// Handler 返回面板的根 http.Handler。
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", p.handleLoginGet)
	mux.HandleFunc("POST /login", p.handleLoginPost)
	mux.HandleFunc("POST /logout", p.handleLogout)

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			csrf, ok := p.sessionCSRF(r)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			// 所有会修改状态的 POST 请求都必须携带与会话绑定的 CSRF 令牌。
			if r.Method == http.MethodPost && !checkCSRF(r, csrf) {
				p.Logger.Warn("panel: rejected request with invalid csrf token", "path", r.URL.Path, "remote", r.RemoteAddr)
				http.Error(w, "invalid or missing CSRF token, please reload the page", http.StatusForbidden)
				return
			}
			h(w, r.WithContext(context.WithValue(r.Context(), csrfCtxKey{}, csrf)))
		}
	}

	mux.HandleFunc("GET /", auth(p.handleIndex))
	mux.HandleFunc("POST /register-token", auth(p.handleCreateToken))
	mux.HandleFunc("GET /clients/{id}", auth(p.handleClientPage))
	mux.HandleFunc("POST /clients/{id}/rules", auth(p.handleCreateRule))
	mux.HandleFunc("POST /clients/{id}/rename", auth(p.handleRenameClient))
	mux.HandleFunc("POST /clients/{id}/delete", auth(p.handleDeleteClient))
	mux.HandleFunc("POST /rules/{id}/edit", auth(p.handleEditRule))
	mux.HandleFunc("POST /rules/{id}/toggle", auth(p.handleToggleRule))
	mux.HandleFunc("POST /rules/{id}/delete", auth(p.handleDeleteRule))
	mux.HandleFunc("POST /reserved/add", auth(p.handleAddReserved))
	mux.HandleFunc("POST /reserved/remove", auth(p.handleRemoveReserved))
	mux.HandleFunc("POST /admin/password", auth(p.handleChangePassword))
	mux.HandleFunc("GET /api/check-update", auth(p.handleCheckUpdate))
	// /metrics 自行鉴权：面板登录会话或 Bearer MetricsToken。
	mux.HandleFunc("GET /metrics", p.handleMetrics)
	// REST API（Bearer API 令牌鉴权，见 api.go）与面板内的令牌管理。
	p.registerAPI(mux)
	mux.HandleFunc("POST /api-tokens", auth(p.handleCreateAPIToken))
	mux.HandleFunc("POST /api-tokens/{id}/delete", auth(p.handleDeleteAPIToken))
	mux.HandleFunc("GET /install_client.sh", p.handleInstallScript)
	mux.HandleFunc("GET /dl/{name}", p.handleDownload)
	static, _ := fs.Sub(templateFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	return mux
}

// ---- 认证 -----------------------------------------------------------------

const (
	sessionCookieName = "onfr_session"
	sessionTTL        = 12 * time.Hour
)

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// hashSessionToken 返回会话 Cookie 的 SHA-256 哈希；数据库中只保存该哈希。
func hashSessionToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// sessionCSRF 返回当前请求所属会话的 CSRF 令牌；未登录或会话已过期时 ok 为 false。
func (p *Panel) sessionCSRF(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	csrf, _, ok, err := p.Store.GetPanelSession(r.Context(), hashSessionToken(c.Value))
	if err != nil {
		p.Logger.Warn("panel: load session failed", "error", err)
		return "", false
	}
	return csrf, ok
}

func (p *Panel) authed(r *http.Request) bool {
	_, ok := p.sessionCSRF(r)
	return ok
}

// csrfCtxKey 是请求上下文中保存当前会话 CSRF 令牌的键。
type csrfCtxKey struct{}

// csrfFrom 返回 auth 中间件放入请求上下文的 CSRF 令牌（供模板渲染隐藏字段）。
func csrfFrom(r *http.Request) string {
	s, _ := r.Context().Value(csrfCtxKey{}).(string)
	return s
}

// checkCSRF 校验表单字段 csrf_token 或请求头 X-CSRF-Token 是否与会话令牌一致。
func checkCSRF(r *http.Request, want string) bool {
	if want == "" {
		return false
	}
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = r.FormValue("csrf_token")
	}
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// setSessionCookie 创建一个新的持久化会话（含独立的 CSRF 令牌）并下发 Cookie。
func (p *Panel) setSessionCookie(w http.ResponseWriter, r *http.Request) {
	tok := randomHex(32)
	csrf := randomHex(32)
	if err := p.Store.CreatePanelSession(r.Context(), hashSessionToken(tok), csrf, time.Now().Add(sessionTTL)); err != nil {
		p.Logger.Error("panel: create session failed", "error", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, MaxAge: int(sessionTTL / time.Second),
	})
}

func (p *Panel) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	p.tmpl.ExecuteTemplate(w, "login.html", nil)
}

func (p *Panel) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// 1. 获取客户端来源 IP 进行限速与防爆破防御
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	p.mu.Lock()
	attempt, ok := p.loginAttempts[clientIP]
	if !ok {
		attempt = &loginAttempt{}
		p.loginAttempts[clientIP] = attempt
	}
	now := time.Now()
	if now.Before(attempt.lockedUntil) {
		p.mu.Unlock()
		w.WriteHeader(http.StatusTooManyRequests)
		p.tmpl.ExecuteTemplate(w, "login.html", map[string]any{"Error": "登录失败次数过多，账号已临时锁定，请 30 秒后再试"})
		return
	}
	p.mu.Unlock()

	// 2. 校验管理员账密 (store 内部恒定执行一次 bcrypt)
	okAuth, err := p.Store.VerifyAdmin(r.Context(), r.FormValue("username"), r.FormValue("password"))

	if err != nil || !okAuth {
		p.mu.Lock()
		attempt.failedCount++
		// 连续失败 5 次，锁定 30 秒
		if attempt.failedCount >= 5 {
			attempt.lockedUntil = time.Now().Add(30 * time.Second)
		}
		p.mu.Unlock()

		// 防御暴力破解延时惩罚 (300ms)
		time.Sleep(300 * time.Millisecond)

		p.tmpl.ExecuteTemplate(w, "login.html", map[string]any{"Error": friendlyMsg("invalid credentials")})
		return
	}

	// 3. 登录成功，重置失败尝试记录
	p.mu.Lock()
	delete(p.loginAttempts, clientIP)
	p.mu.Unlock()

	p.setSessionCookie(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *Panel) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		if err := p.Store.DeletePanelSession(r.Context(), hashSessionToken(c.Value)); err != nil {
			p.Logger.Warn("panel: delete session failed", "error", err)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- 仪表盘 --------------------------------------------------------------

type clientRow struct {
	ID        string
	Name      string
	LastSeen  string
	Online    bool
	RuleCount int
}

// friendlyMsg 翻译重定向里携带的 err/ok 参数，输出用户可读的中文提示；
func friendlyMsg(s string) string {
	switch s {
	case "":
		return ""
	case "invalid credentials":
		return "用户名或密码错误"
	case "bad protocol":
		return "协议无效，仅支持 HTTP、TLS 透传、TCP、UDP 或 TCP+UDP 双栈"
	case "bad port":
		return "端口无效，请填写 1–65535 之间的数字"
	case "bad local ip":
		return "本地 IP 无效，请填写合法的 IPv4/IPv6 地址"
	case "bad path prefix":
		return "路径前缀无效，须以 / 开头且只含合法 URL 字符"
	case "offline page too large":
		return "自定义不可用页面过大（上限 64 KB）"
	case "rule saved":
		return "规则已保存"
	case "acme needs domain":
		return "自动证书（ACME）至少需要绑定一个非通配的精确域名"
	case "tls cert required":
		return "自定义证书模式需要同时填写 PEM 证书和私钥"
	case "bad tls cert":
		return "证书或私钥无法解析，或二者不匹配，请检查 PEM 内容"
	case "bad tls mode":
		return "HTTPS 模式无效"
	case "redirect needs domain":
		return "开启 HTTP→HTTPS 跳转需要绑定至少一个域名"
	case "api token revoked":
		return "API 令牌已吊销"
	case "missing api token":
		return "缺少 API 令牌，请使用 Authorization: Bearer <token>"
	case "invalid api token":
		return "API 令牌无效或已吊销"
	case "read-only api token":
		return "该 API 令牌为只读，不能执行修改操作"
	case "client not found":
		return "内网机器不存在"
	case "rule not found":
		return "规则不存在"
	case "bad request body":
		return "请求体无效，请提交 JSON 对象或表单"
	case "internal error":
		return "服务器内部错误"
	case "bad host rewrite":
		return "Host 改写无效，请填写域名、IP 或 域名:端口（如 internal.local:8080）"
	case "bad req headers":
		return "自定义请求头无效：每行一个 \"Name: Value\"（值留空表示删除），不能修改 Host/Connection 等逐跳头"
	case "bad resp headers":
		return "自定义响应头无效：每行一个 \"Name: Value\"（值留空表示删除），不能修改 Connection 等逐跳头"
	case "bad basic auth":
		return "Basic Auth 账户无效：每行一个 \"用户名:密码\"，用户名不能含空格"
	case "not found page too large":
		return "自定义 404 页面过大（上限 64 KB）"
	case "password too short":
		return "新密码长度至少 6 位"
	case "invalid current password":
		return "当前旧密码错误，请重新输入"
	case "password changed":
		return "密码修改成功，所有已有登录会话已重新刷新"
	}
	if strings.HasPrefix(s, "bad ip source ") {
		return fmt.Sprintf("真实 IP 来源 %s 无效", strings.TrimPrefix(s, "bad ip source "))
	}
	if strings.HasPrefix(s, "bad trusted proxy ") {
		return fmt.Sprintf("可信代理 %s 无效，请填写 IP 或 CIDR（如 173.245.48.0/20）", strings.TrimPrefix(s, "bad trusted proxy "))
	}
	if strings.HasPrefix(s, "bad guard allow ") {
		return fmt.Sprintf("访问白名单条目 %s 无效，请填写 IP 或 CIDR（如 192.168.0.0/16）", strings.TrimPrefix(s, "bad guard allow "))
	}
	if strings.HasPrefix(s, "bad guard deny ") {
		return fmt.Sprintf("访问黑名单条目 %s 无效，请填写 IP 或 CIDR（如 203.0.113.0/24）", strings.TrimPrefix(s, "bad guard deny "))
	}
	if strings.HasPrefix(s, "bad backend ") {
		return fmt.Sprintf("额外后端 %s 无效，请填写 IP:端口（如 192.168.1.10:8080）", strings.TrimPrefix(s, "bad backend "))
	}
	if s == "too many backends" {
		return "额外后端过多（上限 32 个）"
	}
	if s == "bad proxy protocol" {
		return "Proxy Protocol 版本无效，仅支持关闭、v1 或 v2"
	}
	if s == "proxy protocol udp" {
		return "UDP 规则不支持 Proxy Protocol"
	}
	if s == "bad lb strategy" {
		return "负载均衡策略无效，仅支持轮询、随机或主备"
	}
	if s == "bad guard limit" {
		return "连接数 / 速率 / 带宽上限无效，请填写非负整数（留空或 0 表示不限制）"
	}
	if strings.HasPrefix(s, "bad ip allow ") {
		return fmt.Sprintf("IP 白名单条目 %s 无效，请填写 IP 或 CIDR（如 192.168.0.0/16）", strings.TrimPrefix(s, "bad ip allow "))
	}
	if strings.HasPrefix(s, "bad domain ") {
		return fmt.Sprintf("域名 %s 无效，请填写如 example.com 或 *.example.com 的域名", strings.TrimPrefix(s, "bad domain "))
	}
	if strings.HasPrefix(s, "http route conflicts with rule ") {
		return fmt.Sprintf("该端口上已有规则 #%s 使用了相同的域名（+ 路径前缀），或 HTTP/HTTPS 设置不一致", strings.TrimPrefix(s, "http route conflicts with rule "))
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
		online, _, _ := p.clientStatus(c)
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
		"CSRF":      csrfFrom(r),
		"APITokens": p.apiTokenRows(r.Context()),
		"Error":     friendlyMsg(r.URL.Query().Get("err")),
		"Notice":    friendlyMsg(r.URL.Query().Get("ok")),
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

// handleMetrics 以 Prometheus 文本格式导出规则级统计与客户端在线状态。
func (p *Panel) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ok := false
	if p.MetricsToken != "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") &&
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(p.MetricsToken)) == 1 {
			ok = true
		}
	}
	if !ok && !p.authed(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="opennofrp-metrics"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rules, err := p.Store.ListAllEnabledRules(r.Context())
	if err != nil {
		http.Error(w, "failed to list rules", http.StatusInternalServerError)
		return
	}
	labels := make(map[uint32]listener.RuleLabel, len(rules))
	for _, ru := range rules {
		labels[uint32(ru.ID)] = listener.RuleLabel{ClientID: ru.ClientID, Name: ru.Name, Protocol: ru.Protocol, Port: ru.RemotePort}
	}
	var stats []listener.RuleStats
	if p.RuleStats != nil {
		stats = p.RuleStats()
	}
	online := func(clientID string) bool {
		if p.ClientStatus == nil {
			return false
		}
		o, _, _ := p.ClientStatus(clientID)
		return o
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	listener.WritePrometheus(w, stats, labels, online)
}

// ---- 客户端页面 ----------------------------------------------------------

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
	online, clientVersion, caps := p.clientStatus(c)
	// 有 HTTP 规则且 Client 在线但不支持 dial_ack 时，在页面上提示升级。
	outdated := false
	if online && !protocol.HasCapability(caps, protocol.CapDialAck) {
		for _, ru := range rules {
			if ru.Protocol == "http" {
				outdated = true
				break
			}
		}
	}

	// ?edit=<ruleID> 时在页面中预填编辑表单。
	var editRule *store.Rule
	if eid, err := strconv.ParseInt(r.URL.Query().Get("edit"), 10, 64); err == nil && eid > 0 {
		if er, err := p.Store.GetRule(r.Context(), eid); err == nil && er.ClientID == c.ID {
			editRule = &er
		}
	}

	// 规则实时统计（活跃连接、流量、后端错误），按规则 ID 索引供模板使用。
	statsByRule := map[int64]listener.RuleStats{}
	if p.RuleStats != nil {
		for _, s := range p.RuleStats() {
			statsByRule[int64(s.RuleID)] = s
		}
	}

	p.tmpl.ExecuteTemplate(w, "client.html", map[string]any{
		"Stats": statsByRule,
		"Client": struct {
			ID, Name, LastSeen string
		}{ID: c.ID, Name: c.Name, LastSeen: lastSeen},
		"Online":        online,
		"ClientVersion": clientVersion,
		"Outdated":      outdated,
		"Rules":         rules,
		"EditRule":      editRule,
		"CSRF":          csrfFrom(r),
		"Error":         friendlyMsg(r.URL.Query().Get("err")),
		"Notice":        friendlyMsg(r.URL.Query().Get("ok")),
	})
}

var (
	validDomainRegex = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
	validPathRegex   = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)
)

// maxOfflinePageBytes 限制自定义“服务不可用”页面的大小。
const maxOfflinePageBytes = 64 * 1024

// parseRuleForm 从表单解析并校验一条规则（创建与编辑共用）。excludeID 为正在
// 编辑的规则 ID（创建时为 0）。返回的 errKey 非空时表示校验失败，可直接放入
// ?err= 参数，由 friendlyMsg 翻译。
func (p *Panel) parseRuleForm(r *http.Request, clientID string, excludeID int64) (store.Rule, string) {
	protocol := r.FormValue("protocol")
	if protocol != "tcp" && protocol != "udp" && protocol != "tcp+udp" && protocol != "http" && protocol != "tls" {
		return store.Rule{}, "bad protocol"
	}
	localPort, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("local_port")))
	remotePort, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("remote_port")))
	if localPort <= 0 || localPort > 65535 || remotePort <= 0 || remotePort > 65535 {
		return store.Rule{}, "bad port"
	}
	reserved, _ := p.Store.ReservedPorts(r.Context())
	if reason, isReserved := reserved[uint16(remotePort)]; isReserved {
		return store.Rule{}, fmt.Sprintf("remote_port %d is reserved (%s)", remotePort, reason)
	}
	localIP := strings.TrimSpace(r.FormValue("local_ip"))
	if localIP == "" {
		localIP = "127.0.0.1"
	}
	if net.ParseIP(localIP) == nil {
		return store.Rule{}, "bad local ip"
	}
	rule := store.Rule{
		ID: excludeID, ClientID: clientID, Name: strings.TrimSpace(r.FormValue("name")), Protocol: protocol,
		LocalIP: localIP, LocalPort: uint16(localPort), RemotePort: uint16(remotePort),
		PreserveSourceIP: r.FormValue("preserve_source_ip") == "1",
		Enabled:          r.FormValue("enabled") == "1",
	}
	if protocol == "http" {
		domains := store.SplitDomains(r.FormValue("domains"))
		for _, d := range domains {
			if len(d) > 253 || !validDomainRegex.MatchString(d) {
				return store.Rule{}, "bad domain " + d
			}
		}
		pathPrefix := store.NormalizePathPrefix(r.FormValue("path_prefix"))
		if !validPathRegex.MatchString(pathPrefix) {
			return store.Rule{}, "bad path prefix"
		}
		offlinePage := r.FormValue("offline_page")
		if len(offlinePage) > maxOfflinePageBytes {
			return store.Rule{}, "offline page too large"
		}
		rule.Domains = strings.Join(domains, ",")
		if pathPrefix != "/" {
			rule.PathPrefix = pathPrefix
		}
		rule.OfflinePage = offlinePage

		// 真实 IP 来源优先级：表单中按顺序提交多个 ip_sources 值（或单个逗号分隔值）。
		rawSources := strings.Join(r.Form["ip_sources"], ",")
		for _, s := range strings.FieldsFunc(rawSources, func(c rune) bool { return c == ',' || c == ' ' }) {
			known := false
			for _, k := range listener.KnownIPSources {
				if strings.EqualFold(s, k) {
					known = true
					break
				}
			}
			if !known {
				return store.Rule{}, "bad ip source " + s
			}
		}
		rule.IPSources = strings.Join(listener.ParseIPSources(rawSources), ",")

		trusted := strings.TrimSpace(r.FormValue("trusted_proxies"))
		if _, bad := listener.ParseTrustedProxies(trusted); len(bad) > 0 {
			return store.Rule{}, "bad trusted proxy " + bad[0]
		}
		rule.TrustedProxies = strings.Join(strings.FieldsFunc(trusted, func(c rune) bool {
			return c == ',' || c == ' ' || c == ';' || c == '\n' || c == '\r' || c == '\t'
		}), ",")

		// HTTPS：tls_mode = "" / "acme" / "custom"。
		tlsMode := strings.TrimSpace(r.FormValue("tls_mode"))
		switch tlsMode {
		case "":
		case "acme":
			hasExact := false
			for _, d := range domains {
				if !strings.HasPrefix(d, "*.") {
					hasExact = true
				}
			}
			if !hasExact {
				return store.Rule{}, "acme needs domain"
			}
		case "custom":
			certPEM := strings.TrimSpace(r.FormValue("tls_cert"))
			keyPEM := strings.TrimSpace(r.FormValue("tls_key"))
			if certPEM == "" && keyPEM == "" && excludeID > 0 {
				// 编辑时留空表示沿用已保存的证书。
				if old, err := p.Store.GetRule(r.Context(), excludeID); err == nil && old.TLSMode == "custom" {
					certPEM, keyPEM = old.TLSCert, old.TLSKey
				}
			}
			if certPEM == "" || keyPEM == "" {
				return store.Rule{}, "tls cert required"
			}
			if err := listener.ValidateCertPair(certPEM, keyPEM); err != nil {
				return store.Rule{}, "bad tls cert"
			}
			rule.TLSCert, rule.TLSKey = certPEM, keyPEM
		default:
			return store.Rule{}, "bad tls mode"
		}
		rule.TLSMode = tlsMode
		if tlsMode != "" && r.FormValue("redirect_https") == "1" {
			if len(domains) == 0 {
				return store.Rule{}, "redirect needs domain"
			}
			rule.RedirectHTTPS = "1"
		}

		// 路由选项：剥离前缀、Host 改写、自定义头、Basic Auth、IP 白名单、404 页面。
		if r.FormValue("strip_prefix") == "1" && rule.PathPrefix != "" {
			rule.StripPrefix = "1"
		}
		hostRewrite := strings.TrimSpace(r.FormValue("host_rewrite"))
		if hostRewrite != "" {
			h := hostRewrite
			if hh, port, err := net.SplitHostPort(hostRewrite); err == nil {
				if pn, err := strconv.Atoi(port); err != nil || pn <= 0 || pn > 65535 {
					return store.Rule{}, "bad host rewrite"
				}
				h = hh
			}
			if net.ParseIP(h) == nil && (len(h) > 253 || strings.HasPrefix(h, "*.") || !validDomainRegex.MatchString(strings.ToLower(h))) {
				return store.Rule{}, "bad host rewrite"
			}
		}
		rule.HostRewrite = hostRewrite
		reqHeaders := strings.TrimSpace(r.FormValue("req_headers"))
		if err := listener.ValidateHeaderOps(reqHeaders); err != nil {
			return store.Rule{}, "bad req headers"
		}
		rule.ReqHeaders = reqHeaders
		respHeaders := strings.TrimSpace(r.FormValue("resp_headers"))
		if err := listener.ValidateHeaderOps(respHeaders); err != nil {
			return store.Rule{}, "bad resp headers"
		}
		rule.RespHeaders = respHeaders

		// Basic Auth：每行 "user:password"；若密码部分已是 bcrypt 哈希（编辑时回显的
		// 已保存值）则原样保留，否则视为明文并哈希后保存。
		var authLines []string
		for _, line := range strings.Split(strings.ReplaceAll(r.FormValue("basic_auth"), "\r\n", "\n"), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			user, pass, ok := strings.Cut(line, ":")
			user = strings.TrimSpace(user)
			if !ok || user == "" || pass == "" || strings.ContainsAny(user, " \t") {
				return store.Rule{}, "bad basic auth"
			}
			if !(strings.HasPrefix(pass, "$2a$") || strings.HasPrefix(pass, "$2b$") || strings.HasPrefix(pass, "$2y$")) {
				h, err := listener.HashBasicAuthPassword(pass)
				if err != nil {
					return store.Rule{}, "bad basic auth"
				}
				pass = h
			}
			authLines = append(authLines, user+":"+pass)
		}
		basicAuth := strings.Join(authLines, "\n")
		if _, err := listener.ParseBasicAuth(basicAuth); err != nil {
			return store.Rule{}, "bad basic auth"
		}
		rule.BasicAuth = basicAuth

		ipAllow := strings.TrimSpace(r.FormValue("ip_allow"))
		if _, bad := listener.ParseTrustedProxies(ipAllow); len(bad) > 0 {
			return store.Rule{}, "bad ip allow " + bad[0]
		}
		rule.IPAllow = strings.Join(strings.FieldsFunc(ipAllow, func(c rune) bool {
			return c == ',' || c == ' ' || c == ';' || c == '\n' || c == '\r' || c == '\t'
		}), ",")

		notFoundPage := r.FormValue("not_found_page")
		if len(notFoundPage) > maxOfflinePageBytes {
			return store.Rule{}, "not found page too large"
		}
		rule.NotFoundPage = notFoundPage
	}
	if protocol == "tls" {
		// TLS 透传：只按 SNI 域名路由，不解密，证书由内网后端持有。
		domains := store.SplitDomains(r.FormValue("domains"))
		for _, d := range domains {
			if len(d) > 253 || !validDomainRegex.MatchString(d) {
				return store.Rule{}, "bad domain " + d
			}
		}
		rule.Domains = strings.Join(domains, ",")
	}
	// 规则级防护（所有协议通用）：黑白名单、单 IP 并发/速率上限、带宽上限。
	splitCIDRs := func(s string) string {
		return strings.Join(strings.FieldsFunc(s, func(c rune) bool {
			return c == ',' || c == ' ' || c == ';' || c == '\n' || c == '\r' || c == '\t'
		}), ",")
	}
	guardAllow := strings.TrimSpace(r.FormValue("guard_allow"))
	if _, bad := listener.ParseTrustedProxies(guardAllow); len(bad) > 0 {
		return store.Rule{}, "bad guard allow " + bad[0]
	}
	rule.GuardAllow = splitCIDRs(guardAllow)
	guardDeny := strings.TrimSpace(r.FormValue("guard_deny"))
	if _, bad := listener.ParseTrustedProxies(guardDeny); len(bad) > 0 {
		return store.Rule{}, "bad guard deny " + bad[0]
	}
	rule.GuardDeny = splitCIDRs(guardDeny)
	parseLimit := func(name string, max int) (int, bool) {
		v := strings.TrimSpace(r.FormValue(name))
		if v == "" {
			return 0, true
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > max {
			return 0, false
		}
		return n, true
	}
	var okLimit bool
	if rule.MaxConnsPerIP, okLimit = parseLimit("max_conns_per_ip", 1000000); !okLimit {
		return store.Rule{}, "bad guard limit"
	}
	if rule.ConnRatePerMin, okLimit = parseLimit("conn_rate_per_min", 1000000); !okLimit {
		return store.Rule{}, "bad guard limit"
	}
	if rule.BandwidthKBps, okLimit = parseLimit("bandwidth_kbps", 10000000); !okLimit {
		return store.Rule{}, "bad guard limit"
	}
	// 多后端负载均衡：额外后端 "ip:port"（每行或逗号分隔），主后端仍为本地 IP:端口。
	if protocol != "udp" {
		var backends []string
		for _, b := range strings.FieldsFunc(r.FormValue("backends"), func(c rune) bool {
			return c == ',' || c == ' ' || c == ';' || c == '\n' || c == '\r' || c == '\t'
		}) {
			h, port, err := net.SplitHostPort(b)
			pn, perr := strconv.Atoi(port)
			if err != nil || net.ParseIP(h) == nil || perr != nil || pn <= 0 || pn > 65535 {
				return store.Rule{}, "bad backend " + b
			}
			backends = append(backends, net.JoinHostPort(h, strconv.Itoa(pn)))
		}
		if len(backends) > 32 {
			return store.Rule{}, "too many backends"
		}
		rule.Backends = strings.Join(backends, ",")
		switch lb := strings.TrimSpace(r.FormValue("lb_strategy")); lb {
		case "", "round_robin", "random", "failover":
			if len(backends) > 0 {
				rule.LBStrategy = lb
			}
		default:
			return store.Rule{}, "bad lb strategy"
		}
	}
	// Proxy Protocol v1/v2：Client 拨通后端后先写入 PROXY 头（tcp/http/tls 规则）。
	switch pp := strings.TrimSpace(r.FormValue("proxy_protocol")); pp {
	case "", "0":
	case "1", "2":
		if protocol == "udp" {
			return store.Rule{}, "proxy protocol udp"
		}
		rule.ProxyProtocol, _ = strconv.Atoi(pp)
	default:
		return store.Rule{}, "bad proxy protocol"
	}
	conflict, err := p.Store.RuleConflict(r.Context(), rule)
	if err != nil {
		return store.Rule{}, err.Error()
	}
	if conflict != nil {
		if (protocol == "http" && conflict.Protocol == "http") || (protocol == "tls" && conflict.Protocol == "tls") {
			return store.Rule{}, fmt.Sprintf("http route conflicts with rule %d", conflict.ID)
		}
		return store.Rule{}, fmt.Sprintf("remote_port %d already used", remotePort)
	}
	return rule, ""
}

func (p *Panel) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	clientID := r.PathValue("id")
	if _, err := p.Store.GetClient(r.Context(), clientID); err != nil {
		http.NotFound(w, r)
		return
	}
	rule, errKey := p.parseRuleForm(r, clientID, 0)
	if errKey != "" {
		p.redirectErr(w, r, "/clients/"+clientID+"?err="+url.QueryEscape(errKey))
		return
	}
	if _, err := p.Store.CreateRule(r.Context(), rule); err != nil {
		p.redirectErr(w, r, "/clients/"+clientID+"?err="+url.QueryEscape(err.Error()))
		return
	}
	p.rulesChanged()
	http.Redirect(w, r, "/clients/"+clientID, http.StatusSeeOther)
}

// handleEditRule 覆盖一条现有规则的全部可变字段（ClientID 不可变）。
func (p *Panel) handleEditRule(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id64, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	existing, err := p.Store.GetRule(r.Context(), id64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	rule, errKey := p.parseRuleForm(r, existing.ClientID, id64)
	if errKey != "" {
		p.redirectErr(w, r, fmt.Sprintf("/clients/%s?edit=%d&err=%s", existing.ClientID, id64, url.QueryEscape(errKey)))
		return
	}
	if err := p.Store.UpdateRule(r.Context(), rule); err != nil {
		p.redirectErr(w, r, "/clients/"+existing.ClientID+"?err="+url.QueryEscape(err.Error()))
		return
	}
	p.rulesChanged()
	http.Redirect(w, r, "/clients/"+existing.ClientID+"?ok=rule+saved", http.StatusSeeOther)
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
	curPW := r.FormValue("current_password")
	newPW := r.FormValue("new_password")
	if len(newPW) < 6 {
		p.redirectErr(w, r, "/?err=password+too+short")
		return
	}

	// 严格校验原密码
	ok, err := p.Store.SetAdminPasswordWithOld(r.Context(), curPW, newPW)
	if err != nil || !ok {
		p.redirectErr(w, r, "/?err=invalid+current+password")
		return
	}

	// 密码修改成功，轮换并注销所有已有登录 Session（踢出潜在被盗用的其他会话）
	if err := p.Store.DeleteAllPanelSessions(r.Context()); err != nil {
		p.Logger.Warn("panel: delete all sessions failed", "error", err)
	}

	// 为当前改密操作重新发放新 Session Cookie
	p.setSessionCookie(w, r)
	http.Redirect(w, r, "/?ok=password+changed", http.StatusSeeOther)
}

var (
	validHostRegex        = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	validFingerprintRegex = regexp.MustCompile(`^SHA256(:[0-9A-F]{2}){32}$`)
	validTokenRegex       = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

func escapeShellSingleQuote(s string) string {
	// 使用单引号包裹，并将内部的单引号替换为 '\''
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (p *Panel) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" || len(token) > 64 || !validTokenRegex.MatchString(token) {
		http.Error(w, "missing or invalid token format", http.StatusBadRequest)
		return
	}

	// 强校验 Token 有效性：必须在数据库中存在且未过期、未消费
	valid, err := p.Store.CheckRegisterTokenValid(r.Context(), token)
	if err != nil || !valid {
		http.Error(w, "invalid or expired registration token", http.StatusForbidden)
		return
	}

	// HIGH-1 修复：绝不信任外部 query 传入的 fingerprint 参数，强制使用服务端自身的有效指纹
	fp := strings.TrimSpace(p.Fingerprint)
	if !validFingerprintRegex.MatchString(fp) {
		fp = ""
	}

	base := p.baseURLOf(r)
	host := p.ControlHost
	if host == "" || host == "0.0.0.0" {
		host = sanitizeHost(r.Host)
	}

	w.Header().Set("Content-Type", "text/x-shellscript")
	fmt.Fprintf(w, clientInstallScriptTemplate,
		escapeShellSingleQuote(host),
		p.ControlPort,
		escapeShellSingleQuote(token),
		escapeShellSingleQuote(fp),
		escapeShellSingleQuote(base),
	)
}

func (p *Panel) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := path.Base(r.PathValue("name")) // 防止路径穿越
	http.ServeFile(w, r, p.ClientBinDir+"/"+name)
}

// ---- 辅助函数 -------------------------------------------------------------

// clientStatus 返回 Client 的在线状态、版本与能力。优先使用 Server 核心注入的实时
// 会话信息；未注入时回退为基于 LastSeen（2 分钟内）的判断。
func (p *Panel) clientStatus(c store.Client) (bool, string, []string) {
	if p.ClientStatus != nil {
		return p.ClientStatus(c.ID)
	}
	return !c.LastSeenAt.IsZero() && time.Since(c.LastSeenAt) < 2*time.Minute, "", nil
}

func (p *Panel) rulesChanged() {
	if p.OnRules != nil {
		p.OnRules()
	}
}

func (p *Panel) redirectErr(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func sanitizeHost(raw string) string {
	h := strings.TrimSpace(raw)
	if hostPart, _, err := net.SplitHostPort(h); err == nil {
		h = hostPart
	}
	if !validHostRegex.MatchString(h) {
		return "127.0.0.1" // 非法字符直接回退到安全的 127.0.0.1
	}
	return h
}

func (p *Panel) baseURLOf(r *http.Request) string {
	if p.BaseURL != "" {
		return p.BaseURL
	}
	// HIGH-2 修复：严格校验 Host 标头，拦截带特殊字符的恶意请求
	safeHost := sanitizeHost(r.Host)
	port := ""
	if _, portPart, err := net.SplitHostPort(r.Host); err == nil && portPart != "" {
		if pNum, err := strconv.Atoi(portPart); err == nil && pNum > 0 && pNum <= 65535 {
			port = ":" + strconv.Itoa(pNum)
		}
	}
	scheme := "http://"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https://"
	}
	return scheme + safeHost + port
}

const clientInstallScriptTemplate = `#!/bin/bash
# OpenNoFrp internal-client one-time install script, generated by the
# admin panel. The --token baked below is SINGLE-USE: after this machine
# completes its first registration it persists permanent credentials to
# /etc/opennofrp/client_credentials.toml and any later copy of this command
# will fail to re-register a second machine.
set -euo pipefail
SERVER_HOST=%s
SERVER_PORT=%d
TOKEN=%s
FINGERPRINT=%s
BASE_URL=%s

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

  REPO="YearnstudioHorizon/OpenNoFrp"
  MIRROR_PREFIX="https://mirror.yearnstudio.cn/"

  safe_curl_get() {
    local url="$1"
    local timeout="${2:-10}"
    curl -4 -s --connect-timeout 6 -m "$timeout" "$url" 2>/dev/null || curl -s --connect-timeout 6 -m "$timeout" "$url" 2>/dev/null
  }

  safe_curl_download() {
    local url="$1"
    local dest="$2"
    local timeout="${3:-120}"
    if curl -4 -fsSL --connect-timeout 15 -m "$timeout" --retry 2 --retry-delay 1 "$url" -o "$dest" 2>/dev/null; then
      return 0
    fi
    if curl -fsSL --connect-timeout 15 -m "$timeout" "$url" -o "$dest" 2>/dev/null; then
      return 0
    fi
    return 1
  }

  get_latest_tag() {
    local tag=""
    local loc
    loc=$(curl -4 -sI --connect-timeout 6 -m 8 "https://github.com/$REPO/releases/latest" 2>/dev/null | grep -i "^location:" | tr -d "\r\n" || true)
    if [ -z "$loc" ]; then
      loc=$(curl -sI --connect-timeout 6 -m 8 "https://github.com/$REPO/releases/latest" 2>/dev/null | grep -i "^location:" | tr -d "\r\n" || true)
    fi
    if [ -n "$loc" ]; then
      tag=$(echo "$loc" | awk -F"/tag/" '{print $2}' | tr -d " \r\n")
    fi
    if [ -z "$tag" ]; then
      tag=$(safe_curl_get "https://api.github.com/repos/$REPO/releases/latest" 8 | grep '"tag_name":' | head -n1 | cut -d'"' -f4 || true)
    fi
    if [ -z "$tag" ]; then
      tag=$(safe_curl_get "${MIRROR_PREFIX}https://api.github.com/repos/$REPO/releases/latest" 10 | grep '"tag_name":' | head -n1 | cut -d'"' -f4 || true)
    fi
    echo "$tag"
  }

  TAG="$(get_latest_tag)"
  ASSET_NAME="opennofrp-client-linux-$ARCH"

  if [ -n "$TAG" ]; then
    GH_URL="https://github.com/$REPO/releases/download/$TAG/$ASSET_NAME"
    MIRROR_URL="${MIRROR_PREFIX}${GH_URL}"

    # 2. 尝试从 GitHub 官方下载 (超时限制 8 秒)
    if safe_curl_download "$GH_URL" "$CLIENT_BIN" 120; then
      echo "[opennofrp] downloaded from GitHub Releases ($TAG)"
      return 0
    fi

    # 3. GitHub 直连超时或受限，自动切换至 mirror.yearnstudio.cn 镜像加速 (优先 IPv4 规避 Cloudflare IPv6 握手黑洞)
    echo "[opennofrp] GitHub direct download timed out, switching to mirror accelerator ($MIRROR_PREFIX)..."
    if safe_curl_download "$MIRROR_URL" "$CLIENT_BIN" 180; then
      echo "[opennofrp] downloaded via YearnStudio mirror accelerator ($TAG)"
      return 0
    fi
  else
    GH_LATEST="https://github.com/$REPO/releases/latest/download/$ASSET_NAME"
    if safe_curl_download "$GH_LATEST" "$CLIENT_BIN" 120; then
      echo "[opennofrp] downloaded from GitHub Releases"
      return 0
    fi
  fi

  echo "[opennofrp] ERROR: could not download client binary from server, GitHub, or mirror!" >&2
  exit 1
}

download_client
chmod +x "$CLIENT_BIN"

# 完整性安全校验：防止网络中间人劫持/篡改或返回 HTML 错误页面
if [ ! -s "$CLIENT_BIN" ]; then
  echo "[opennofrp] ERROR: downloaded client binary is empty!" >&2
  exit 1
fi
MAGIC=$(head -c 4 "$CLIENT_BIN" 2>/dev/null || true)
if [ "$MAGIC" != $'\x7fELF' ]; then
  echo "[opennofrp] ERROR: downloaded client file is not a valid Linux ELF executable! (possible network tampering)" >&2
  exit 1
fi

mkdir -p /opt/opennofrp /etc/opennofrp /var/lib/opennofrp
if systemctl is-active --quiet opennofrp-client 2>/dev/null; then
  echo "[opennofrp] stopping running client service before upgrade..."
  systemctl stop opennofrp-client || true
fi
install -m 0755 "$CLIENT_BIN" /opt/opennofrp/opennofrp-client

if [ -n "$TOKEN" ]; then
  echo "[opennofrp] applying new registration token and updating client configuration..."
  rm -f /etc/opennofrp/client_credentials.toml
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
elif [ ! -f /etc/opennofrp/client.toml ]; then
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
else
  echo "[opennofrp] existing /etc/opennofrp/client.toml kept (config preserved)"
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
