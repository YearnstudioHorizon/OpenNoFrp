package panel

// REST API（/api/v1/*）：以 "Authorization: Bearer <token>" 调用，令牌在面板中创建
// 与吊销。只读令牌只能调用 GET。规则的创建/修改复用面板表单的 parseRuleForm 校验
// 逻辑：JSON 请求体中的字段名与表单字段名一致（布尔值 true 等价于表单的 "1"）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"opennofrp/server/internal/listener"
	"opennofrp/server/internal/store"
)

// apiTokenPrefix 是明文 API 令牌的固定前缀，便于在日志/密钥扫描中识别。
const apiTokenPrefix = "onfr_"

type apiTokenCtxKey struct{}

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, key string) {
	apiJSON(w, status, map[string]any{"ok": false, "error": key, "message": friendlyMsg(key)})
}

// apiAuth 校验 Bearer API 令牌；只读令牌拒绝非 GET 请求。
func (p *Panel) apiAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="opennofrp-api"`)
			apiError(w, http.StatusUnauthorized, "missing api token")
			return
		}
		tok := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		t, ok, err := p.Store.LookupAPIToken(r.Context(), hashSessionToken(tok))
		if err != nil {
			apiError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="opennofrp-api", error="invalid_token"`)
			apiError(w, http.StatusUnauthorized, "invalid api token")
			return
		}
		if t.ReadOnly && r.Method != http.MethodGet {
			apiError(w, http.StatusForbidden, "read-only api token")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), apiTokenCtxKey{}, t)))
	}
}

// registerAPI 注册 /api/v1/* 路由。
func (p *Panel) registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/clients", p.apiAuth(p.apiListClients))
	mux.HandleFunc("GET /api/v1/clients/{id}", p.apiAuth(p.apiGetClient))
	mux.HandleFunc("DELETE /api/v1/clients/{id}", p.apiAuth(p.apiDeleteClient))
	mux.HandleFunc("GET /api/v1/clients/{id}/rules", p.apiAuth(p.apiListRules))
	mux.HandleFunc("POST /api/v1/clients/{id}/rules", p.apiAuth(p.apiCreateRule))
	mux.HandleFunc("GET /api/v1/rules/{id}", p.apiAuth(p.apiGetRule))
	mux.HandleFunc("PUT /api/v1/rules/{id}", p.apiAuth(p.apiUpdateRule))
	mux.HandleFunc("POST /api/v1/rules/{id}/enable", p.apiAuth(p.apiSetEnabled(true)))
	mux.HandleFunc("POST /api/v1/rules/{id}/disable", p.apiAuth(p.apiSetEnabled(false)))
	mux.HandleFunc("DELETE /api/v1/rules/{id}", p.apiAuth(p.apiDeleteRule))
	mux.HandleFunc("GET /api/v1/stats", p.apiAuth(p.apiStats))
}

// ---- 资源表示 -------------------------------------------------------------

type apiClient struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Online       bool     `json:"online"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	LastSeenAt   int64    `json:"last_seen_at"`
	RuleCount    int      `json:"rule_count"`
}

type apiRule struct {
	ID               int64    `json:"id"`
	ClientID         string   `json:"client_id"`
	Name             string   `json:"name"`
	Protocol         string   `json:"protocol"`
	LocalIP          string   `json:"local_ip"`
	LocalPort        uint16   `json:"local_port"`
	RemotePort       uint16   `json:"remote_port"`
	PreserveSourceIP bool     `json:"preserve_source_ip"`
	Enabled          bool     `json:"enabled"`
	Domains          string   `json:"domains,omitempty"`
	PathPrefix       string   `json:"path_prefix,omitempty"`
	IPSources        string   `json:"ip_sources,omitempty"`
	TrustedProxies   string   `json:"trusted_proxies,omitempty"`
	TLSMode          string   `json:"tls_mode,omitempty"`
	RedirectHTTPS    bool     `json:"redirect_https,omitempty"`
	StripPrefix      bool     `json:"strip_prefix,omitempty"`
	HostRewrite      string   `json:"host_rewrite,omitempty"`
	ReqHeaders       string   `json:"req_headers,omitempty"`
	RespHeaders      string   `json:"resp_headers,omitempty"`
	BasicAuthUsers   []string `json:"basic_auth_users,omitempty"`
	IPAllow          string   `json:"ip_allow,omitempty"`
	GuardAllow       string   `json:"guard_allow,omitempty"`
	GuardDeny        string   `json:"guard_deny,omitempty"`
	MaxConnsPerIP    int      `json:"max_conns_per_ip,omitempty"`
	ConnRatePerMin   int      `json:"conn_rate_per_min,omitempty"`
	BandwidthKBps    int      `json:"bandwidth_kbps,omitempty"`
	Backends         string   `json:"backends,omitempty"`
	LBStrategy       string   `json:"lb_strategy,omitempty"`
	HasOfflinePage   bool     `json:"has_offline_page,omitempty"`
	HasNotFoundPage  bool     `json:"has_not_found_page,omitempty"`
}

// toAPIRule 转换规则表示；不输出私钥、密码哈希与大段 HTML。
func toAPIRule(r store.Rule) apiRule {
	var users []string
	for _, line := range strings.Split(r.BasicAuth, "\n") {
		if u, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && u != "" {
			users = append(users, u)
		}
	}
	return apiRule{
		ID: r.ID, ClientID: r.ClientID, Name: r.Name, Protocol: r.Protocol,
		LocalIP: r.LocalIP, LocalPort: r.LocalPort, RemotePort: r.RemotePort,
		PreserveSourceIP: r.PreserveSourceIP, Enabled: r.Enabled,
		Domains: r.Domains, PathPrefix: r.PathPrefix, IPSources: r.IPSources, TrustedProxies: r.TrustedProxies,
		TLSMode: r.TLSMode, RedirectHTTPS: r.RedirectHTTPS == "1", StripPrefix: r.StripPrefix == "1",
		HostRewrite: r.HostRewrite, ReqHeaders: r.ReqHeaders, RespHeaders: r.RespHeaders, BasicAuthUsers: users,
		IPAllow: r.IPAllow, GuardAllow: r.GuardAllow, GuardDeny: r.GuardDeny,
		MaxConnsPerIP: r.MaxConnsPerIP, ConnRatePerMin: r.ConnRatePerMin, BandwidthKBps: r.BandwidthKBps,
		Backends: r.Backends, LBStrategy: r.LBStrategy,
		HasOfflinePage: strings.TrimSpace(r.OfflinePage) != "", HasNotFoundPage: strings.TrimSpace(r.NotFoundPage) != "",
	}
}

// ---- 处理函数 -------------------------------------------------------------

func (p *Panel) apiListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := p.Store.ListClients(r.Context())
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]apiClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, p.apiClientOf(r.Context(), c))
	}
	apiJSON(w, http.StatusOK, map[string]any{"ok": true, "clients": out})
}

func (p *Panel) apiClientOf(ctx context.Context, c store.Client) apiClient {
	online, ver, caps := p.clientStatus(c)
	rules, _ := p.Store.ListRulesForClient(ctx, c.ID)
	ac := apiClient{ID: c.ID, Name: c.Name, Online: online, Version: ver, Capabilities: caps, RuleCount: len(rules)}
	if !c.LastSeenAt.IsZero() {
		ac.LastSeenAt = c.LastSeenAt.Unix()
	}
	return ac
}

func (p *Panel) apiGetClient(w http.ResponseWriter, r *http.Request) {
	c, err := p.Store.GetClient(r.Context(), r.PathValue("id"))
	if err != nil {
		apiError(w, http.StatusNotFound, "client not found")
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{"ok": true, "client": p.apiClientOf(r.Context(), c)})
}

func (p *Panel) apiDeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := p.Store.GetClient(r.Context(), id); err != nil {
		apiError(w, http.StatusNotFound, "client not found")
		return
	}
	if err := p.Store.DeleteClient(r.Context(), id); err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	p.rulesChanged()
	apiJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) apiListRules(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := p.Store.GetClient(r.Context(), id); err != nil {
		apiError(w, http.StatusNotFound, "client not found")
		return
	}
	rules, err := p.Store.ListRulesForClient(r.Context(), id)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]apiRule, 0, len(rules))
	for _, ru := range rules {
		out = append(out, toAPIRule(ru))
	}
	apiJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": out})
}

// loadRuleForm 把 JSON（或表单）请求体转换为 r.Form，供 parseRuleForm 复用。
func loadRuleForm(r *http.Request) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return r.ParseForm()
	}
	var body map[string]any
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		return err
	}
	vals := url.Values{}
	var add func(k string, v any)
	add = func(k string, v any) {
		switch x := v.(type) {
		case nil:
		case bool:
			if x {
				vals.Add(k, "1")
			}
		case string:
			vals.Add(k, x)
		case json.Number:
			vals.Add(k, x.String())
		case []any:
			for _, e := range x {
				add(k, e)
			}
		default:
			vals.Add(k, fmt.Sprint(x))
		}
	}
	for k, v := range body {
		add(k, v)
	}
	r.Form = vals
	r.PostForm = vals
	return nil
}

func (p *Panel) apiCreateRule(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("id")
	if _, err := p.Store.GetClient(r.Context(), clientID); err != nil {
		apiError(w, http.StatusNotFound, "client not found")
		return
	}
	if err := loadRuleForm(r); err != nil {
		apiError(w, http.StatusBadRequest, "bad request body")
		return
	}
	rule, errKey := p.parseRuleForm(r, clientID, 0)
	if errKey != "" {
		apiError(w, http.StatusUnprocessableEntity, errKey)
		return
	}
	id, err := p.Store.CreateRule(r.Context(), rule)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	p.rulesChanged()
	created, err := p.Store.GetRule(r.Context(), id)
	if err != nil {
		apiJSON(w, http.StatusCreated, map[string]any{"ok": true, "id": id})
		return
	}
	apiJSON(w, http.StatusCreated, map[string]any{"ok": true, "rule": toAPIRule(created)})
}

func (p *Panel) apiRuleByPath(w http.ResponseWriter, r *http.Request) (store.Rule, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		apiError(w, http.StatusNotFound, "rule not found")
		return store.Rule{}, false
	}
	ru, err := p.Store.GetRule(r.Context(), id)
	if err != nil {
		apiError(w, http.StatusNotFound, "rule not found")
		return store.Rule{}, false
	}
	return ru, true
}

func (p *Panel) apiGetRule(w http.ResponseWriter, r *http.Request) {
	ru, ok := p.apiRuleByPath(w, r)
	if !ok {
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": toAPIRule(ru)})
}

// apiUpdateRule 以请求体整体覆盖规则的可变字段（与面板编辑表单语义相同）。
// 自定义证书留空时沿用已保存的证书；offline_page / not_found_page / basic_auth
// 未提供时沿用原值。
func (p *Panel) apiUpdateRule(w http.ResponseWriter, r *http.Request) {
	existing, ok := p.apiRuleByPath(w, r)
	if !ok {
		return
	}
	if err := loadRuleForm(r); err != nil {
		apiError(w, http.StatusBadRequest, "bad request body")
		return
	}
	for key, old := range map[string]string{"offline_page": existing.OfflinePage, "not_found_page": existing.NotFoundPage, "basic_auth": existing.BasicAuth} {
		if _, given := r.Form[key]; !given && old != "" {
			r.Form.Set(key, old)
		}
	}
	rule, errKey := p.parseRuleForm(r, existing.ClientID, existing.ID)
	if errKey != "" {
		apiError(w, http.StatusUnprocessableEntity, errKey)
		return
	}
	if err := p.Store.UpdateRule(r.Context(), rule); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	p.rulesChanged()
	updated, _ := p.Store.GetRule(r.Context(), existing.ID)
	apiJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": toAPIRule(updated)})
}

func (p *Panel) apiSetEnabled(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ru, ok := p.apiRuleByPath(w, r)
		if !ok {
			return
		}
		if err := p.Store.SetRuleEnabled(r.Context(), ru.ID, enabled); err != nil {
			apiError(w, http.StatusInternalServerError, err.Error())
			return
		}
		p.rulesChanged()
		apiJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": enabled})
	}
}

func (p *Panel) apiDeleteRule(w http.ResponseWriter, r *http.Request) {
	ru, ok := p.apiRuleByPath(w, r)
	if !ok {
		return
	}
	if err := p.Store.DeleteRule(r.Context(), ru.ID); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	p.rulesChanged()
	apiJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) apiStats(w http.ResponseWriter, r *http.Request) {
	var stats []listener.RuleStats
	if p.RuleStats != nil {
		stats = p.RuleStats()
	}
	type row struct {
		RuleID        uint32 `json:"rule_id"`
		ActiveConns   int64  `json:"active_connections"`
		TotalConns    uint64 `json:"connections_total"`
		Rejected      uint64 `json:"rejected_total"`
		BytesIn       uint64 `json:"bytes_in"`
		BytesOut      uint64 `json:"bytes_out"`
		BackendErrors uint64 `json:"backend_errors"`
		LastError     string `json:"last_error,omitempty"`
		LastErrorAt   int64  `json:"last_error_at,omitempty"`
		LastActive    int64  `json:"last_active_at,omitempty"`
	}
	out := make([]row, 0, len(stats))
	for _, s := range stats {
		rw := row{RuleID: s.RuleID, ActiveConns: s.ActiveConns, TotalConns: s.TotalConns, Rejected: s.Rejected,
			BytesIn: s.BytesIn, BytesOut: s.BytesOut, BackendErrors: s.BackendErrors, LastError: s.LastError}
		if !s.LastErrorAt.IsZero() {
			rw.LastErrorAt = s.LastErrorAt.Unix()
		}
		if !s.LastActive.IsZero() {
			rw.LastActive = s.LastActive.Unix()
		}
		out = append(out, rw)
	}
	apiJSON(w, http.StatusOK, map[string]any{"ok": true, "stats": out})
}

// ---- 面板内的 API 令牌管理 ------------------------------------------------

// handleCreateAPIToken 生成一个新的 API 令牌，明文只在本次响应页面中显示一次。
func (p *Panel) handleCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if len(name) > 64 {
		name = name[:64]
	}
	tok := apiTokenPrefix + randomHex(24)
	if _, err := p.Store.CreateAPIToken(r.Context(), name, hashSessionToken(tok), tok[:len(apiTokenPrefix)+6], r.FormValue("read_only") == "1"); err != nil {
		p.redirectErr(w, r, "/?err="+url.QueryEscape(err.Error())+"#api-tokens")
		return
	}
	data := p.indexData(r)
	data["NewAPIToken"] = tok
	p.tmpl.ExecuteTemplate(w, "index.html", data)
}

func (p *Panel) handleDeleteAPIToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := p.Store.DeleteAPIToken(r.Context(), id); err != nil {
		p.redirectErr(w, r, "/?err="+url.QueryEscape(err.Error())+"#api-tokens")
		return
	}
	http.Redirect(w, r, "/?ok=api+token+revoked#api-tokens", http.StatusSeeOther)
}

// apiTokenRow 是面板中展示的一行 API 令牌信息。
type apiTokenRow struct {
	ID       int64
	Name     string
	Prefix   string
	ReadOnly bool
	Created  string
	LastUsed string
}

func (p *Panel) apiTokenRows(ctx context.Context) []apiTokenRow {
	toks, err := p.Store.ListAPITokens(ctx)
	if err != nil {
		return nil
	}
	out := make([]apiTokenRow, 0, len(toks))
	for _, t := range toks {
		last := "从未使用"
		if !t.LastUsedAt.IsZero() {
			last = t.LastUsedAt.Format("2006-01-02 15:04")
		}
		out = append(out, apiTokenRow{ID: t.ID, Name: t.Name, Prefix: t.Prefix, ReadOnly: t.ReadOnly,
			Created: t.CreatedAt.Format("2006-01-02 15:04"), LastUsed: last})
	}
	return out
}
