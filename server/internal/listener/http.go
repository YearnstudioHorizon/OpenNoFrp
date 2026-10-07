package listener

// HTTP 虚拟主机监听器：同一公网端口上可以挂载多条 protocol = "http" 的规则，
// Server 解析每个 HTTP 请求的 Host 与路径，按 (域名, 路径前缀) 路由到对应规则，
// 再通过 Client 会话的 yamux 流反向代理到内网服务。
//
//   - WebSocket：httputil.ReverseProxy 原生支持 Upgrade（101 Switching Protocols
//     之后退化为双向字节中继）。
//   - SSE / 流式响应：FlushInterval = -1，每次写入立即刷新，不做缓冲。
//   - 服务不可用：Client 离线，或 Client 拨号本地服务失败（通过 FlagDialAck
//     确认字节得知）时，返回规则自定义的 HTML 页面（未配置则使用内置页面）。
//
// 本文件依旧只使用用户态 socket，不触碰 iptables/路由，符合
// docs/01-architecture.md 中“云服务器保持纯用户态”的原则。

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"opennofrp/pkg/protocol"
	"opennofrp/server/internal/session"
)

// httpDialAckTimeout 是等待 Client 回写拨号确认的最长时间。
const httpDialAckTimeout = 10 * time.Second

// httpRoute 是某个 HTTP 端口上的一条路由（对应一条 http 规则）。
type httpRoute struct {
	RuleID      uint32
	ClientID    string
	Name        string
	Domains     []string // 已规范化；为空表示匹配任意 Host
	PathPrefix  string   // 已规范化，以 "/" 开头
	OfflinePage string
	// IPSources 是按优先级排列的真实客户端 IP 来源（见 realip.go）。
	IPSources []string
	// TrustedProxies 非空时，仅当 TCP 对端属于其中之一才信任请求头中的 IP。
	TrustedProxies []*net.IPNet
	// TLS 相关（见 tls.go）。
	TLSMode       string
	TLSCert       string
	TLSKey        string
	RedirectHTTPS bool
	HTTPSPort     uint16 // 该规则所在的 HTTPS 端口，供 80 端口跳转使用
	// 路由选项（见 httpopts.go）。
	StripPrefix  bool
	HostRewrite  string
	ReqHeaders   []headerOp
	RespHeaders  []headerOp
	BasicAuth    map[string]string // user -> bcrypt 哈希；为空表示不启用
	IPAllow      []*net.IPNet
	NotFoundPage string

	// cert 是 custom 模式下已解析的证书（解析失败或非 custom 模式为 nil）。
	cert *tls.Certificate
}

type httpListener struct {
	port   uint16
	ln     net.Listener
	srv    *http.Server
	tls    bool // 该端口是否终止 TLS（HTTPS）
	mu     sync.RWMutex
	routes []httpRoute
}

// routesWantTLS 报告一组路由是否要求该端口以 HTTPS 方式监听。
func routesWantTLS(routes []httpRoute) bool {
	for _, r := range routes {
		if r.TLSMode != "" {
			return true
		}
	}
	return false
}

func (hl *httpListener) setRoutes(routes []httpRoute) {
	sorted := append([]httpRoute(nil), routes...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].RuleID < sorted[j].RuleID })
	hl.mu.Lock()
	hl.routes = sorted
	hl.mu.Unlock()
}

func (hl *httpListener) ruleIDs() []uint32 {
	hl.mu.RLock()
	defer hl.mu.RUnlock()
	out := make([]uint32, 0, len(hl.routes))
	for _, r := range hl.routes {
		out = append(out, r.RuleID)
	}
	return out
}

// hostMatchScore 返回 host 与 domains 的匹配程度：0 = 不匹配，1 = 兜底（domains 为空），
// 2 = 通配匹配，3 = 精确匹配。
func hostMatchScore(host string, domains []string) int {
	if len(domains) == 0 {
		return 1
	}
	best := 0
	for _, d := range domains {
		if d == host {
			return 3
		}
		if strings.HasPrefix(d, "*.") {
			suffix := d[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				best = 2
			}
		}
	}
	return best
}

func pathMatches(path, prefix string) bool {
	if prefix == "/" || prefix == "" {
		return true
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// normalizeRequestHost 去掉端口、末尾点并转小写。
func normalizeRequestHost(h string) string {
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// matchRoute 选出最匹配的路由：先比较 Host 匹配程度（精确 > 通配 > 兜底），
// 再比较路径前缀长度（越长越优先）。
func matchRoute(routes []httpRoute, host, path string) (httpRoute, bool) {
	host = normalizeRequestHost(host)
	if path == "" {
		path = "/"
	}
	var best httpRoute
	bestHost, bestLen, found := 0, -1, false
	for _, r := range routes {
		hs := hostMatchScore(host, r.Domains)
		if hs == 0 || !pathMatches(path, r.PathPrefix) {
			continue
		}
		if hs > bestHost || (hs == bestHost && len(r.PathPrefix) > bestLen) {
			best, bestHost, bestLen, found = r, hs, len(r.PathPrefix), true
		}
	}
	return best, found
}

type ctxKey int

const (
	ctxKeyRoute ctxKey = iota
	ctxKeySession
	ctxKeyRemote
	ctxKeyRealIP
)

func (m *Manager) newHTTPHandler(hl *httpListener) http.Handler {
	transport := &http.Transport{
		// 每个请求使用独立的 yamux 流：Client 侧需要按访问者的源地址拨号（保留
		// 源 IP），连接池复用会把不同访问者/不同规则的请求混在同一条后端连接上。
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 0,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			route, _ := ctx.Value(ctxKeyRoute).(httpRoute)
			sess, _ := ctx.Value(ctxKeySession).(*session.Session)
			remote, _ := ctx.Value(ctxKeyRemote).(*net.TCPAddr)
			if sess == nil {
				return nil, session.ErrBackendUnavailable
			}
			var ip net.IP
			var port uint16
			if remote != nil {
				ip, port = remote.IP, uint16(remote.Port)
			}
			c, err := sess.OpenHTTPStream(ip, port, route.RuleID, httpDialAckTimeout)
			if err != nil {
				return nil, err
			}
			return m.guardFor(route.RuleID).wrapConn(m.countConn(route.RuleID, c, true)), nil
		},
	}

	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1, // SSE / 流式响应立即刷新
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			if pr.Out.URL.Host == "" {
				pr.Out.URL.Host = "backend"
			}
			pr.Out.Host = pr.In.Host // 保留原始 Host，后端可据此做虚拟主机
			route, _ := pr.In.Context().Value(ctxKeyRoute).(httpRoute)
			realIP, _ := pr.In.Context().Value(ctxKeyRealIP).(net.IP)
			// 按规则配置的 IP 来源优先级改写 X-Real-IP / X-Forwarded-* / Forwarded 等头
			rewriteForwardHeaders(pr.In, pr.Out.Header, route, realIP)
			if route.StripPrefix {
				stripPathPrefix(pr.Out.URL, route.PathPrefix)
			}
			if route.HostRewrite != "" {
				pr.Out.Host = route.HostRewrite
			}
			if len(route.BasicAuth) > 0 {
				// 凭据仅用于隧道入口鉴权，不泄露给后端。
				pr.Out.Header.Del("Authorization")
			}
			applyHeaderOps(pr.Out.Header, route.ReqHeaders)
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.Request != nil {
				route, _ := resp.Request.Context().Value(ctxKeyRoute).(httpRoute)
				applyHeaderOps(resp.Header, route.RespHeaders)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			route, _ := r.Context().Value(ctxKeyRoute).(httpRoute)
			if errors.Is(err, context.Canceled) {
				return // 访问者主动断开
			}
			m.Logger.Warn("http backend unavailable", "rule_id", route.RuleID, "host", r.Host, "path", r.URL.Path, "error", err)
			m.statBackendError(route.RuleID, err.Error())
			serveUnavailable(w, route)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			// 明文端口：先应答 ACME HTTP-01 挑战，再处理 HTTPS 强制跳转。
			if m.serveACMEChallenge(w, r) {
				return
			}
			if httpsPort, ok := m.redirectTarget(r.Host); ok {
				serveRedirect(w, r, httpsPort)
				return
			}
		}
		hl.mu.RLock()
		route, ok := matchRoute(hl.routes, r.Host, r.URL.Path)
		notFoundPage := ""
		if !ok {
			notFoundPage = portNotFoundPage(hl.routes)
		}
		hl.mu.RUnlock()
		if !ok {
			serveNotFound(w, r.Host, notFoundPage)
			return
		}
		// 按规则配置的优先级提取真实客户端 IP；该 IP 用于白名单判断、写入转发
		// 请求头，并写入 StreamMetadata，使 Client 以真实 IP 为源地址伪装拨号后端。
		realIP, _ := extractClientIP(r, route)
		if !ipAllowed(realIP, route.IPAllow) {
			m.Logger.Info("http request rejected by ip allowlist", "rule_id", route.RuleID, "ip", realIP)
			serveForbidden(w)
			return
		}
		// 规则级防护：黑白名单、单 IP 并发请求数与请求速率（见 protect.go）。
		release, reason := m.guardFor(route.RuleID).admit(realIP)
		switch reason {
		case guardOK:
			defer release()
			defer m.statOpened(route.RuleID)()
		case guardDenied:
			m.statRejected(route.RuleID)
			m.Logger.Info("http request rejected by rule protection", "rule_id", route.RuleID, "ip", realIP, "reason", reason)
			serveForbidden(w)
			return
		default:
			m.Logger.Info("http request rejected by rule protection", "rule_id", route.RuleID, "ip", realIP, "reason", reason)
			m.statRejected(route.RuleID)
			w.Header().Set("Retry-After", "5")
			http.Error(w, "429 too many requests", http.StatusTooManyRequests)
			return
		}
		if !checkBasicAuth(r, route.BasicAuth) {
			serveAuthRequired(w, route)
			return
		}
		sess := m.Lookup(route.ClientID)
		if sess == nil {
			m.Logger.Warn("http request for offline client", "rule_id", route.RuleID, "host", r.Host)
			m.statBackendError(route.RuleID, "client offline")
			serveUnavailable(w, route)
			return
		}
		if !sess.HasCapability(protocol.CapDialAck) {
			// 旧版 Client 不会回写拨号确认，等待只会超时；直接返回不可用页面。
			m.Logger.Warn("http request for outdated client without dial_ack, upgrade the client",
				"rule_id", route.RuleID, "client_id", route.ClientID, "client_version", sess.ClientVersion)
			serveUnavailable(w, route)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyRoute, route)
		ctx = context.WithValue(ctx, ctxKeySession, sess)
		ctx = context.WithValue(ctx, ctxKeyRealIP, realIP)
		if ap, err := net.ResolveTCPAddr("tcp", r.RemoteAddr); err == nil {
			remote := &net.TCPAddr{IP: ap.IP, Port: ap.Port}
			if realIP != nil && !realIP.Equal(ap.IP) {
				remote.IP = realIP
			}
			ctx = context.WithValue(ctx, ctxKeyRemote, remote)
		} else if realIP != nil {
			ctx = context.WithValue(ctx, ctxKeyRemote, &net.TCPAddr{IP: realIP})
		}
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}

func clientIPOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var defaultUnavailableTmpl = template.Must(template.New("unavailable").Parse(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>服务暂时不可用</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0e16;color:#e7edf9;font:15px/1.6 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.box{max-width:460px;padding:32px;text-align:center}h1{font-size:22px;margin:0 0 8px}p{color:#9aa7bf;margin:0}.code{font-family:ui-monospace,Consolas,monospace;color:#38c8ff;font-size:44px;font-weight:700;margin-bottom:8px}</style>
</head><body><div class="box"><div class="code">503</div><h1>服务暂时不可用</h1>
<p>{{if .Name}}「{{.Name}}」{{else}}该服务{{end}}的源站当前离线或未启动，请稍后再试。</p></div></body></html>`))

func serveUnavailable(w http.ResponseWriter, route httpRoute) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Retry-After", "30")
	w.WriteHeader(http.StatusServiceUnavailable)
	if strings.TrimSpace(route.OfflinePage) != "" {
		fmt.Fprint(w, route.OfflinePage)
		return
	}
	_ = defaultUnavailableTmpl.Execute(w, route)
}

func serveNotFound(w http.ResponseWriter, host, page string) {
	if strings.TrimSpace(page) != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, page)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "404 no route for host %q\n", normalizeRequestHost(host))
}

// openHTTPPort 打开（或更新）某个端口上的 HTTP 监听器并设置其路由表。
func (m *Manager) openHTTPPort(port uint16, routes []httpRoute) error {
	wantTLS := routesWantTLS(routes)
	m.mu.Lock()
	if hl, ok := m.http[port]; ok {
		if hl.tls == wantTLS {
			m.mu.Unlock()
			hl.setRoutes(routes)
			return nil
		}
		// HTTP <-> HTTPS 切换：关闭旧监听器后以新模式重新打开。
		m.mu.Unlock()
		m.closeHTTPPort(port)
		m.mu.Lock()
	}
	if _, ok := m.tcp[port]; ok {
		m.mu.Unlock()
		return fmt.Errorf("listener: tcp port %d already open by a non-http rule", port)
	}
	addr := net.JoinHostPort(m.BindAddr, strconv.Itoa(int(port)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("listener: http listen on %s: %w", addr, err)
	}
	hl := &httpListener{port: port, tls: wantTLS}
	hl.setRoutes(routes)
	if wantTLS {
		ln = tls.NewListener(ln, m.tlsConfigFor(hl))
	}
	hl.ln = ln
	hl.srv = &http.Server{
		Handler:           m.newHTTPHandler(hl),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// 禁用 HTTP/2 自动协商（tls.Config.NextProtos 仅含 http/1.1），保证 WebSocket 可用。
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	m.http[port] = hl
	m.mu.Unlock()

	go func() {
		if err := hl.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.Logger.Error("http listener stopped", "port", port, "error", err)
		}
	}()
	m.Logger.Info("opened public HTTP listener", "port", port, "routes", len(routes))
	return nil
}

// closeHTTPPort 关闭某个端口上的 HTTP 监听器（包括其上已劫持的 WebSocket 连接
// 以外的所有连接）。
func (m *Manager) closeHTTPPort(port uint16) {
	m.mu.Lock()
	hl, ok := m.http[port]
	if ok {
		delete(m.http, port)
	}
	m.mu.Unlock()
	if ok {
		hl.srv.Close()
		m.Logger.Info("closed public HTTP listener", "port", port)
	}
}

// reconcileHTTP 使 HTTP 监听器集合与期望的 http 规则集合一致。
func (m *Manager) reconcileHTTP(desired []RuleView) {
	byPort := map[uint16][]httpRoute{}
	for _, r := range desired {
		if r.Protocol != "http" {
			continue
		}
		route := httpRoute{
			RuleID:         r.ID,
			ClientID:       r.ClientID,
			Name:           r.Name,
			Domains:        r.Domains,
			PathPrefix:     r.PathPrefix,
			OfflinePage:    r.OfflinePage,
			IPSources:      r.IPSources,
			TrustedProxies: r.TrustedProxies,
			TLSMode:        r.TLSMode,
			TLSCert:        r.TLSCert,
			TLSKey:         r.TLSKey,
			RedirectHTTPS:  r.RedirectHTTPS,
			HTTPSPort:      r.Port,
			StripPrefix:    r.StripPrefix,
			HostRewrite:    r.HostRewrite,
			IPAllow:        r.IPAllow,
			NotFoundPage:   r.NotFoundPage,
		}
		if ops, err := parseHeaderOps(r.ReqHeaders); err != nil {
			m.Logger.Warn("http rule has invalid request headers", "rule_id", r.ID, "error", err)
		} else {
			route.ReqHeaders = ops
		}
		if ops, err := parseHeaderOps(r.RespHeaders); err != nil {
			m.Logger.Warn("http rule has invalid response headers", "rule_id", r.ID, "error", err)
		} else {
			route.RespHeaders = ops
		}
		if r.BasicAuth != "" {
			accounts, err := ParseBasicAuth(r.BasicAuth)
			if err != nil || len(accounts) == 0 {
				// 鉴权配置损坏时宁可拒绝访问也不放行：放入一个无法匹配的账户。
				m.Logger.Warn("http rule has invalid basic auth, denying all requests", "rule_id", r.ID, "error", err)
				accounts = map[string]string{"\x00invalid": string(dummyBcrypt)}
			}
			route.BasicAuth = accounts
		}
		if r.TLSMode == "custom" {
			c, err := parseRouteCert(r.TLSCert, r.TLSKey)
			if err != nil {
				m.Logger.Warn("https rule has an invalid certificate", "rule_id", r.ID, "error", err)
			} else {
				route.cert = c
			}
		}
		byPort[r.Port] = append(byPort[r.Port], route)
	}
	// 有规则要求 HTTPS 跳转时，确保明文 80 端口上有 HTTP 监听器（即使没有
	// 规则直接挂在 80 上，它也会负责跳转与 ACME HTTP-01 挑战）。
	if m.updateTLSState(desired) {
		if _, ok := byPort[80]; !ok {
			byPort[80] = []httpRoute{}
		}
	}
	m.mu.Lock()
	var stale []uint16
	for port := range m.http {
		if _, ok := byPort[port]; !ok {
			stale = append(stale, port)
		}
	}
	m.mu.Unlock()
	for _, port := range stale {
		m.closeHTTPPort(port)
	}
	for port, routes := range byPort {
		if err := m.openHTTPPort(port, routes); err != nil {
			m.Logger.Warn("reconcile: could not open http port", "port", port, "error", err)
		}
	}
}
