package listener

// HTTPS 支持（仅 HTTP 规则）：
//   - 端口上任一 HTTP 规则设置了 TLSMode 时，该端口以 TLS 方式监听（终止 TLS 后
//     再按 Host/路径路由，与明文 HTTP 规则共用同一套反向代理逻辑）；
//   - TLSMode = "custom"：使用规则上传的 PEM 证书/私钥，按 SNI 选择；
//   - TLSMode = "acme"：通过 golang.org/x/crypto/acme/autocert 按规则绑定的
//     精确域名自动申请与续期证书（TLS-ALPN-01 在 HTTPS 端口上完成；若 80 端口
//     由本程序监听，也会应答 HTTP-01 挑战）。通配域名无法用 ACME 申请；
//   - RedirectHTTPS：在明文 80 端口上把匹配该规则域名的请求 301 跳转到 HTTPS。

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ACMEConfig 是 ACME 自动证书的全局设置（来自 server.toml）。
type ACMEConfig struct {
	Email        string
	CacheDir     string
	DirectoryURL string
	AcceptTOS    bool
}

type redirectEntry struct {
	Domains   []string
	HTTPSPort uint16
}

// tlsState 保存 Manager 中与 TLS 相关的共享状态。
type tlsState struct {
	mu        sync.RWMutex
	acme      *autocert.Manager
	acmeHosts map[string]bool
	redirects []redirectEntry
}

// SetACME 启用 ACME 自动证书。AcceptTOS 为 false 时不启用（acme 模式的规则将
// 无法获得证书，握手失败并记录日志）。
func (m *Manager) SetACME(cfg ACMEConfig) {
	if !cfg.AcceptTOS {
		m.Logger.Info("ACME disabled (server.acme_accept_tos is false); HTTPS rules in acme mode will not get certificates")
		return
	}
	mgr := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Email:  cfg.Email,
		HostPolicy: func(_ context.Context, host string) error {
			m.tlsst.mu.RLock()
			ok := m.tlsst.acmeHosts[strings.ToLower(host)]
			m.tlsst.mu.RUnlock()
			if !ok {
				return fmt.Errorf("acme: host %q is not bound to any enabled acme https rule", host)
			}
			return nil
		},
	}
	if cfg.CacheDir != "" {
		mgr.Cache = autocert.DirCache(cfg.CacheDir)
	}
	if cfg.DirectoryURL != "" {
		mgr.Client = &acme.Client{DirectoryURL: cfg.DirectoryURL}
	}
	m.tlsst.mu.Lock()
	m.tlsst.acme = mgr
	m.tlsst.mu.Unlock()
	m.Logger.Info("ACME automatic certificates enabled", "cache_dir", cfg.CacheDir, "directory", cfg.DirectoryURL)
}

func (m *Manager) acmeManager() *autocert.Manager {
	m.tlsst.mu.RLock()
	defer m.tlsst.mu.RUnlock()
	return m.tlsst.acme
}

// ACMEHosts 返回当前允许通过 ACME 申请证书的域名集合（供测试/面板展示）。
func (m *Manager) ACMEHosts() []string {
	m.tlsst.mu.RLock()
	defer m.tlsst.mu.RUnlock()
	out := make([]string, 0, len(m.tlsst.acmeHosts))
	for h := range m.tlsst.acmeHosts {
		out = append(out, h)
	}
	return out
}

// updateTLSState 根据期望的规则集刷新 ACME 允许域名与 HTTPS 跳转表。返回是否
// 存在需要在 80 端口上提供跳转的规则。
func (m *Manager) updateTLSState(desired []RuleView) bool {
	hosts := map[string]bool{}
	var reds []redirectEntry
	for _, r := range desired {
		if r.Protocol != "http" || r.TLSMode == "" {
			continue
		}
		if r.TLSMode == "acme" {
			for _, d := range r.Domains {
				if !strings.HasPrefix(d, "*.") {
					hosts[d] = true
				}
			}
		}
		if r.RedirectHTTPS && len(r.Domains) > 0 {
			reds = append(reds, redirectEntry{Domains: r.Domains, HTTPSPort: r.Port})
		}
	}
	m.tlsst.mu.Lock()
	m.tlsst.acmeHosts = hosts
	m.tlsst.redirects = reds
	m.tlsst.mu.Unlock()
	return len(reds) > 0
}

// parseRouteCert 解析 custom 模式规则的 PEM 证书与私钥。
func parseRouteCert(certPEM, keyPEM string) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ValidateCertPair 供面板校验上传的证书/私钥是否匹配且可解析。
func ValidateCertPair(certPEM, keyPEM string) error {
	_, err := parseRouteCert(certPEM, keyPEM)
	return err
}

func helloWantsACMEALPN(hello *tls.ClientHelloInfo) bool {
	for _, p := range hello.SupportedProtos {
		if p == acme.ALPNProto {
			return true
		}
	}
	return false
}

// tlsConfigFor 返回某个 HTTPS 端口使用的 tls.Config：按 SNI 找到最匹配的规则，
// custom 模式返回其上传的证书，acme 模式交给 autocert。只协商 http/1.1，保证
// WebSocket 升级可用。
func (m *Manager) tlsConfigFor(hl *httpListener) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1", acme.ALPNProto},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := normalizeRequestHost(hello.ServerName)
			hl.mu.RLock()
			routes := hl.routes
			hl.mu.RUnlock()

			var best *httpRoute
			bestScore := 0
			for i := range routes {
				r := &routes[i]
				if s := hostMatchScore(host, r.Domains); s > bestScore {
					best, bestScore = r, s
				}
			}

			if best != nil && best.TLSMode == "custom" && best.cert != nil && !helloWantsACMEALPN(hello) {
				return best.cert, nil
			}
			if mgr := m.acmeManager(); mgr != nil && host != "" && (best == nil || best.TLSMode == "acme" || helloWantsACMEALPN(hello)) {
				return mgr.GetCertificate(hello)
			}
			if best != nil && best.cert != nil {
				return best.cert, nil
			}
			// 最后兜底：该端口上任意一张已上传的证书（例如客户端未发送 SNI）。
			for i := range routes {
				if routes[i].cert != nil {
					return routes[i].cert, nil
				}
			}
			return nil, fmt.Errorf("tls: no certificate available for %q", host)
		},
	}
}

// redirectTarget 报告明文请求的 Host 是否属于某条开启了 HTTPS 跳转的规则。
func (m *Manager) redirectTarget(host string) (uint16, bool) {
	h := normalizeRequestHost(host)
	m.tlsst.mu.RLock()
	defer m.tlsst.mu.RUnlock()
	for _, e := range m.tlsst.redirects {
		if hostMatchScore(h, e.Domains) >= 2 {
			return e.HTTPSPort, true
		}
	}
	return 0, false
}

// serveRedirect 301 跳转到同一 Host 的 HTTPS 地址。Host 已与规则域名匹配过，
// 不存在 Host 头注入风险。
func serveRedirect(w http.ResponseWriter, r *http.Request, httpsPort uint16) {
	host := normalizeRequestHost(r.Host)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if httpsPort != 443 {
		host += ":" + strconv.Itoa(int(httpsPort))
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
}

// serveACMEChallenge 在明文端口上应答 ACME HTTP-01 挑战；已处理时返回 true。
func (m *Manager) serveACMEChallenge(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		return false
	}
	mgr := m.acmeManager()
	if mgr == nil {
		return false
	}
	mgr.HTTPHandler(nil).ServeHTTP(w, r)
	return true
}
