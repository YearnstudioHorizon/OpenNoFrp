package listener

// 真实客户端 IP 提取与转发请求头改写（仅 HTTP 规则）。
//
// 每条 HTTP 规则可配置按优先级排列的 IP 来源列表（IPSources）以及可信代理列表
// （TrustedProxies）。Server 按顺序尝试各来源，第一个能解析出合法 IP 的来源胜出；
// 都失败时回退为 TCP 对端地址。提取出的 IP 会：
//   - 写入 StreamMetadata.ClientAddr，Client 据此以该 IP 为源地址伪装拨号
//     （PreserveSourceIP 开启时），后端在 TCP 层看到的就是真实访问者 IP；
//   - 写入转发给后端的 X-Real-IP / X-Forwarded-For / Forwarded 等请求头。
//
// 安全：若配置了 TrustedProxies 而 TCP 对端不在其中，则完全忽略请求头里的 IP
// （防止访问者伪造 X-Forwarded-For），并剥离入站的这些头。

import (
	"net"
	"net/http"
	"strings"
)

// 支持的 IP 来源标识。
const (
	IPSourceRemoteAddr     = "remote_addr"
	IPSourceXForwardedFor  = "x-forwarded-for"
	IPSourceXRealIP        = "x-real-ip"
	IPSourceCFConnectingIP = "cf-connecting-ip"
	IPSourceTrueClientIP   = "true-client-ip"
	IPSourceXClientIP      = "x-client-ip"
	IPSourceForwarded      = "forwarded"
)

// KnownIPSources 按面板展示顺序列出所有合法来源。
var KnownIPSources = []string{
	IPSourceRemoteAddr, IPSourceXForwardedFor, IPSourceXRealIP,
	IPSourceCFConnectingIP, IPSourceTrueClientIP, IPSourceXClientIP, IPSourceForwarded,
}

// clientIPHeaders 是可能携带客户端 IP、在不可信时需要剥离的入站请求头。
var clientIPHeaders = []string{
	"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP", "X-Client-IP", "Forwarded",
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
}

// ParseIPSources 规范化来源列表：小写、去重、丢弃未知值；为空返回 [remote_addr]。
func ParseIPSources(s string) []string {
	known := map[string]bool{}
	for _, k := range KnownIPSources {
		known[k] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range splitList(s) {
		f = strings.ToLower(strings.TrimSpace(f))
		if !known[f] || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	if len(out) == 0 {
		out = []string{IPSourceRemoteAddr}
	}
	return out
}

// ParseTrustedProxies 解析逗号分隔的 IP/CIDR 列表；无法解析的项通过 bad 返回。
func ParseTrustedProxies(s string) (nets []*net.IPNet, bad []string) {
	for _, f := range splitList(s) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			ip := net.ParseIP(f)
			if ip == nil {
				bad = append(bad, f)
				continue
			}
			bits := 128
			if v4 := ip.To4(); v4 != nil {
				ip, bits = v4, 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(f)
		if err != nil {
			bad = append(bad, f)
			continue
		}
		nets = append(nets, n)
	}
	return nets, bad
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// headersTrusted 报告是否可以信任来自 peer 的请求头中的 IP。
func headersTrusted(peer net.IP, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return true
	}
	return peer != nil && ipInNets(peer, trusted)
}

func parseHeaderIP(v string) net.IP {
	v = strings.Trim(strings.TrimSpace(v), "\"")
	if v == "" || strings.EqualFold(v, "unknown") {
		return nil
	}
	if strings.HasPrefix(v, "[") {
		if i := strings.Index(v, "]"); i > 0 {
			v = v[1:i]
		}
	} else if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	return net.ParseIP(v)
}

// fromChain 从 IP 链中选取客户端 IP：配置了可信代理时，从右向左跳过可信代理
// 取第一个非可信地址；否则取最左侧的合法地址。
func fromChain(values []string, trusted []*net.IPNet) net.IP {
	var chain []net.IP
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if ip := parseHeaderIP(part); ip != nil {
				chain = append(chain, ip)
			}
		}
	}
	if len(chain) == 0 {
		return nil
	}
	if len(trusted) > 0 {
		for i := len(chain) - 1; i >= 0; i-- {
			if !ipInNets(chain[i], trusted) {
				return chain[i]
			}
		}
	}
	return chain[0]
}

// fromForwarded 解析 RFC 7239 Forwarded 头中的 for= 值。
func fromForwarded(values []string, trusted []*net.IPNet) net.IP {
	var chain []string
	for _, v := range values {
		for _, elem := range strings.Split(v, ",") {
			for _, pair := range strings.Split(elem, ";") {
				k, val, ok := strings.Cut(strings.TrimSpace(pair), "=")
				if ok && strings.EqualFold(strings.TrimSpace(k), "for") {
					chain = append(chain, val)
				}
			}
		}
	}
	return fromChain(chain, trusted)
}

func peerIPOf(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

// extractClientIP 按路由配置的优先级提取真实客户端 IP。fromHeader 表示该 IP
// 是否来自请求头（而非 TCP 对端地址）。
func extractClientIP(r *http.Request, route httpRoute) (ip net.IP, fromHeader bool) {
	peer := peerIPOf(r)
	if !headersTrusted(peer, route.TrustedProxies) {
		return peer, false
	}
	sources := route.IPSources
	if len(sources) == 0 {
		sources = []string{IPSourceRemoteAddr}
	}
	for _, src := range sources {
		var got net.IP
		switch src {
		case IPSourceRemoteAddr:
			return peer, false
		case IPSourceXForwardedFor:
			got = fromChain(r.Header.Values("X-Forwarded-For"), route.TrustedProxies)
		case IPSourceForwarded:
			got = fromForwarded(r.Header.Values("Forwarded"), route.TrustedProxies)
		case IPSourceXRealIP:
			got = parseHeaderIP(r.Header.Get("X-Real-IP"))
		case IPSourceCFConnectingIP:
			got = parseHeaderIP(r.Header.Get("CF-Connecting-IP"))
		case IPSourceTrueClientIP:
			got = parseHeaderIP(r.Header.Get("True-Client-IP"))
		case IPSourceXClientIP:
			got = parseHeaderIP(r.Header.Get("X-Client-IP"))
		}
		if got != nil {
			return got, true
		}
	}
	return peer, false
}

func forwardedNode(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	if ip.To4() == nil {
		return "\"[" + ip.String() + "]\""
	}
	return ip.String()
}

// rewriteForwardHeaders 改写发往后端的请求头，使后端无论读哪个头都能拿到同一个
// 真实客户端 IP：
//
//	X-Real-IP          = 真实 IP
//	X-Forwarded-For    = 真实 IP（若入站链可信，则为 入站链 + 对端地址）
//	X-Forwarded-Host   = 原始 Host
//	X-Forwarded-Proto  = http/https（可信时沿用入站值）
//	Forwarded          = for=<真实 IP>;host="<Host>";proto=<proto>
//	CF-Connecting-IP / True-Client-IP / X-Client-IP：可信时原样保留，否则剥离。
func rewriteForwardHeaders(in *http.Request, out http.Header, route httpRoute, realIP net.IP) {
	peer := peerIPOf(in)
	trusted := headersTrusted(peer, route.TrustedProxies)

	proto := "http"
	if in.TLS != nil {
		proto = "https"
	}
	inXFF := strings.Join(in.Header.Values("X-Forwarded-For"), ", ")
	if trusted {
		if p := strings.ToLower(strings.TrimSpace(in.Header.Get("X-Forwarded-Proto"))); p == "http" || p == "https" {
			proto = p
		}
	} else {
		for _, h := range clientIPHeaders {
			out.Del(h)
		}
		inXFF = ""
	}

	realStr := ""
	if realIP != nil {
		realStr = realIP.String()
	}
	xff := realStr
	if strings.TrimSpace(inXFF) != "" && peer != nil {
		xff = inXFF + ", " + peer.String()
	}
	if xff != "" {
		out.Set("X-Forwarded-For", xff)
	} else {
		out.Del("X-Forwarded-For")
	}
	if realStr != "" {
		out.Set("X-Real-IP", realStr)
	}
	out.Set("X-Forwarded-Host", in.Host)
	out.Set("X-Forwarded-Proto", proto)
	out.Set("Forwarded", "for="+forwardedNode(realIP)+";host=\""+strings.ReplaceAll(in.Host, "\"", "")+"\";proto="+proto)
}
