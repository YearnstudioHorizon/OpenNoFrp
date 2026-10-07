package listener

// HTTP 路由选项：剥离路径前缀、改写 Host、自定义请求/响应头、Basic Auth、
// IP 白名单与端口级自定义 404 页面。解析函数同时供面板校验表单使用。

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// headerOp 是一条自定义头操作：Del 为 true 时删除该头，否则设置为 Value。
type headerOp struct {
	Name  string
	Value string
	Del   bool
}

// 逐跳头与代理自身维护的头不允许通过自定义头修改。
var forbiddenCustomHeaders = map[string]bool{
	"Connection":        true,
	"Upgrade":           true,
	"Transfer-Encoding": true,
	"Content-Length":    true,
	"Te":                true,
	"Trailer":           true,
	"Keep-Alive":        true,
	"Host":              true,
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// parseHeaderOps 解析每行一个 "Name: Value" 的文本；"Name:" 表示删除该头。
// 空行与以 # 开头的行被忽略。
func parseHeaderOps(s string) ([]headerOp, error) {
	var ops []headerOp
	for i, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: missing ':'", i+1)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !validHeaderName(name) {
			return nil, fmt.Errorf("line %d: invalid header name %q", i+1, name)
		}
		canon := http.CanonicalHeaderKey(name)
		if forbiddenCustomHeaders[canon] {
			return nil, fmt.Errorf("line %d: header %q cannot be customized", i+1, canon)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("line %d: invalid header value", i+1)
		}
		ops = append(ops, headerOp{Name: canon, Value: value, Del: value == ""})
	}
	return ops, nil
}

// ValidateHeaderOps 校验自定义头文本，供面板使用。
func ValidateHeaderOps(s string) error {
	_, err := parseHeaderOps(s)
	return err
}

func applyHeaderOps(h http.Header, ops []headerOp) {
	for _, op := range ops {
		if op.Del {
			h.Del(op.Name)
		} else {
			h.Set(op.Name, op.Value)
		}
	}
}

// ParseBasicAuth 解析每行一个 "user:bcrypt哈希" 的文本，返回 user -> 哈希。
func ParseBasicAuth(s string) (map[string]string, error) {
	out := map[string]string{}
	for i, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, hash, ok := strings.Cut(line, ":")
		if !ok || user == "" || hash == "" {
			return nil, fmt.Errorf("line %d: expected user:hash", i+1)
		}
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return nil, fmt.Errorf("line %d: password hash for %q is not bcrypt", i+1, user)
		}
		out[user] = hash
	}
	return out, nil
}

// HashBasicAuthPassword 生成 bcrypt 哈希，供面板把明文密码转换为存储格式。
func HashBasicAuthPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("empty password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// dummyBcrypt 用于用户不存在时仍执行一次比较，避免通过耗时探测用户名。
var dummyBcrypt, _ = bcrypt.GenerateFromPassword([]byte("opennofrp-dummy"), bcrypt.MinCost)

// checkBasicAuth 报告请求是否携带有效的 Basic Auth 凭据。accounts 为空时总是放行。
func checkBasicAuth(r *http.Request, accounts map[string]string) bool {
	if len(accounts) == 0 {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	hash, found := "", false
	for u, h := range accounts {
		if subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1 {
			hash, found = h, true
		}
	}
	if !found {
		_ = bcrypt.CompareHashAndPassword(dummyBcrypt, []byte(pass))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
}

// ipAllowed 报告 ip 是否落在白名单内。白名单为空时总是放行；ip 为空时拒绝。
func ipAllowed(ip net.IP, allow []*net.IPNet) bool {
	if len(allow) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, n := range allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// stripPathPrefix 去掉 URL 路径中的前缀（/api/x -> /x，/api -> /）。
func stripPathPrefix(u *url.URL, prefix string) {
	if prefix == "" || prefix == "/" {
		return
	}
	strip := func(p string) string {
		if p == prefix {
			return "/"
		}
		if strings.HasPrefix(p, prefix+"/") {
			return p[len(prefix):]
		}
		return p
	}
	u.Path = strip(u.Path)
	if u.RawPath != "" {
		u.RawPath = strip(u.RawPath)
	}
}

func serveAuthRequired(w http.ResponseWriter, route httpRoute) {
	realm := route.Name
	if realm == "" {
		realm = "OpenNoFrp"
	}
	realm = strings.NewReplacer(`"`, "", "\\", "").Replace(realm)
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintln(w, "401 unauthorized")
}

func serveForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintln(w, "403 forbidden")
}

// portNotFoundPage 返回该端口上第一条设置了自定义 404 页面的路由的页面。
func portNotFoundPage(routes []httpRoute) string {
	for _, r := range routes {
		if strings.TrimSpace(r.NotFoundPage) != "" {
			return r.NotFoundPage
		}
	}
	return ""
}
