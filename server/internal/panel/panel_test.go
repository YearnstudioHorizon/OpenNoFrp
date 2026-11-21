package panel

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"opennofrp/server/internal/listener"
	"opennofrp/server/internal/store"
)

var csrfRe = regexp.MustCompile(`name="csrf_token" value="([0-9a-f]+)"`)

func newTestPanel(t *testing.T, st *store.Store) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := New(st, logger, nil, "http://127.0.0.1", "127.0.0.1", 17000, "", t.TempDir())
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func login(t *testing.T, srv *httptest.Server) *http.Cookie {
	t.Helper()
	resp, err := noRedirectClient().PostForm(srv.URL+"/login", url.Values{"username": {"admin"}, "password": {"pass1234"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			return c
		}
	}
	t.Fatalf("login did not set session cookie (status %d)", resp.StatusCode)
	return nil
}

func do(t *testing.T, method, u string, cookie *http.Cookie, form url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, u, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestPanelCSRFAndPersistentSessions(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateAdmin(context.Background(), "admin", "pass1234"); err != nil {
		t.Fatal(err)
	}
	srv := newTestPanel(t, st)

	// 未登录访问被重定向到登录页
	if resp, _ := do(t, "GET", srv.URL+"/", nil, nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unauthenticated GET / = %d", resp.StatusCode)
	}

	cookie := login(t, srv)
	resp, page := do(t, "GET", srv.URL+"/", cookie, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("index page has no csrf_token field")
	}
	csrf := m[1]

	// 缺少或错误的 CSRF 令牌被拒绝
	if resp, _ := do(t, "POST", srv.URL+"/reserved/add", cookie, url.Values{"port": {"2222"}, "reason": {"x"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST without csrf = %d, want 403", resp.StatusCode)
	}
	if resp, _ := do(t, "POST", srv.URL+"/reserved/add", cookie, url.Values{"port": {"2222"}, "csrf_token": {strings.Repeat("0", len(csrf))}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST with wrong csrf = %d, want 403", resp.StatusCode)
	}
	reserved, _ := st.ReservedPorts(context.Background())
	if _, ok := reserved[2222]; ok {
		t.Fatalf("reserved port added despite csrf failure")
	}

	// 正确的 CSRF 令牌被接受
	if resp, _ := do(t, "POST", srv.URL+"/reserved/add", cookie, url.Values{"port": {"2222"}, "reason": {"x"}, "csrf_token": {csrf}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("POST with csrf = %d, want 303", resp.StatusCode)
	}
	reserved, _ = st.ReservedPorts(context.Background())
	if _, ok := reserved[2222]; !ok {
		t.Errorf("reserved port not added with valid csrf")
	}

	// 会话持久化：新的 Panel 实例（模拟重启）仍认可该会话
	srv2 := newTestPanel(t, st)
	if resp, _ := do(t, "GET", srv2.URL+"/", cookie, nil); resp.StatusCode != 200 {
		t.Errorf("session not persisted across panel restart: %d", resp.StatusCode)
	}

	if resp, _ := do(t, "POST", srv2.URL+"/logout", cookie, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without CSRF token = %d, want 403", resp.StatusCode)
	}
	// 退出登录后会话失效
	do(t, "POST", srv2.URL+"/logout", cookie, url.Values{"csrf_token": {csrf}})
	if resp, _ := do(t, "GET", srv.URL+"/", cookie, nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("session still valid after logout: %d", resp.StatusCode)
	}
}

func TestBootstrapRequiresTrustedHTTPS(t *testing.T) {
	p := &Panel{BaseURL: "https://panel.example.test"}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/install_client.sh", nil)
	req.RemoteAddr = "127.0.0.1:15100"
	req.Header.Set("X-Forwarded-Proto", "https")
	if _, ok := p.bootstrapURL(httptest.NewRecorder(), req); ok {
		t.Fatal("forwarded scheme accepted from an unconfigured peer")
	}
	p.TrustedProxies, _ = listener.ParseTrustedProxies("127.0.0.1/32")
	base, ok := p.bootstrapURL(httptest.NewRecorder(), req)
	if !ok || base.Hostname() != "panel.example.test" {
		t.Fatalf("trusted HTTPS request rejected or wrong origin: %v", base)
	}
	p.BaseURL = "http://panel.example.test"
	if _, ok := p.bootstrapURL(httptest.NewRecorder(), req); ok {
		t.Fatal("bootstrap accepted a configured plaintext origin")
	}
}

func TestClientBootstrapScript(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "onboard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := New(st, slog.Default(), nil, "https://panel.example.test", "", 17000, "SHA256"+strings.Repeat(":AB", 32), "")
	token, err := st.CreateRegisterToken(context.Background(), "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://panel.example.test/install_client.sh?token="+token.Token, nil)
	response := httptest.NewRecorder()
	p.Handler().ServeHTTP(response, req)
	script := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(script, "SERVER_HOST='panel.example.test'") ||
		!strings.Contains(script, "gh attestation verify") {
		t.Fatal("bootstrap script missed configured host or required release verification")
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = strings.NewReader(script)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bootstrap script has invalid shell syntax: %v: %s", err, output)
		}
	}
}

func TestHTTPPanelLoginAndManualOnboarding(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateAdmin(ctx, "admin", "pass1234"); err != nil {
		t.Fatal(err)
	}
	fp := "SHA256" + strings.Repeat(":AB", 32)
	p := New(st, slog.Default(), nil, "http://panel.example.test:8080", "", 17000, fp, "")
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	cookie := login(t, srv)
	if cookie.Secure {
		t.Fatal("HTTP login issued a Secure cookie")
	}
	resp, page := do(t, "GET", srv.URL+"/onboard", cookie, nil)
	match := csrfRe.FindStringSubmatch(page)
	if resp.StatusCode != http.StatusOK || match == nil {
		t.Fatal("onboarding page is unavailable over HTTP")
	}
	resp, page = do(t, "POST", srv.URL+"/register-token", cookie, url.Values{"csrf_token": {match[1]}})
	for _, want := range []string{"[server]", "panel.example.test", "port = 17000", fp, "token = "} {
		if resp.StatusCode != http.StatusOK || !strings.Contains(page, want) {
			t.Fatalf("manual config is missing %q (HTTP %d)", want, resp.StatusCode)
		}
	}
	if strings.Contains(page, "/install_client.sh?token=") {
		t.Fatal("HTTP onboarding returned an executable bootstrap command")
	}
}
