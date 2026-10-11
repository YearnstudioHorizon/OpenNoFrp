package panel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opennofrp/server/internal/store"
)

type captchaTransport func(*http.Request) (*http.Response, error)

func (f captchaTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func captchaTestPanel(t *testing.T) (*Panel, *httptest.Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "captcha.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.CreateAdmin(context.Background(), "admin", "pass1234"); err != nil {
		t.Fatal(err)
	}
	p := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, "", "", 0, "", "")
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return p, srv
}

func TestBuiltinCaptchaLogin(t *testing.T) {
	p, srv := captchaTestPanel(t)
	if err := p.Store.SaveCaptchaSettings(context.Background(), store.CaptchaSettings{Provider: "builtin"}); err != nil {
		t.Fatal(err)
	}
	credentials := url.Values{"username": {"admin"}, "password": {"pass1234"}}
	resp, page := do(t, "POST", srv.URL+"/login", nil, credentials)
	if resp.StatusCode == http.StatusSeeOther || !strings.Contains(page, "人机验证未通过") {
		t.Fatal("missing captcha bypassed")
	}
	resp, err := http.Get(srv.URL + "/captcha/image")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	img, err := png.Decode(resp.Body)
	if err != nil || img.Bounds().Dx() != 200 {
		t.Fatal("invalid captcha image", err)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("captcha image cached")
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == captchaCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly {
		t.Fatal("missing protected challenge cookie")
	}
	p.mu.Lock()
	challenge := p.captchaChallenges[cookie.Value]
	p.mu.Unlock()
	credentials.Set("captcha_answer", challenge.Answer)
	resp, _ = do(t, "POST", srv.URL+"/login", cookie, credentials)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatal("valid captcha rejected", resp.StatusCode)
	}
	resp, page = do(t, "POST", srv.URL+"/login", cookie, credentials)
	if resp.StatusCode == http.StatusSeeOther || !strings.Contains(page, "人机验证未通过") {
		t.Fatal("captcha replay accepted")
	}
	p.mu.Lock()
	p.captchaChallenges[cookie.Value] = captchaChallenge{Answer: challenge.Answer, Expires: time.Now().Add(-time.Second)}
	p.mu.Unlock()
	resp, _ = do(t, "POST", srv.URL+"/login", cookie, credentials)
	if resp.StatusCode == http.StatusSeeOther {
		t.Fatal("expired captcha accepted")
	}
}

func TestExternalCaptchaVerification(t *testing.T) {
	p, _ := captchaTestPanel(t)
	settings := store.CaptchaSettings{Provider: "fcaptcha", FCaptchaURL: "https://captcha.example.test/base", FCaptchaSiteKey: "site", FCaptchaSecret: "server-secret"}
	if err := p.Store.SaveCaptchaSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	response := `{"valid":true,"score":0.1,"site_key":"site","hostname":"example.com"}`
	status := http.StatusOK
	count := 0
	p.captchaHTTP = &http.Client{Transport: captchaTransport(func(r *http.Request) (*http.Response, error) {
		count++
		if r.URL.String() != settings.FCaptchaURL+"/api/token/verify" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("incorrect native verify request")
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["secret"] != settings.FCaptchaSecret || payload["token"] == "" {
			t.Fatal("missing backend credentials")
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
	})}
	verify := func(token string) error {
		req := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{"captcha_token": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return p.verifyCaptcha(req)
	}
	if err := verify("good"); err != nil {
		t.Fatal(err)
	}
	if err := verify("good"); err == nil || count != 1 {
		t.Fatal("token replay reached provider")
	}
	for i, bad := range []string{`{"valid":false,"score":0.1}`, `{"valid":true,"score":0.5}`, `{"valid":true}`, `{"valid":true,"score":-1}`, `not json`, `{"valid":true,"score":0.1,"site_key":"other","hostname":"example.com"}`, `{"valid":true,"score":0.1,"site_key":"site","hostname":"other.test"}`, `{"valid":true,"score":0.1,"site_key":"site","hostname":"example.com","action":"different-action"}`} {
		response = bad
		if err := verify(string(rune('a' + i))); err == nil {
			t.Fatalf("unsafe response accepted: %s", bad)
		}
	}
	response = `{"valid":true,"score":0}`
	status = http.StatusServiceUnavailable
	if err := verify("unavailable"); err == nil {
		t.Fatal("provider outage bypassed")
	}
	settings.Provider = "geetest"
	settings.GeetestID = "configured-id"
	settings.GeetestKey = "private-key"
	if err := p.Store.SaveCaptchaSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	p.captchaHTTP = &http.Client{Transport: captchaTransport(func(r *http.Request) (*http.Response, error) {
		r.ParseForm()
		mac := hmac.New(sha256.New, []byte(settings.GeetestKey))
		mac.Write([]byte("lot-1"))
		if r.URL.Scheme != "https" || r.URL.Host != "gcaptcha4.geetest.com" || r.FormValue("captcha_id") != settings.GeetestID || r.FormValue("sign_token") != hex.EncodeToString(mac.Sum(nil)) {
			t.Fatal("bad geetest signing or provider")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"result":"success"}`)), Header: make(http.Header)}, nil
	})}
	values := url.Values{"lot_number": {"lot-1"}, "captcha_output": {"output"}, "pass_token": {"pass"}, "gen_time": {"123"}, "captcha_id": {"attacker-id"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := p.verifyCaptcha(req); err != nil {
		t.Fatal(err)
	}
	if err := p.verifyCaptcha(req); err == nil {
		t.Fatal("geetest replay accepted")
	}
}

func TestCaptchaSettingsProtectedAndSecretsHidden(t *testing.T) {
	p, srv := captchaTestPanel(t)
	cookie := login(t, srv)
	_, page := do(t, "GET", srv.URL+"/security", cookie, nil)
	csrf := csrfRe.FindStringSubmatch(page)[1]
	values := url.Values{"provider": {"fcaptcha"}, "fcaptcha_url": {"https://captcha.example.test/"}, "fcaptcha_site_key": {"site"}, "fcaptcha_secret": {"secret-do-not-render"}}
	resp, _ := do(t, "POST", srv.URL+"/security/captcha", cookie, values)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatal("settings csrf bypass")
	}
	values.Set("csrf_token", csrf)
	resp, _ = do(t, "POST", srv.URL+"/security/captcha", cookie, values)
	if !strings.HasPrefix(resp.Header.Get("Location"), "/security?ok=") {
		t.Fatal("failed save")
	}
	for _, path := range []string{"/security", "/login"} {
		_, page = do(t, "GET", srv.URL+path, cookie, nil)
		if strings.Contains(page, "secret-do-not-render") {
			t.Fatal("secret leaked", path)
		}
	}
	values.Set("fcaptcha_secret", "")
	values.Set("provider", "builtin")
	values.Del("fcaptcha_url")
	values.Del("fcaptcha_site_key")
	do(t, "POST", srv.URL+"/security/captcha", cookie, values)
	s, err := p.Store.CaptchaSettings(context.Background())
	if err != nil || s.Provider != "builtin" || s.FCaptchaSecret != "secret-do-not-render" || s.FCaptchaSiteKey != "site" {
		t.Fatal("switch lost saved settings", err)
	}
	for _, address := range []string{"javascript:alert(1)", "https://user:pass@example.test", "https://example.test?a=1", "https://example.test#fragment"} {
		s.Provider = "fcaptcha"
		s.FCaptchaURL = address
		if validateCaptchaSettings(s) == nil {
			t.Fatal("unsafe instance URL accepted", address)
		}
	}
}
