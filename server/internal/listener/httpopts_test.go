package listener

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseHeaderOps(t *testing.T) {
	ops, err := parseHeaderOps("x-from: opennofrp\r\n# comment\n\nCookie:\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 || ops[0].Name != "X-From" || ops[0].Value != "opennofrp" || ops[0].Del ||
		ops[1].Name != "Cookie" || !ops[1].Del {
		t.Fatalf("unexpected ops: %+v", ops)
	}
	for _, bad := range []string{"NoColon", "Bad Name: v", "Host: x", "connection: close", ": v"} {
		if _, err := parseHeaderOps(bad); err == nil {
			t.Errorf("parseHeaderOps(%q) should fail", bad)
		}
	}
	h := http.Header{}
	h.Set("Cookie", "a=b")
	applyHeaderOps(h, ops)
	if h.Get("X-From") != "opennofrp" || h.Get("Cookie") != "" {
		t.Errorf("applyHeaderOps result: %v", h)
	}
}

func TestBasicAuth(t *testing.T) {
	hash, err := HashBasicAuthPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := ParseBasicAuth("admin:" + hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBasicAuth("admin:plaintext"); err == nil {
		t.Errorf("non-bcrypt hash should be rejected")
	}
	cases := []struct {
		user, pass string
		set        bool
		want       bool
	}{
		{"admin", "s3cret", true, true},
		{"admin", "wrong", true, false},
		{"nobody", "s3cret", true, false},
		{"", "", false, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if c.set {
			r.SetBasicAuth(c.user, c.pass)
		}
		if got := checkBasicAuth(r, accounts); got != c.want {
			t.Errorf("checkBasicAuth(%q,%q) = %v want %v", c.user, c.pass, got, c.want)
		}
	}
	if !checkBasicAuth(httptest.NewRequest("GET", "/", nil), nil) {
		t.Errorf("empty accounts should allow all")
	}
}

func TestIPAllowed(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.0.0/16")
	allow := []*net.IPNet{n}
	if !ipAllowed(net.ParseIP("192.168.1.2"), allow) {
		t.Errorf("in-range IP rejected")
	}
	if ipAllowed(net.ParseIP("10.0.0.1"), allow) {
		t.Errorf("out-of-range IP allowed")
	}
	if ipAllowed(nil, allow) {
		t.Errorf("nil IP allowed with non-empty allowlist")
	}
	if !ipAllowed(net.ParseIP("10.0.0.1"), nil) {
		t.Errorf("empty allowlist should allow all")
	}
}

func TestStripPathPrefix(t *testing.T) {
	cases := map[string]string{
		"/api":       "/",
		"/api/x":     "/x",
		"/api/x/y":   "/x/y",
		"/apix":      "/apix",
		"/other/api": "/other/api",
	}
	for in, want := range cases {
		u := &url.URL{Path: in}
		stripPathPrefix(u, "/api")
		if u.Path != want {
			t.Errorf("strip(%q) = %q want %q", in, u.Path, want)
		}
	}
	u := &url.URL{Path: "/x"}
	stripPathPrefix(u, "/")
	if u.Path != "/x" {
		t.Errorf("root prefix should be a no-op, got %q", u.Path)
	}
}

func TestServeNotFoundCustomPage(t *testing.T) {
	routes := []httpRoute{{RuleID: 1}, {RuleID: 2, NotFoundPage: "<h1>nope</h1>"}}
	w := httptest.NewRecorder()
	serveNotFound(w, "a.test", portNotFoundPage(routes))
	if w.Code != 404 || w.Body.String() != "<h1>nope</h1>" {
		t.Errorf("custom 404: %d %q", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	serveNotFound(w, "a.test", "")
	if w.Code != 404 || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("default 404: %d %v", w.Code, w.Header())
	}
}
