package listener

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMatchRoute(t *testing.T) {
	routes := []httpRoute{
		{RuleID: 1, Domains: nil, PathPrefix: "/"},
		{RuleID: 2, Domains: []string{"app.example.com"}, PathPrefix: "/"},
		{RuleID: 3, Domains: []string{"app.example.com"}, PathPrefix: "/api"},
		{RuleID: 4, Domains: []string{"*.example.com"}, PathPrefix: "/"},
	}
	cases := []struct {
		host, path string
		want       uint32
	}{
		{"app.example.com", "/", 2},
		{"APP.example.com:80", "/index.html", 2},
		{"app.example.com", "/api", 3},
		{"app.example.com", "/api/v1/x", 3},
		{"app.example.com", "/apix", 2},
		{"foo.example.com", "/", 4},
		{"example.com", "/", 1},
		{"other.org", "/x", 1},
		{"1.2.3.4:8080", "/", 1},
	}
	for _, c := range cases {
		got, ok := matchRoute(routes, c.host, c.path)
		if !ok || got.RuleID != c.want {
			t.Errorf("matchRoute(%q,%q) = %d,%v; want %d", c.host, c.path, got.RuleID, ok, c.want)
		}
	}

	if _, ok := matchRoute(routes[1:3], "other.org", "/"); ok {
		t.Errorf("expected no match without fallback route")
	}
}

func TestServeUnavailable(t *testing.T) {
	rec := httptest.NewRecorder()
	serveUnavailable(rec, httpRoute{Name: "blog"})
	if rec.Code != 503 {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "blog") {
		t.Errorf("default page should mention rule name")
	}

	rec = httptest.NewRecorder()
	serveUnavailable(rec, httpRoute{OfflinePage: "<h1>维护中</h1>"})
	if rec.Code != 503 || rec.Body.String() != "<h1>维护中</h1>" {
		t.Errorf("custom page not served: %d %q", rec.Code, rec.Body.String())
	}
}
