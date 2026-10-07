package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSplitDomainsAndPath(t *testing.T) {
	got := SplitDomains(" A.example.com, b.example.com.;a.example.com \n *.x.org")
	want := []string{"a.example.com", "b.example.com", "*.x.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SplitDomains = %v, want %v", got, want)
	}
	for in, want := range map[string]string{"": "/", "/": "/", "api": "/api", "/api/": "/api", "/a/b//": "/a/b"} {
		if got := NormalizePathPrefix(in); got != want {
			t.Errorf("NormalizePathPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRulesConflict(t *testing.T) {
	h := func(domains, path string) Rule { return Rule{Protocol: "http", Domains: domains, PathPrefix: path} }
	cases := []struct {
		a, b Rule
		want bool
	}{
		{h("a.com", ""), h("b.com", ""), false},
		{h("a.com", ""), h("a.com,b.com", ""), true},
		{h("a.com", "/api"), h("a.com", ""), false},
		{h("a.com", "/api"), h("a.com", "/api/"), true},
		{h("", ""), h("", ""), true},
		{h("", ""), h("a.com", ""), false},
		{h("a.com", ""), Rule{Protocol: "tcp"}, true},
		{h("a.com", ""), Rule{Protocol: "tcp+udp"}, true},
		{h("a.com", ""), Rule{Protocol: "udp"}, false},
		{Rule{Protocol: "tcp"}, Rule{Protocol: "udp"}, false},
		{Rule{Protocol: "udp"}, Rule{Protocol: "tcp+udp"}, true},
	}
	for i, c := range cases {
		if got := rulesConflict(c.a, c.b); got != c.want {
			t.Errorf("case %d: rulesConflict = %v, want %v", i, got, c.want)
		}
		if got := rulesConflict(c.b, c.a); got != c.want {
			t.Errorf("case %d (swapped): rulesConflict = %v, want %v", i, got, c.want)
		}
	}
}

func TestHTTPRulesSharePort(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	cid, _, err := st.CreateClient(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	r1 := Rule{ClientID: cid, Name: "a", Protocol: "http", LocalIP: "127.0.0.1", LocalPort: 3000, RemotePort: 80, Domains: "a.com", OfflinePage: "<p>down</p>", Enabled: true}
	id1, err := st.CreateRule(ctx, r1)
	if err != nil {
		t.Fatal(err)
	}
	r2 := Rule{ClientID: cid, Name: "b", Protocol: "http", LocalIP: "127.0.0.1", LocalPort: 3001, RemotePort: 80, Domains: "b.com", Enabled: true}
	if c, err := st.RuleConflict(ctx, r2); err != nil || c != nil {
		t.Fatalf("unexpected conflict %v %v", c, err)
	}
	if _, err := st.CreateRule(ctx, r2); err != nil {
		t.Fatalf("second http rule on same port should be allowed: %v", err)
	}
	r3 := Rule{ClientID: cid, Name: "c", Protocol: "http", RemotePort: 80, Domains: "a.com"}
	if c, _ := st.RuleConflict(ctx, r3); c == nil || c.ID != id1 {
		t.Fatalf("expected conflict with rule %d, got %v", id1, c)
	}
	got, err := st.GetRule(ctx, id1)
	if err != nil || got.Domains != "a.com" || got.OfflinePage != "<p>down</p>" {
		t.Fatalf("GetRule roundtrip failed: %+v %v", got, err)
	}
}
