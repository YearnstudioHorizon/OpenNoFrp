package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
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
	tl := func(domains string) Rule { return Rule{Protocol: "tls", Domains: domains} }
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
		// HTTPS 与明文 HTTP 不能共用端口
		{Rule{Protocol: "http", Domains: "a.com", TLSMode: "acme"}, h("b.com", ""), true},
		// TLS 透传
		{tl("a.com"), tl("b.com"), false},
		{tl("a.com"), tl("a.com,c.com"), true},
		{tl(""), tl(""), true},
		{tl(""), tl("a.com"), false},
		{tl("a.com"), h("b.com", ""), true},
		{tl("a.com"), Rule{Protocol: "tcp"}, true},
		{tl("a.com"), Rule{Protocol: "udp"}, false},
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

func TestPortRangeConflict(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "pr.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	cid, _, err := st.CreateClient(ctx, "c")
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateRule(ctx, Rule{ClientID: cid, Name: "range", Protocol: "tcp", LocalIP: "127.0.0.1", LocalPort: 20000, RemotePort: 10000, RemotePortEnd: 10010})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := st.RuleConflict(ctx, Rule{Protocol: "tcp", RemotePort: 10005}); err != nil || c == nil || c.ID != id {
		t.Errorf("port inside range should conflict: %v %v", c, err)
	}
	if c, err := st.RuleConflict(ctx, Rule{Protocol: "tcp", RemotePort: 9990, RemotePortEnd: 10000}); err != nil || c == nil {
		t.Errorf("overlapping range should conflict: %v %v", c, err)
	}
	if c, err := st.RuleConflict(ctx, Rule{Protocol: "tcp", RemotePort: 10011}); err != nil || c != nil {
		t.Errorf("port after range should not conflict: %v %v", c, err)
	}
	if c, err := st.RuleConflict(ctx, Rule{Protocol: "udp", RemotePort: 10005}); err != nil || c != nil {
		t.Errorf("udp inside tcp range should not conflict: %v %v", c, err)
	}
}

// TestMigrateOldDatabase 模拟最早版本（仅 tcp/udp、remote_port UNIQUE、无扩展列）的
// 数据库，验证升级后旧数据保留、新协议与新字段可用，且迁移可重复执行。
func TestMigrateOldDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	const old = `
CREATE TABLE clients (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	secret_hash TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL DEFAULT 0,
	last_seen_addr TEXT NOT NULL DEFAULT ''
);
CREATE TABLE rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	protocol TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
	local_ip TEXT NOT NULL DEFAULT '127.0.0.1',
	local_port INTEGER NOT NULL,
	remote_port INTEGER NOT NULL UNIQUE,
	preserve_source_ip INTEGER NOT NULL DEFAULT 1,
	enabled INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);
INSERT INTO clients (id, name, secret_hash, created_at) VALUES ('c1', 'box', 'x', 1);
INSERT INTO rules (client_id, name, protocol, local_port, remote_port, enabled, created_at) VALUES ('c1', 'ssh', 'tcp', 22, 2222, 1, 1);
`
	if _, err := db.Exec(old); err != nil {
		db.Close()
		t.Fatalf("create old schema: %v", err)
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	ctx := context.Background()
	rules, err := st.ListRulesForClient(ctx, "c1")
	if err != nil || len(rules) != 1 {
		t.Fatalf("old rules after migration: %v %v", rules, err)
	}
	if r := rules[0]; r.Protocol != "tcp" || r.RemotePort != 2222 || r.LocalPort != 22 || !r.Enabled || !r.PreserveSourceIP {
		t.Errorf("old rule not preserved: %+v", r)
	}

	// 新协议与 UNIQUE(remote_port) 已移除：两条 HTTP 规则共享 80 端口。
	for _, d := range []string{"a.com", "b.com"} {
		if _, err := st.CreateRule(ctx, Rule{ClientID: "c1", Name: d, Protocol: "http", LocalIP: "127.0.0.1", LocalPort: 8080, RemotePort: 80, Domains: d}); err != nil {
			t.Fatalf("create http rule after migration: %v", err)
		}
	}
	full := Rule{ClientID: "c1", Name: "full", Protocol: "tls", LocalIP: "127.0.0.1", LocalPort: 8443, RemotePort: 443,
		Domains: "x.com", GuardDeny: "10.0.0.0/8", MaxConnsPerIP: 3, BandwidthKBps: 100,
		Backends: "127.0.0.2:8443", LBStrategy: "failover", ProxyProtocol: 2}
	id, err := st.CreateRule(ctx, full)
	if err != nil {
		t.Fatalf("create tls rule after migration: %v", err)
	}
	got, err := st.GetRule(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != "tls" || got.GuardDeny != full.GuardDeny || got.MaxConnsPerIP != 3 || got.BandwidthKBps != 100 ||
		got.Backends != full.Backends || got.LBStrategy != "failover" || got.ProxyProtocol != 2 {
		t.Errorf("new fields roundtrip failed: %+v", got)
	}
	if _, err := st.CreateRule(ctx, Rule{ClientID: "c1", Name: "range", Protocol: "udp", LocalPort: 30000, RemotePort: 30000, RemotePortEnd: 30009}); err != nil {
		t.Fatalf("create port range rule: %v", err)
	}
	st.Close()

	// 迁移幂等：再次打开不报错、不丢数据。
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen migrated db: %v", err)
	}
	defer st2.Close()
	rules, err = st2.ListRulesForClient(ctx, "c1")
	if err != nil || len(rules) != 5 {
		t.Fatalf("rules after reopen: %d %v", len(rules), err)
	}
	var ddl string
	if err := st2.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'rules'`).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ddl, "'tls'") || strings.Contains(strings.ToUpper(ddl), "UNIQUE") {
		t.Errorf("rules DDL not migrated: %s", ddl)
	}
}
