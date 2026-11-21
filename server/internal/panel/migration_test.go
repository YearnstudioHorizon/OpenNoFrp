package panel

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opennofrp/server/internal/store"
)

// newMigrationTestPanel 构造一个带迁移路径的面板测试服务器。
func newMigrationTestPanel(t *testing.T, st *store.Store, dir string) *httptest.Server {
	t.Helper()
	p := New(st, slog.Default(), nil, "https://panel.example.test", "127.0.0.1", 17000, "", filepath.Join(dir, "bins"))
	p.MigrationPaths = &MigrationPaths{
		ConfigFile: filepath.Join(dir, "server.toml"),
		DBPath:     filepath.Join(dir, "opennofrp.db"),
		TLSCert:    filepath.Join(dir, "server.crt"),
		TLSKey:     filepath.Join(dir, "server.key"),
		ACMEDir:    filepath.Join(dir, "acme"),
		DataDir:    dir,
	}
	_, loopback, _ := net.ParseCIDR("127.0.0.1/32")
	p.TrustedProxies = []*net.IPNet{loopback}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-Proto", "https")
		p.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMigrationTokenLifecycleAndBundle(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	st, err := store.Open(filepath.Join(dir, "opennofrp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateAdmin(ctx, "admin", "pass1234"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateClient(ctx, "box"); err != nil {
		t.Fatal(err)
	}

	// 模拟已有的配置与证书文件。
	if err := os.WriteFile(filepath.Join(dir, "server.toml"), []byte("[server]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "acme", "cert.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := newMigrationTestPanel(t, st, dir)

	// 1. 未登录不能创建迁移令牌。
	if resp, _ := do(t, "POST", srv.URL+"/migration-token", nil, url.Values{}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unauthenticated migration-token = %d, want redirect", resp.StatusCode)
	}

	cookie := login(t, srv)
	resp, page := do(t, "GET", srv.URL+"/account", cookie, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /account = %d", resp.StatusCode)
	}
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no csrf token on account page")
	}

	// 2. 面板创建迁移令牌并渲染迁移命令。
	resp, page = do(t, "POST", srv.URL+"/migration-token", cookie, url.Values{"csrf_token": {m[1]}})
	if resp.StatusCode != 200 {
		t.Fatalf("POST migration-token = %d", resp.StatusCode)
	}
	if !strings.Contains(page, "/migrate.sh?token=") || !strings.Contains(page, "id=\"migration\"") {
		t.Fatal("migration command not rendered")
	}
	tok := extractToken(t, page)

	// 3. /migrate.sh 无需登录（新机器上没有旧面板的会话），仅凭令牌获取脚本。
	resp, script := do(t, "GET", srv.URL+"/migrate.sh?token="+tok, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET migrate.sh = %d", resp.StatusCode)
	}
	if !strings.Contains(script, "opennofrp-server") || !strings.Contains(script, tok) {
		t.Fatal("migrate script incomplete")
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = strings.NewReader(script)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("migration script has invalid shell syntax: %v: %s", err, output)
		}
	}
	// 坏令牌格式被拒绝。
	if resp, _ := do(t, "GET", srv.URL+"/migrate.sh?token=bad!token", nil, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("migrate.sh with invalid token = %d, want 400", resp.StatusCode)
	}

	// 4. 一次性下载数据 bundle。
	resp, bundle := do(t, "GET", srv.URL+"/migrate/data?token="+tok, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET migrate/data = %d", resp.StatusCode)
	}
	names := readBundleNames(t, strings.NewReader(bundle))
	want := map[string]bool{"server.toml": false, "opennofrp.db": false, "server.key": false, "acme/cert.json": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("bundle missing %s", n)
		}
	}

	// 5. 令牌已被消费：重复下载被拒绝。
	if resp, _ := do(t, "GET", srv.URL+"/migrate/data?token="+tok, nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reused migration token = %d, want 403", resp.StatusCode)
	}
	if resp, _ := do(t, "GET", srv.URL+"/migrate/data?token=000000000000000000000000000000000000000000000000", nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("unknown migration token = %d, want 403", resp.StatusCode)
	}
}

func extractToken(t *testing.T, page string) string {
	t.Helper()
	i := strings.Index(page, "/migrate.sh?token=")
	if i < 0 {
		t.Fatal("migration command not found")
	}
	rest := page[i+len("/migrate.sh?token="):]
	end := strings.IndexAny(rest, "\"&'")
	if end < 0 {
		t.Fatal("unterminated token")
	}
	return rest[:end]
}

func readBundleNames(t *testing.T, r io.Reader) []string {
	t.Helper()
	gz, err := gzip.NewReader(r)
	if err != nil {
		t.Fatalf("bundle is not gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read bundle entry: %v", err)
		}
		names = append(names, hdr.Name)
	}
	return names
}

func TestMigrationTokenStoreSemantics(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	tok, err := st.CreateMigrationToken(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 32 {
		t.Fatalf("token too short: %q", tok)
	}
	// 未消费前可校验成功一次；消费后拒绝重复使用。
	if err := st.ConsumeMigrationToken(ctx, tok); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if err := st.ConsumeMigrationToken(ctx, tok); err == nil {
		t.Fatal("second consume must fail")
	}
	// 过期令牌被拒绝。
	expired, err := st.CreateMigrationToken(ctx, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ConsumeMigrationToken(ctx, expired); err == nil {
		t.Fatal("expired token must be rejected")
	}
	// 不存在的令牌被拒绝。
	if err := st.ConsumeMigrationToken(ctx, "doesnotexist1234"); err == nil {
		t.Fatal("missing token must be rejected")
	}
}
