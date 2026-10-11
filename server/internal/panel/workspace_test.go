package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"opennofrp/server/internal/store"
)

func TestWorkspacePagesAndDedicatedRuleEditor(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "workspace.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateAdmin(ctx, "admin", "pass1234"); err != nil {
		t.Fatal(err)
	}
	clientID, _, err := st.CreateClient(ctx, "test machine")
	if err != nil {
		t.Fatal(err)
	}
	otherID, _, err := st.CreateClient(ctx, "other machine")
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := st.CreateRule(ctx, store.Rule{ClientID: clientID, Name: "existing tunnel", Protocol: "tcp", LocalIP: "127.0.0.1", LocalPort: 22, RemotePort: 18022})
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestPanel(t, st)
	cookie := login(t, srv)
	sections := []string{"clients-table", `id="onboard"`, `id="reserved"`, `id="api-tokens"`, `id="account"`}
	for _, tc := range []struct{ path, title, marker string }{{"/", "工作空间概览", ""}, {"/clients", "内网机器", "clients-table"}, {"/onboard", "接入新机器", `id="onboard"`}, {"/reserved", "保留端口", `id="reserved"`}, {"/api-tokens", "API 令牌", `id="api-tokens"`}, {"/account", "账号设置", `id="account"`}} {
		t.Run(tc.path, func(t *testing.T) {
			resp, page := do(t, "GET", srv.URL+tc.path, cookie, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if !strings.Contains(page, "<h1>"+tc.title+"</h1>") {
				t.Fatal("missing page title")
			}
			for _, marker := range sections {
				if strings.Contains(page, marker) != (marker == tc.marker) {
					t.Fatalf("unexpected section %s on %s", marker, tc.path)
				}
			}
		})
	}
	resp, listPage := do(t, "GET", srv.URL+"/clients/"+clientID, cookie, nil)
	if resp.StatusCode != 200 || !strings.Contains(listPage, `id="rules-table"`) || strings.Contains(listPage, `id="rule-editor"`) {
		t.Fatal("machine page should contain only its rule list")
	}
	for _, path := range []string{"/clients/" + clientID + "/rules/new", fmt.Sprintf("/clients/%s/rules/%d/edit", clientID, ruleID), fmt.Sprintf("/clients/%s?edit=%d", clientID, ruleID)} {
		resp, page := do(t, "GET", srv.URL+path, cookie, nil)
		if resp.StatusCode != 200 || !strings.Contains(page, `id="rule-editor"`) || strings.Contains(page, `id="rules-table"`) {
			t.Fatalf("editor isolation failed: %s", path)
		}
	}
	resp, _ = do(t, "GET", fmt.Sprintf("%s/clients/%s/rules/%d/edit", srv.URL, otherID, ruleID), cookie, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("cross-client editor status %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", srv.URL+"/unknown-page", cookie, nil)
	if resp.StatusCode != 404 {
		t.Fatalf("unknown page status %d", resp.StatusCode)
	}
	_, page := do(t, "GET", srv.URL+"/clients/"+clientID+"/rules/new", cookie, nil)
	csrf := csrfRe.FindStringSubmatch(page)[1]
	resp, _ = do(t, "POST", srv.URL+"/reserved/add", cookie, url.Values{"csrf_token": {csrf}, "port": {"12345"}, "reason": {"test"}})
	if resp.Header.Get("Location") != "/reserved" {
		t.Fatal("reserved operation should return to reserved page")
	}
	resp, _ = do(t, "POST", srv.URL+"/clients/"+clientID+"/rules", cookie, url.Values{"csrf_token": {csrf}, "name": {"bad"}, "protocol": {"tcp"}, "local_ip": {"127.0.0.1"}, "local_port": {"0"}, "remote_port": {"19000"}})
	if !strings.HasPrefix(resp.Header.Get("Location"), "/clients/"+clientID+"/rules/new?err=") {
		t.Fatal("invalid creation should return to the dedicated guide")
	}
}
