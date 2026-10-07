package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"opennofrp/server/internal/store"
)

var apiTokenRe = regexp.MustCompile(`<pre id="apitoken">(onfr_[0-9a-f]+)</pre>`)

func apiDo(t *testing.T, method, u, token, body string) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, u, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func createAPIToken(t *testing.T, srvURL string, cookie *http.Cookie, csrf string, readOnly bool) string {
	t.Helper()
	form := url.Values{"name": {"test"}, "csrf_token": {csrf}}
	if readOnly {
		form.Set("read_only", "1")
	}
	resp, page := do(t, "POST", srvURL+"/api-tokens", cookie, form)
	if resp.StatusCode != 200 {
		t.Fatalf("create api token = %d", resp.StatusCode)
	}
	m := apiTokenRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("new api token not shown on page")
	}
	return m[1]
}

func TestRESTAPI(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.CreateAdmin(ctx, "admin", "pass1234"); err != nil {
		t.Fatal(err)
	}
	clientID, _, err := st.CreateClient(ctx, "box")
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestPanel(t, st)
	cookie := login(t, srv)
	_, page := do(t, "GET", srv.URL+"/", cookie, nil)
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no csrf token")
	}
	csrf := m[1]

	rw := createAPIToken(t, srv.URL, cookie, csrf, false)
	ro := createAPIToken(t, srv.URL, cookie, csrf, true)

	if code, _ := apiDo(t, "GET", srv.URL+"/api/v1/clients", "", ""); code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", code)
	}
	if code, _ := apiDo(t, "GET", srv.URL+"/api/v1/clients", "onfr_bogus", ""); code != http.StatusUnauthorized {
		t.Errorf("bad token = %d, want 401", code)
	}
	code, out := apiDo(t, "GET", srv.URL+"/api/v1/clients", ro, "")
	if code != 200 {
		t.Fatalf("list clients = %d %v", code, out)
	}
	if cl, _ := out["clients"].([]any); len(cl) != 1 {
		t.Errorf("clients = %v", out["clients"])
	}

	body := `{"name":"ssh","protocol":"tcp","local_ip":"127.0.0.1","local_port":22,"remote_port":2222,"enabled":true}`
	if code, _ := apiDo(t, "POST", srv.URL+"/api/v1/clients/"+clientID+"/rules", ro, body); code != http.StatusForbidden {
		t.Errorf("read-only create = %d, want 403", code)
	}
	code, out = apiDo(t, "POST", srv.URL+"/api/v1/clients/"+clientID+"/rules", rw, body)
	if code != http.StatusCreated {
		t.Fatalf("create rule = %d %v", code, out)
	}
	rule, _ := out["rule"].(map[string]any)
	id, _ := rule["id"].(float64)
	if id == 0 || rule["remote_port"].(float64) != 2222 || rule["enabled"] != true {
		t.Fatalf("created rule = %v", rule)
	}
	ruleURL := srv.URL + "/api/v1/rules/" + strings.TrimSuffix(strings.TrimSuffix(json.Number(jsonNum(id)).String(), ".0"), ".")

	if code, out := apiDo(t, "POST", srv.URL+"/api/v1/clients/"+clientID+"/rules", rw, `{"name":"x","protocol":"bogus","local_port":1,"remote_port":1}`); code != http.StatusUnprocessableEntity || out["error"] != "bad protocol" {
		t.Errorf("invalid rule = %d %v", code, out)
	}

	if code, out := apiDo(t, "POST", ruleURL+"/disable", rw, ""); code != 200 || out["enabled"] != false {
		t.Errorf("disable = %d %v", code, out)
	}
	code, out = apiDo(t, "GET", ruleURL, ro, "")
	if code != 200 || out["rule"].(map[string]any)["enabled"] != false {
		t.Errorf("get after disable = %d %v", code, out)
	}
	code, out = apiDo(t, "PUT", ruleURL, rw, `{"name":"ssh2","protocol":"tcp","local_port":22,"remote_port":2223,"enabled":true}`)
	if code != 200 || out["rule"].(map[string]any)["name"] != "ssh2" {
		t.Errorf("update = %d %v", code, out)
	}
	if code, _ := apiDo(t, "GET", srv.URL+"/api/v1/stats", ro, ""); code != 200 {
		t.Errorf("stats = %d", code)
	}
	if code, _ := apiDo(t, "DELETE", ruleURL, rw, ""); code != 200 {
		t.Errorf("delete = %d", code)
	}
	if code, _ := apiDo(t, "GET", ruleURL, ro, ""); code != http.StatusNotFound {
		t.Errorf("get deleted = %d, want 404", code)
	}
}

func jsonNum(f float64) string {
	b, _ := json.Marshal(int64(f))
	return string(b)
}
