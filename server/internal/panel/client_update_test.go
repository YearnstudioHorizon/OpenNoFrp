package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"opennofrp/pkg/protocol"
)

func TestClientUpdateAuthorizationAndCapabilities(t *testing.T) {
	p, _ := captchaTestPanel(t)
	id, _, err := p.Store.CreateClient(context.Background(), "update machine")
	if err != nil {
		t.Fatal(err)
	}
	online := true
	caps := []string{protocol.CapSelfUpdate}
	calls := 0
	p.ClientStatus = func(string) (bool, string, []string) { return online, "v0.4.1", caps }
	p.UpdateClient = func(ctx context.Context, got string) (string, error) {
		if got != id {
			t.Fatal("wrong update target")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing task timeout")
		}
		calls++
		return "升级完成", nil
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	cookie := login(t, srv)
	_, page := do(t, "GET", srv.URL+"/clients/"+id, cookie, nil)
	csrf := csrfRe.FindStringSubmatch(page)[1]
	if !strings.Contains(page, "一键更新 Client") {
		t.Fatal("missing update entry")
	}
	endpoint := srv.URL + "/clients/" + id + "/update"
	resp, _ := do(t, "POST", endpoint, nil, url.Values{"csrf_token": {csrf}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatal("unauthenticated update allowed")
	}
	resp, _ = do(t, "POST", endpoint, cookie, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatal("csrf bypass")
	}
	for _, state := range []string{"offline", "legacy", "ready"} {
		online = state != "offline"
		caps = []string{protocol.CapSelfUpdate}
		if state == "legacy" {
			caps = nil
		}
		resp, _ = do(t, "POST", endpoint, cookie, url.Values{"csrf_token": {csrf}})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatal("wrong response")
		}
		if strings.Contains(resp.Header.Get("Location"), "?ok=") != (state == "ready") {
			t.Fatal("wrong update outcome", state)
		}
	}
	if calls != 1 {
		t.Fatal("unsupported update dispatched", calls)
	}
}
