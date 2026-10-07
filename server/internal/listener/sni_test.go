package listener

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"opennofrp/pkg/protocol"
	"opennofrp/server/internal/session"
)

func TestMatchSNIRoute(t *testing.T) {
	routes := []tlsPassRoute{
		{RuleID: 1},
		{RuleID: 2, Domains: []string{"a.test"}},
		{RuleID: 3, Domains: []string{"*.b.test"}},
	}
	cases := []struct {
		sni  string
		want uint32
	}{
		{"a.test", 2},
		{"A.TEST", 2},
		{"x.b.test", 3},
		{"other.org", 1},
		{"", 1},
	}
	for _, c := range cases {
		got, ok := matchSNIRoute(routes, c.sni)
		if !ok || got.RuleID != c.want {
			t.Errorf("matchSNIRoute(%q) = %d,%v want %d", c.sni, got.RuleID, ok, c.want)
		}
	}
	if _, ok := matchSNIRoute(routes[1:], ""); ok {
		t.Errorf("no-SNI connection should not match without fallback route")
	}
}

func TestTLSPassthroughE2E(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("passthrough-ok"))
	}))
	defer backend.Close()

	a, b := net.Pipe()
	srvYm, err := yamux.Server(a, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	cliYm, err := yamux.Client(b, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer srvYm.Close()
	defer cliYm.Close()

	gotSNI := make(chan string, 1)
	go func() {
		for {
			st, err := cliYm.AcceptStream()
			if err != nil {
				return
			}
			go func(st net.Conn) {
				defer st.Close()
				meta, err := protocol.ReadStreamMetadata(st)
				if err != nil {
					return
				}
				select {
				case gotSNI <- meta.SNI:
				default:
				}
				up, err := net.Dial("tcp", backend.Listener.Addr().String())
				if err != nil {
					st.Write([]byte{protocol.DialAckFailed})
					return
				}
				defer up.Close()
				st.Write([]byte{protocol.DialAckOK})
				done := make(chan struct{}, 2)
				go func() { io.Copy(up, st); done <- struct{}{} }()
				go func() { io.Copy(st, up); done <- struct{}{} }()
				<-done
			}(st)
		}
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sess := session.New("s", "c1", srvYm, logger, nil)
	sess.Capabilities = []string{protocol.CapDialAck, protocol.CapSNIHint}
	m := NewManager("127.0.0.1", logger, func(string) *session.Session { return sess })
	if err := m.openTLSPassPort(0, []tlsPassRoute{{RuleID: 5, ClientID: "c1", Domains: []string{"a.test"}}}); err != nil {
		t.Fatal(err)
	}
	defer m.closeTLSPassPort(0)
	addr := m.tlsPass[0].ln.Addr().String()

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "a.test", InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "passthrough-ok" {
		t.Fatalf("passthrough: %d %q", resp.StatusCode, body)
	}
	if sni := <-gotSNI; sni != "a.test" {
		t.Errorf("SNI hint = %q, want a.test", sni)
	}

	// unknown SNI: connection must be closed without reaching the backend
	bad := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "nope.test", InsecureSkipVerify: true},
	}}
	if _, err := bad.Get("https://" + addr + "/"); err == nil {
		t.Errorf("expected failure for unknown SNI")
	}
}
