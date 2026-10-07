package listener

import (
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

// TestRealIPPropagatedToMetadataAndHeaders checks that the IP extracted per the
// rule's priority list reaches the client via StreamMetadata.ClientAddr (used for
// spoofed source dialing) and the backend via X-Real-IP / X-Forwarded-For.
func TestRealIPPropagatedToMetadataAndHeaders(t *testing.T) {
	gotHeaders := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders <- r.Header.Clone()
		w.Write([]byte("ok"))
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

	gotMeta := make(chan protocol.StreamMetadata, 1)
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
				case gotMeta <- meta:
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
	sess.Capabilities = []string{protocol.CapDialAck}
	m := NewManager("127.0.0.1", logger, func(id string) *session.Session { return sess })
	route := httpRoute{RuleID: 7, ClientID: "c1", PathPrefix: "/",
		IPSources: []string{"cf-connecting-ip", "x-forwarded-for"}, TrustedProxies: mustNets(t, "127.0.0.0/8")}
	if err := m.openHTTPPort(0, []httpRoute{route}); err != nil {
		t.Fatal(err)
	}
	defer m.closeHTTPPort(0)
	addr := m.http[0].ln.Addr().String()

	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	req.Host = "a.test"
	req.Header.Set("CF-Connecting-IP", "203.0.113.9")
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	meta := <-gotMeta
	if !meta.ClientAddr.Equal(net.ParseIP("203.0.113.9")) || meta.RuleID != 7 || !meta.HasFlag(protocol.FlagDialAck) {
		t.Errorf("metadata: %+v", meta)
	}
	h := <-gotHeaders
	if h.Get("X-Real-IP") != "203.0.113.9" || h.Get("X-Forwarded-For") != "198.51.100.1, 127.0.0.1" || h.Get("CF-Connecting-IP") != "203.0.113.9" {
		t.Errorf("headers: %v", h)
	}
	if h.Get("Forwarded") != `for=203.0.113.9;host="a.test";proto=http` {
		t.Errorf("Forwarded: %q", h.Get("Forwarded"))
	}
}
