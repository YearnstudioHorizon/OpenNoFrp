package listener

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"opennofrp/pkg/protocol"
	"opennofrp/server/internal/session"
)

// fakeClient emulates the opennofrp-client side: accepts streams, reads the
// metadata, dials backendAddr, writes the dial ack and relays bytes.
func fakeClient(t *testing.T, ym *yamux.Session, backendAddr string) {
	for {
		st, err := ym.AcceptStream()
		if err != nil {
			return
		}
		go func(st net.Conn) {
			defer st.Close()
			meta, err := protocol.ReadStreamMetadata(st)
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", backendAddr)
			if err != nil {
				if meta.HasFlag(protocol.FlagDialAck) {
					st.Write([]byte{protocol.DialAckFailed})
				}
				return
			}
			defer up.Close()
			if meta.HasFlag(protocol.FlagDialAck) {
				st.Write([]byte{protocol.DialAckOK})
			}
			done := make(chan struct{}, 2)
			go func() { io.Copy(up, st); done <- struct{}{} }()
			go func() { io.Copy(st, up); done <- struct{}{} }()
			<-done
		}(st)
	}
}

func setupHTTPProxy(t *testing.T, backendAddr string, offline string, clientOnline bool) string {
	t.Helper()
	a, b := net.Pipe()
	srvYm, err := yamux.Server(a, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	cliYm, err := yamux.Client(b, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srvYm.Close(); cliYm.Close() })
	go fakeClient(t, cliYm, backendAddr)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sess := session.New("s", "c1", srvYm, logger, nil)
	m := NewManager("127.0.0.1", logger, func(id string) *session.Session {
		if clientOnline && id == "c1" {
			return sess
		}
		return nil
	})
	if err := m.openHTTPPort(0, []httpRoute{{RuleID: 1, ClientID: "c1", Name: "svc", Domains: []string{"a.test"}, PathPrefix: "/", OfflinePage: offline}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.closeHTTPPort(0) })
	return m.http[0].ln.Addr().String()
}

func doGet(t *testing.T, addr, host, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
	req.Host = host
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHTTPProxyE2E(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			for i := 0; i < 2; i++ {
				fmt.Fprintf(w, "data: %d\n\n", i)
				w.(http.Flusher).Flush()
				time.Sleep(300 * time.Millisecond)
			}
		case "/ws":
			if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				http.Error(w, "no upgrade", 400)
				return
			}
			conn, brw, _ := w.(http.Hijacker).Hijack()
			defer conn.Close()
			brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			brw.Flush()
			line, _ := brw.ReadString('\n')
			brw.WriteString("echo:" + line)
			brw.Flush()
		default:
			fmt.Fprintf(w, "host=%s xff=%s", r.Host, r.Header.Get("X-Forwarded-For"))
		}
	}))
	defer backend.Close()
	addr := setupHTTPProxy(t, backend.Listener.Addr().String(), "", true)

	// plain request
	resp := doGet(t, addr, "a.test", "/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "host=a.test") || !strings.Contains(string(body), "xff=127.0.0.1") {
		t.Fatalf("plain: %d %q", resp.StatusCode, body)
	}

	// unknown host -> 404
	resp = doGet(t, addr, "b.test", "/")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("unknown host: %d", resp.StatusCode)
	}

	// SSE: first event must arrive before the stream ends
	resp = doGet(t, addr, "a.test", "/sse")
	start := time.Now()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "data: 0\n" || time.Since(start) > 250*time.Millisecond {
		t.Fatalf("sse first event: %q %v after %v", line, err, time.Since(start))
	}
	resp.Body.Close()

	// WebSocket-style upgrade
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET /ws HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	cr := bufio.NewReader(c)
	status, _ := cr.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("ws status: %q", status)
	}
	for {
		l, err := cr.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" {
			break
		}
	}
	fmt.Fprintf(c, "hello\n")
	echo, _ := cr.ReadString('\n')
	if echo != "echo:hello\n" {
		t.Fatalf("ws echo: %q", echo)
	}
}

func TestHTTPProxyBackendDown(t *testing.T) {
	// reserve a port then close it so dialing fails
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()

	addr := setupHTTPProxy(t, dead, "<h1>maintenance</h1>", true)
	resp := doGet(t, addr, "a.test", "/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 || string(body) != "<h1>maintenance</h1>" {
		t.Fatalf("backend down: %d %q", resp.StatusCode, body)
	}

	addr2 := setupHTTPProxy(t, dead, "", false)
	resp = doGet(t, addr2, "a.test", "/")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 || !strings.Contains(string(body), "svc") {
		t.Fatalf("client offline: %d %q", resp.StatusCode, body)
	}
}
