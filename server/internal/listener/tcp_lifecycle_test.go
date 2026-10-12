package listener

import (
	"github.com/hashicorp/yamux"
	"io"
	"log/slog"
	"net"
	"opennofrp/pkg/protocol"
	"opennofrp/server/internal/session"
	"sync"
	"testing"
	"time"
)

func lifecycleManager(t *testing.T) (*Manager, *yamux.Session) {
	t.Helper()
	a, b := net.Pipe()
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	server, err := yamux.Server(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, err := yamux.Client(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sess := session.New("test", "client", server, logger, nil)
	m := NewManager("127.0.0.1", logger, func(string) *session.Session { return sess })
	t.Cleanup(func() { m.ClosePort("tcp", 0); server.Close(); client.Close() })
	if err := m.OpenRule(RuleView{ID: 1, ClientID: "client", Protocol: "tcp", Port: 0}); err != nil {
		t.Fatal(err)
	}
	return m, client
}

func dialLifecycle(t *testing.T, m *Manager, client *yamux.Session) (net.Conn, *yamux.Stream) {
	t.Helper()
	m.mu.Lock()
	addr := m.tcp[0].ln.Addr().String()
	m.mu.Unlock()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	stream, err := client.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })
	stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := protocol.ReadStreamMetadata(stream); err != nil {
		t.Fatal(err)
	}
	stream.SetReadDeadline(time.Time{})
	return conn, stream
}

func TestDisableTCPClosesExistingConnectionsAndReopen(t *testing.T) {
	m, client := lifecycleManager(t)
	for cycle := 0; cycle < 10; cycle++ {
		conn, stream := dialLifecycle(t, m, client)
		m.ClosePort("tcp", 0)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("disabled socket: %v", err)
		}
		stream.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := stream.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("disabled stream: %v", err)
		}
		m.mu.Lock()
		active := m.tcpActive
		m.mu.Unlock()
		if active != 0 {
			t.Fatalf("retained %d connection slots", active)
		}
		if err := m.OpenRule(RuleView{ID: 1, ClientID: "client", Protocol: "tcp", Port: 0}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTCPConnectionLimitAndRelease(t *testing.T) {
	m, client := lifecycleManager(t)
	m.MaxTCPConnections = 1
	conn, stream := dialLifecycle(t, m, client)
	m.mu.Lock()
	addr := m.tcp[0].ln.Addr().String()
	m.mu.Unlock()
	rejected, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer rejected.Close()
	rejected.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := rejected.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("over-limit socket: %v", err)
	}
	conn.Close()
	stream.Close()
	until := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		n := m.tcpActive
		m.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("slot not released")
		}
		time.Sleep(time.Millisecond)
	}
	dialLifecycle(t, m, client)
}

func TestTCPIdleConnectionExpires(t *testing.T) {
	m, client := lifecycleManager(t)
	m.TCPIdleTimeout = 50 * time.Millisecond
	conn, stream := dialLifecycle(t, m, client)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("idle socket: %v", err)
	}
	stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("idle stream: %v", err)
	}
}

func TestTCPDisableRacesAccept(t *testing.T) {
	m, client := lifecycleManager(t)
	// Drain peer streams so opening them cannot block the accept loop.
	go func() {
		for {
			stream, err := client.AcceptStream()
			if err != nil {
				return
			}
			stream.Close()
		}
	}()
	for cycle := 0; cycle < 20; cycle++ {
		m.mu.Lock()
		addr := m.tcp[0].ln.Addr().String()
		m.mu.Unlock()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _ := net.DialTimeout("tcp", addr, time.Second)
			if c != nil {
				c.Close()
			}
		}()
		m.ClosePort("tcp", 0)
		wg.Wait()
		if err := m.OpenRule(RuleView{ID: 1, ClientID: "client", Protocol: "tcp", Port: 0}); err != nil {
			t.Fatal(err)
		}
	}
}
