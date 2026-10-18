//go:build linux

package controlconn

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"opennofrp/client/internal/config"
)

func TestRunOnceCancellationDuringTLSHandshake(t *testing.T) {
	t.Setenv("OPENNOFRP_CREDENTIALS", filepath.Join(t.TempDir(), "credentials.toml"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	c := Client{Cfg: &config.Config{Server: config.ServerConfig{Addr: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.runOnce(ctx) }()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("client did not connect")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancellation error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled connection remained blocked")
	}
}

func TestReconnectBackoffResetsAfterEstablishedSession(t *testing.T) {
	c := Client{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts []time.Time
	c.runReconnectLoop(ctx, func(context.Context) error {
		attempts = append(attempts, time.Now())
		if len(attempts) == 3 {
			c.connectionEstablished = true
		}
		if len(attempts) == 4 {
			cancel()
		}
		return io.ErrUnexpectedEOF
	}, 50*time.Millisecond, 400*time.Millisecond)
	if len(attempts) != 4 {
		t.Fatalf("attempts: %d", len(attempts))
	}
	failureDelay := attempts[2].Sub(attempts[1])
	resetDelay := attempts[3].Sub(attempts[2])
	if failureDelay < 90*time.Millisecond {
		t.Fatalf("consecutive failures did not back off: %v", failureDelay)
	}
	if resetDelay >= 150*time.Millisecond {
		t.Fatalf("successful session did not reset backoff: %v", resetDelay)
	}
}
