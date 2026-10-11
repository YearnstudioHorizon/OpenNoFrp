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
