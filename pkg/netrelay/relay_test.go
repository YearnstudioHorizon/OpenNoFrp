package netrelay

import (
	"github.com/hashicorp/yamux"
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a, err := ln.Accept()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); a.Close() })
	c.SetDeadline(time.Now().Add(3 * time.Second))
	a.SetDeadline(time.Now().Add(3 * time.Second))
	return a.(*net.TCPConn), c.(*net.TCPConn)
}

func TestRelayHalfCloseThroughYamux(t *testing.T) {
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
	defer server.Close()
	defer client.Close()
	local, err := server.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := client.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(3 * time.Second))
	public, visitor := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- Relay(public, local) }()
	if _, err := visitor.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := visitor.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(remote)
	if err != nil || string(request) != "request" {
		t.Fatalf("request %q: %v", request, err)
	}
	if _, err := remote.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := remote.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(visitor)
	if err != nil || string(response) != "response" {
		t.Fatalf("response %q: %v", response, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not finish")
	}
}

func TestRelayErrorAfterEOFClosesOtherDirection(t *testing.T) {
	a, peer := tcpPair(t)
	b, service := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- Relay(a, b) }()
	peer.CloseWrite()
	// Service waits for request EOF before provoking a read error in the relay.
	if _, err := io.ReadAll(service); err != nil {
		t.Fatal(err)
	}
	b.SetReadDeadline(time.Now())
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("missing read error")
		}
	case <-time.After(time.Second):
		t.Fatal("relay blocked after EOF followed by error")
	}
}
