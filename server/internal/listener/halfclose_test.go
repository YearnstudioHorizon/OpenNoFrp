package listener

import (
	"io"
	"net"
	"opennofrp/pkg/netrelay"
	"testing"
	"time"
)

func TestWrappedPublicConnCloseWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	peer.SetDeadline(time.Now().Add(time.Second))
	released := false
	wrapped := newRuleGuard(GuardConfig{BandwidthKBps: 1024}).wrapConn(&countingConn{Conn: &releaseConn{Conn: conn, release: func() { released = true }}, c: &ruleCounters{}})
	if err := netrelay.CloseWrite(wrapped); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := peer.Read(buf[:]); err != io.EOF {
		t.Fatalf("expected EOF: %v", err)
	}
	if released {
		t.Fatal("half-close released active connection")
	}
	peer.Write([]byte("x"))
	if _, err := wrapped.Read(buf[:]); err != nil || buf[0] != 'x' {
		t.Fatalf("reverse direction lost: %v", err)
	}
	wrapped.Close()
	if !released {
		t.Fatal("full close did not release connection")
	}
}
