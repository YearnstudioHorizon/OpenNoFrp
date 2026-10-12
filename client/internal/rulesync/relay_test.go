package rulesync

import (
	"net"
	"testing"
	"time"
)

func TestRelayErrorClosesTouchedStream(t *testing.T) {
	stream, peer := net.Pipe()
	upstream, service := net.Pipe()
	defer stream.Close()
	defer peer.Close()
	defer upstream.Close()
	defer service.Close()
	done := make(chan struct{})
	go func() {
		relay(&touchConn{Conn: stream}, upstream)
		close(done)
	}()
	// A local service read error must also wake the stream reader.
	upstream.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay stayed blocked after local service error")
	}
}
