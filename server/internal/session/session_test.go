package session

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"opennofrp/pkg/protocol"
)

func newPair(t *testing.T) (*Session, *yamux.Session) {
	t.Helper()
	a, b := net.Pipe()
	srv, err := yamux.Server(a, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	cli, err := yamux.Client(b, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close(); cli.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New("s1", "c1", srv, logger, nil), cli
}

func TestHasCapability(t *testing.T) {
	s := &Session{Capabilities: []string{protocol.CapDialAck}}
	if !s.HasCapability(protocol.CapDialAck) || s.HasCapability(protocol.CapSNIHint) {
		t.Errorf("HasCapability mismatch")
	}
}

func TestOpenAckStream(t *testing.T) {
	sess, cli := newPair(t)
	for _, tc := range []struct {
		ack     byte
		wantErr bool
	}{{protocol.DialAckOK, false}, {protocol.DialAckFailed, true}} {
		metaCh := make(chan protocol.StreamMetadata, 1)
		go func(ack byte) {
			st, err := cli.AcceptStream()
			if err != nil {
				return
			}
			m, err := protocol.ReadStreamMetadata(st)
			if err != nil {
				return
			}
			metaCh <- m
			st.Write([]byte{ack})
			if ack == protocol.DialAckOK {
				buf := make([]byte, 4)
				io.ReadFull(st, buf)
				st.Write(buf)
			}
		}(tc.ack)
		c, err := sess.OpenAckStream(net.ParseIP("9.9.9.9"), 4321, 7, "a.test", 5*time.Second)
		m := <-metaCh
		if m.RuleID != 7 || m.ClientPort != 4321 || !m.ClientAddr.Equal(net.ParseIP("9.9.9.9")) || m.SNI != "a.test" || !m.HasFlag(protocol.FlagDialAck) {
			t.Errorf("metadata = %+v", m)
		}
		if tc.wantErr {
			if !errors.Is(err, ErrBackendUnavailable) {
				t.Errorf("want ErrBackendUnavailable, got %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("ping"))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Errorf("echo = %q %v", buf, err)
		}
		c.Close()
	}
}

func TestOpenAckStreamTimeout(t *testing.T) {
	sess, cli := newPair(t)
	go func() {
		st, err := cli.AcceptStream()
		if err == nil {
			protocol.ReadStreamMetadata(st) // 不回写确认
		}
	}()
	start := time.Now()
	_, err := sess.OpenHTTPStream(nil, 0, 1, 200*time.Millisecond)
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Errorf("want ErrBackendUnavailable on timeout, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("timeout not honored")
	}
}

func TestOpenUDPStreamOffset(t *testing.T) {
	sess, cli := newPair(t)
	metaCh := make(chan protocol.StreamMetadata, 1)
	go func() {
		st, err := cli.AcceptStream()
		if err != nil {
			return
		}
		m, _ := protocol.ReadStreamMetadata(st)
		metaCh <- m
	}()
	st, err := sess.OpenUDPStreamOffset(&net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 53}, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := <-metaCh
	if m.Transport != protocol.TransportUDP || m.RuleID != 3 || m.PortOffset != 5 || m.ClientPort != 53 {
		t.Errorf("udp metadata = %+v", m)
	}
}
