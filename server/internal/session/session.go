// Package session manages one connected, registered Client: its control
// stream (heartbeats up, rules snapshots down) plus yamux session lifecycle.
package session

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"opennofrp/pkg/protocol"
)

// Session represents one connected, authenticated Client.
type Session struct {
	ID       string // internal session id (random)
	ClientID string // registered client id this session belongs to
	Yamux    *yamux.Session
	Logger   *slog.Logger

	mu           sync.Mutex
	lastActivity time.Time
	ctrlStream   net.Conn // bidirectional control stream: heartbeats up, snapshots+acks down
}

func New(id, clientID string, ym *yamux.Session, logger *slog.Logger, ctrlStream net.Conn) *Session {
	return &Session{
		ID:           id,
		ClientID:     clientID,
		Yamux:        ym,
		Logger:       logger,
		ctrlStream:   ctrlStream,
		lastActivity: time.Now(),
	}
}

func (s *Session) Touch() {
	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()
}

func (s *Session) IdleFor() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastActivity)
}

// SetControlStream swaps the bidirectional control stream in (called once
// during setup; the previous one, if any, is closed).
func (s *Session) SetControlStream(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctrlStream != nil && s.ctrlStream != c {
		s.ctrlStream.Close()
	}
	s.ctrlStream = c
}

// PushRulesSnapshot forwards a fresh rules snapshot to this Client over the
// control stream. No-op when the control stream is gone; the next handshake
// re-establishes a full snapshot regardless, so a missed push only means a
// briefly stale rule list on the Client until reconnect.
func (s *Session) PushRulesSnapshot(rules []protocol.Rule) error {
	s.mu.Lock()
	c := s.ctrlStream
	s.mu.Unlock()
	if c == nil {
		return nil
	}
	return protocol.WriteJSONMessage(c, protocol.RulesSnapshot{
		Type:  protocol.MsgRulesSnapshot,
		Rules: rules,
	})
}

// OpenStreamFor opens a new yamux stream towards the Client for a freshly
// accepted public TCP connection, writes the StreamMetadata header (so the
// Client knows the original client's address and which rule this connection
// belongs to), then relays bytes bidirectionally until either side closes.
func (s *Session) OpenStreamFor(publicConn net.Conn, ruleID uint32) error {
	stream, err := s.Yamux.Open()
	if err != nil {
		return fmt.Errorf("session: open yamux stream: %w", err)
	}

	ra := publicConn.RemoteAddr()
	tcpAddr, _ := ra.(*net.TCPAddr)
	if tcpAddr == nil {
		stream.Close()
		return fmt.Errorf("session: public conn has non-TCP remote addr")
	}

	meta := protocol.StreamMetadata{
		Transport:  protocol.TransportTCP,
		ClientAddr: tcpAddr.IP,
		ClientPort: uint16(tcpAddr.Port),
		RuleID:     ruleID,
	}
	if err := meta.WriteHeader(stream); err != nil {
		stream.Close()
		return fmt.Errorf("session: write stream metadata: %w", err)
	}

	s.Touch()
	go relay(publicConn, stream, s.Logger)
	return nil
}

// OpenUDPStream opens a yamux stream for one UDP "flow" (identified by its
// source address). The returned stream carries datagrams as frames:
// 2 bytes big-endian length + payload per datagram. The Client wraps the same
// framing onto its local UDP socket, so datagrams cross the control
// connection with boundaries preserved.
func (s *Session) OpenUDPStream(remoteAddr *net.UDPAddr, ruleID uint32) (net.Conn, error) {
	stream, err := s.Yamux.Open()
	if err != nil {
		return nil, fmt.Errorf("session: open yamux stream (udp): %w", err)
	}
	meta := protocol.StreamMetadata{
		Transport:  protocol.TransportUDP,
		ClientAddr: remoteAddr.IP,
		ClientPort: uint16(remoteAddr.Port),
		RuleID:     ruleID,
	}
	if err := meta.WriteHeader(stream); err != nil {
		stream.Close()
		return nil, fmt.Errorf("session: write stream metadata: %w", err)
	}
	s.Touch()
	return stream, nil
}

func relay(publicConn net.Conn, stream net.Conn, logger *slog.Logger) {
	defer publicConn.Close()
	defer stream.Close()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go cp(publicConn, stream)
	go cp(stream, publicConn)
	<-done
}
