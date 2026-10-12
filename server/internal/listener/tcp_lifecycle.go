package listener

import (
	"net"
	"opennofrp/pkg/netrelay"
	"sync"
	"time"
)

// Track public sockets even while opening the backend stream, so disabling a
// rule cancels both pending and established forwards.
type trackedTCPConn struct {
	net.Conn
	listener *tcpListener
	manager  *Manager
	once     sync.Once
	idle     time.Duration
}

func (m *Manager) acquireTCP() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tcpActive >= m.MaxTCPConnections {
		return false
	}
	m.tcpActive++
	return true
}

func (tl *tcpListener) track(c *trackedTCPConn) bool {
	tl.connMu.Lock()
	defer tl.connMu.Unlock()
	if tl.closed {
		return false
	}
	tl.conns[c] = struct{}{}
	return true
}

func (tl *tcpListener) stop() {
	tl.connMu.Lock()
	if tl.closed {
		tl.connMu.Unlock()
		return
	}
	tl.closed = true
	close(tl.done)
	conns := make([]*trackedTCPConn, 0, len(tl.conns))
	for c := range tl.conns {
		conns = append(conns, c)
	}
	tl.connMu.Unlock()
	tl.ln.Close()
	// Never close tracked sockets while holding either manager or listener locks.
	for _, c := range conns {
		c.Close()
	}
}

func (c *trackedTCPConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.listener.connMu.Lock()
		delete(c.listener.conns, c)
		c.listener.connMu.Unlock()
		c.manager.mu.Lock()
		c.manager.tcpActive--
		c.manager.mu.Unlock()
	})
	return err
}

// Both directions refresh the same deadline: a long one-way transfer stays
// alive, but a silent peer cannot retain a relay and stream indefinitely.
func (c *trackedTCPConn) touch() {
	if c.idle > 0 {
		_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
}
func (c *trackedTCPConn) Read(p []byte) (int, error) {
	c.touch()
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}
func (c *trackedTCPConn) Write(p []byte) (int, error) {
	c.touch()
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}
func (c *trackedTCPConn) CloseWrite() error { return netrelay.CloseWrite(c.Conn) }
