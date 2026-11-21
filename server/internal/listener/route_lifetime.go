package listener

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"opennofrp/pkg/netrelay"
)

// A route generation owns its backend streams and hijacked sockets. Removing
// it cancels requests and closes only those connections, even on shared ports.
type routeLifetime struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	conns  map[*releaseConn]struct{}
}

func newRouteLifetime() *routeLifetime {
	ctx, cancel := context.WithCancel(context.Background())
	return &routeLifetime{ctx: ctx, cancel: cancel, conns: make(map[*releaseConn]struct{})}
}

func (l *routeLifetime) track(conn net.Conn, release func()) (net.Conn, error) {
	c := &releaseConn{Conn: conn}
	l.mu.Lock()
	if l.ctx.Err() != nil || len(l.conns) >= 256 {
		l.mu.Unlock()
		conn.Close()
		release()
		return nil, net.ErrClosed
	}
	c.release = func() {
		l.mu.Lock()
		delete(l.conns, c)
		l.mu.Unlock()
		release()
	}
	l.conns[c] = struct{}{}
	l.mu.Unlock()
	return c, nil
}

func (l *routeLifetime) stop() {
	l.cancel()
	l.mu.Lock()
	conns := make([]*releaseConn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	for _, c := range conns {
		_ = c.SetDeadline(time.Now())
		c.Close()
	}
}

type trackedResponse struct {
	http.ResponseWriter
	route *routeLifetime
	idle  time.Duration
}

func (w trackedResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w trackedResponse) Write(p []byte) (int, error) {
	_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(w.idle))
	return w.ResponseWriter.Write(p)
}

func (w trackedResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	_ = c.SetDeadline(time.Now().Add(w.idle))
	tracked, err := w.route.track(&activityConn{Conn: c, idle: w.idle}, func() {})
	return tracked, rw, err
}

type publicListener struct {
	net.Listener
	global chan struct{}
}

func (l publicListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.global <- struct{}{}:
			c = &releaseConn{Conn: c, release: func() { <-l.global }}
			return c, nil
		default:
			c.Close()
		}
	}
}

type activityConn struct {
	net.Conn
	idle time.Duration
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

func (c *activityConn) CloseWrite() error { return netrelay.CloseWrite(c.Conn) }
