//go:build darwin

package darwinsource

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Darwin chooses the route's source IP when a wildcard-bound UDP socket
// answers with sendto(). The PF state must use that IP on the backend side,
// or the reply won't match the state created by the incoming datagram.
type udpListeners struct {
	mu    sync.Mutex
	ports map[netip.AddrPort]udpListener
}

type udpListener struct {
	wildcard bool
	expires  time.Time
}

func (l *udpListeners) destination(ctx context.Context, backend, visitor netip.AddrPort) netip.AddrPort {
	if !backend.Addr().IsLoopback() || !l.isWildcard(ctx, backend) {
		return backend
	}
	if visitor.Port() == 0 {
		visitor = netip.AddrPortFrom(visitor.Addr(), 9)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp4", visitor.String())
	if err != nil {
		return backend
	}
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
	conn.Close()
	return netip.AddrPortFrom(local, backend.Port())
}

func (l *udpListeners) isWildcard(ctx context.Context, backend netip.AddrPort) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if c, ok := l.ports[backend]; ok && now.Before(c.expires) {
		return c.wildcard
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	port := strconv.Itoa(int(backend.Port()))
	// Include both families: a dual-stack wildcard socket can be listed as
	// IPv6 even when it also accepts IPv4. An exact bind takes precedence.
	out, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-iUDP:"+port, "-Fn").Output()
	wildcard := err == nil && wildcardListener(string(out), backend, port)
	if l.ports == nil {
		l.ports = make(map[netip.AddrPort]udpListener)
	}
	for addr, entry := range l.ports {
		if !now.Before(entry.expires) {
			delete(l.ports, addr)
		}
	}
	l.ports[backend] = udpListener{wildcard: wildcard, expires: now.Add(2 * time.Second)}
	return wildcard
}

func wildcardListener(output string, backend netip.AddrPort, port string) bool {
	wildcard := false
	for _, field := range strings.Split(output, "\n") {
		if field == "n*:"+port {
			wildcard = true
		}
		if addr, err := netip.ParseAddrPort(strings.TrimPrefix(field, "n")); err == nil &&
			addr.Addr().Unmap() == backend.Addr() && addr.Port() == backend.Port() {
			return false
		}
	}
	return wildcard
}
