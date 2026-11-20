//go:build darwin

package rulesync

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"opennofrp/client/internal/darwinsource"
	"opennofrp/pkg/protocol"
)

type platformSource struct {
	mu      sync.Mutex
	dialer  *darwinsource.Dialer
	retryAt time.Time
	lastErr error
	closed  bool
}

func (p *platformSource) get(ctx context.Context) (*darwinsource.Dialer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	if p.dialer != nil {
		select {
		case <-p.dialer.Done():
			p.dialer = nil
		default:
			return p.dialer, nil
		}
	}
	if time.Now().Before(p.retryAt) {
		return nil, p.lastErr
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p.dialer, p.lastErr = darwinsource.New(ctx)
	if p.lastErr != nil {
		p.retryAt = time.Now().Add(5 * time.Second)
	}
	return p.dialer, p.lastErr
}

func (r *Reconciler) Close() error {
	p := &r.source
	p.mu.Lock()
	p.closed = true
	dialer := p.dialer
	p.mu.Unlock()
	if dialer != nil {
		return dialer.Close()
	}
	return nil
}

func (r *Reconciler) dialPreservingSource(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata, _ string) (net.Conn, error) {
	return r.dialDarwin(ctx, "tcp", rule, meta)
}

func (r *Reconciler) dialSpoofedUDP(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata) (net.Conn, error) {
	return r.dialDarwin(ctx, "udp", rule, meta)
}

func (r *Reconciler) dialDarwin(ctx context.Context, network string, rule protocol.Rule, meta protocol.StreamMetadata) (net.Conn, error) {
	visitor, valid := netip.AddrFromSlice(meta.ClientAddr)
	visitor = visitor.Unmap()
	backend, err := netip.ParseAddr(rule.LocalIP)
	backend = backend.Unmap()
	if !valid || !visitor.Is4() || !visitor.IsGlobalUnicast() || err != nil || !backend.Is4() || !backend.IsLoopback() {
		r.Logger.Debug("source IP preservation requires an IPv4 visitor and an IPv4 loopback backend; using plain forwarding",
			"rule", rule.Name, "visitor", visitor, "backend", rule.LocalIP)
		return nil, nil
	}
	d, err := r.source.get(ctx)
	if err != nil {
		r.Logger.Warn("macOS source IP setup failed, falling back to plain forwarding", "rule", rule.Name, "error", err)
		return nil, nil
	}
	conn, err := d.Dial(ctx, network, netip.AddrPortFrom(visitor, meta.ClientPort), netip.AddrPortFrom(backend, rule.LocalPort))
	if err != nil {
		return nil, fmt.Errorf("dial local service with source %s: %w", visitor, err)
	}
	return conn, nil
}
