// Package forwarder implements the data-plane logic that runs on the Client:
// for each proxy rule with preserve_source_ip enabled, it listens for
// TPROXY-redirected connections, and for each one dials the real local
// service with a spoofed source IP matching the original remote client.
//
// For rules without preserve_source_ip, it falls back to a plain reverse
// proxy (dial the local service normally; the local service will see the
// Client's own loopback/local address as the source, same as vanilla frp).
package forwarder

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"opennofrp/client/internal/tproxy"
)

// TCPRule is the runtime configuration for one TCP proxy rule.
type TCPRule struct {
	Name             string
	LocalIP          net.IP
	LocalPort        uint16
	PreserveSourceIP bool

	// Only used when PreserveSourceIP is true:
	IngressIface string
	ListenPort   uint16 // the port our TPROXY listener binds to
}

// TCPForwarder owns the listener for one TCPRule with PreserveSourceIP=true.
// It must be started after the corresponding tproxy.RuleSpec has been
// applied via tproxy.Manager.Setup, otherwise inbound connections will never
// reach ListenPort in the first place.
type TCPForwarder struct {
	Rule   TCPRule
	Logger *slog.Logger
	Dialer tproxy.SpoofedDialer

	listener net.Listener
}

// Start begins listening on 127.0.0.1:ListenPort for TPROXY-redirected
// connections. The listening socket itself needs IP_TRANSPARENT set (via
// SO_IP_TRANSPARENT on the listening socket) so that accept() can hand back
// connections whose local address is the *original* destination address
// (the TPROXY semantics relied upon throughout this design -- see
// docs/01-architecture.md).
func (f *TCPForwarder) Start(ctx context.Context) error {
	lc := net.ListenConfig{
		Control: controlSetTransparent,
	}
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%d", f.Rule.ListenPort))
	if err != nil {
		return fmt.Errorf("forwarder: listen on TPROXY port %d: %w", f.Rule.ListenPort, err)
	}
	f.listener = ln

	go f.acceptLoop(ctx)
	return nil
}

func (f *TCPForwarder) Close() error {
	if f.listener != nil {
		return f.listener.Close()
	}
	return nil
}

func (f *TCPForwarder) acceptLoop(ctx context.Context) {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			f.Logger.Error("tproxy accept failed", "rule", f.Rule.Name, "error", err)
			continue
		}
		go f.handleConn(ctx, conn)
	}
}

// handleConn is called for every TPROXY-redirected inbound connection. Per
// TPROXY semantics: conn.RemoteAddr() is the ORIGINAL remote client's real
// address (this is the whole point of TPROXY vs. a plain REDIRECT/DNAT), and
// conn.LocalAddr() -- via getsockname() -- is the connection's ORIGINAL
// destination address (i.e. the public-facing address the client thought it
// was connecting to). We don't actually need LocalAddr here since we already
// know the target local service's address from the rule config, but logging
// it is useful for diagnostics.
func (f *TCPForwarder) handleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	remoteAddr, ok := clientConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		f.Logger.Error("tproxy conn has non-TCP remote addr", "rule", f.Rule.Name)
		return
	}

	f.Logger.Debug("accepted tproxy connection",
		"rule", f.Rule.Name,
		"original_client", remoteAddr.String(),
		"original_dst", clientConn.LocalAddr().String(),
	)

	upstream, err := f.Dialer.DialSpoofed(ctx, remoteAddr.IP, f.Rule.LocalIP, f.Rule.LocalPort)
	if err != nil {
		f.Logger.Warn("failed to dial local service with spoofed source IP",
			"rule", f.Rule.Name,
			"local_target", fmt.Sprintf("%s:%d", f.Rule.LocalIP, f.Rule.LocalPort),
			"error", err,
		)
		return
	}
	defer upstream.Close()

	relay(clientConn, upstream)
}

// relay pipes bytes bidirectionally between two connections until either
// side closes or errors.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}

// DialPlain connects to the local service without any source-IP spoofing.
// Used for rules with PreserveSourceIP=false, or as the behavior OpenNoFrp
// falls back to for Docker bridge-network targets where TPROXY cannot work
// (see docs/01-architecture.md section 6.2) -- the local service will see
// the Client process's own address as the connection source, matching
// vanilla frp's behavior.
func DialPlain(ctx context.Context, localIP net.IP, localPort uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", localIP, localPort))
}
