package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// SpoofedDialer connects to a local service while making the connection's
// source IP appear to be an arbitrary address (the original remote client's
// real IP), using the Linux IP_TRANSPARENT socket option. This requires
// root/CAP_NET_ADMIN+CAP_NET_RAW and the destination to be reachable via a
// route table that treats the chosen source address as locally deliverable
// (see EnsurePolicyRoute in route.go, which this package depends on being
// set up beforehand).
//
// Timeout is important: in the pathological case where the kernel-level
// routing/CONNMARK plumbing is misconfigured, this connect() call hangs
// until TCP's own SYN retransmission timeout rather than failing fast. A
// generous but bounded timeout (a few seconds) turns a silent hang into an
// actionable error.
type SpoofedDialer struct {
	Timeout int // seconds, 0 = use a sensible default (4s)

	// FWMark, if nonzero, is set via SO_MARK on the outbound connect()
	// socket. This is REQUIRED for the connection to succeed: it makes the
	// kernel's policy routing (see EnsurePolicyRoute/table 100) recognize
	// this new connection -- and critically, the SYN-ACK reply packet sent
	// back by the local service -- as belonging to our "deliver locally"
	// routing class. Without this, the reply packet's CONNMARK restoration
	// has nothing to restore (the connection was never marked to begin
	// with), the handshake silently never completes, and connect() hangs
	// until timeout. This was discovered through painful end-to-end testing
	// after the sandbox validation runs had, in retrospect, only exercised
	// scenarios where this happened to not matter. Must match the FWMark
	// used in the corresponding tproxy.RuleSpec.
	FWMark uint32
}

func (d SpoofedDialer) timeoutSeconds() int {
	if d.Timeout <= 0 {
		return 4
	}
	return d.Timeout
}

// DialSpoofed connects to (targetIP, targetPort) with the connection's local
// (source) address set to (spoofSourceIP, 0) -- an ephemeral port is chosen
// automatically. The returned net.Conn behaves like any other TCP
// connection; the caller is responsible for closing it.
func (d SpoofedDialer) DialSpoofed(ctx context.Context, spoofSourceIP net.IP, targetIP net.IP, targetPort uint16) (net.Conn, error) {
	ipv4 := targetIP.To4() != nil
	var domain int
	if ipv4 {
		domain = unix.AF_INET
	} else {
		domain = unix.AF_INET6
	}

	fd, err := unix.Socket(domain, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("tproxy: socket: %w", err)
	}
	// From here on, any early return must close fd to avoid leaking it.
	closeOnErr := func(err error) (net.Conn, error) {
		unix.Close(fd)
		return nil, err
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return closeOnErr(fmt.Errorf("tproxy: SO_REUSEADDR: %w", err))
	}

	// IP_TRANSPARENT is what allows bind() to a non-local address below.
	level := unix.SOL_IP
	if !ipv4 {
		level = unix.SOL_IPV6
	}
	if err := unix.SetsockoptInt(fd, level, unix.IP_TRANSPARENT, 1); err != nil {
		return closeOnErr(fmt.Errorf("tproxy: IP_TRANSPARENT: %w (are you root? CAP_NET_ADMIN+CAP_NET_RAW required)", err))
	}

	if d.FWMark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(d.FWMark)); err != nil {
			return closeOnErr(fmt.Errorf("tproxy: SO_MARK: %w", err))
		}
	}

	if err := bindSpoofedSource(fd, ipv4, spoofSourceIP); err != nil {
		return closeOnErr(err)
	}

	if err := connectWithTimeout(ctx, fd, ipv4, targetIP, targetPort, d.timeoutSeconds()); err != nil {
		return closeOnErr(err)
	}

	file := fileFromFD(fd)
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		return closeOnErr(fmt.Errorf("tproxy: net.FileConn: %w", err))
	}
	return conn, nil
}

func bindSpoofedSource(fd int, ipv4 bool, srcIP net.IP) error {
	if ipv4 {
		var addr unix.SockaddrInet4
		ip4 := srcIP.To4()
		if ip4 == nil {
			return fmt.Errorf("tproxy: spoof source %s is not a valid IPv4 address", srcIP)
		}
		copy(addr.Addr[:], ip4)
		addr.Port = 0
		if err := unix.Bind(fd, &addr); err != nil {
			return fmt.Errorf("tproxy: bind spoofed source %s: %w", srcIP, err)
		}
		return nil
	}
	var addr unix.SockaddrInet6
	ip6 := srcIP.To16()
	if ip6 == nil {
		return fmt.Errorf("tproxy: spoof source %s is not a valid IPv6 address", srcIP)
	}
	copy(addr.Addr[:], ip6)
	addr.Port = 0
	if err := unix.Bind(fd, &addr); err != nil {
		return fmt.Errorf("tproxy: bind spoofed source %s: %w", srcIP, err)
	}
	return nil
}

func connectWithTimeout(ctx context.Context, fd int, ipv4 bool, targetIP net.IP, targetPort uint16, timeoutSeconds int) error {
	// Make the socket non-blocking so connect() returns immediately with
	// EINPROGRESS, then use select/poll-style waiting bounded by both the
	// caller's context and our own timeout. This is what turns a
	// misconfigured-routing hang into a clean, bounded error instead of
	// blocking for the OS's full SYN retry period (which can be 2+ minutes).
	if err := unix.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("tproxy: set non-blocking: %w", err)
	}

	var connectErr error
	if ipv4 {
		var addr unix.SockaddrInet4
		ip4 := targetIP.To4()
		if ip4 == nil {
			return fmt.Errorf("tproxy: target %s is not a valid IPv4 address", targetIP)
		}
		copy(addr.Addr[:], ip4)
		addr.Port = int(targetPort)
		connectErr = unix.Connect(fd, &addr)
	} else {
		var addr unix.SockaddrInet6
		ip6 := targetIP.To16()
		if ip6 == nil {
			return fmt.Errorf("tproxy: target %s is not a valid IPv6 address", targetIP)
		}
		copy(addr.Addr[:], ip6)
		addr.Port = int(targetPort)
		connectErr = unix.Connect(fd, &addr)
	}

	if connectErr != nil && connectErr != unix.EINPROGRESS {
		return fmt.Errorf("tproxy: connect to %s:%d: %w", targetIP, targetPort, connectErr)
	}

	// Wait for the socket to become writable (connect complete) or time out.
	pollCtx, cancel := context.WithTimeoutCause(ctx, secondsToDuration(timeoutSeconds),
		fmt.Errorf("tproxy: connect to %s:%d timed out after %ds (check: TPROXY rules, policy routing table, CONNMARK save/restore, sysctls -- see docs/01-architecture.md section 6.1)", targetIP, targetPort, timeoutSeconds))
	defer cancel()

	done := make(chan error, 1)
	go func() {
		var pfd unix.PollFd
		pfd.Fd = int32(fd)
		pfd.Events = unix.POLLOUT
		for {
			n, err := unix.Poll([]unix.PollFd{pfd}, 100)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				done <- fmt.Errorf("tproxy: poll: %w", err)
				return
			}
			if n > 0 {
				break
			}
			select {
			case <-pollCtx.Done():
				return
			default:
			}
		}
		soErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			done <- fmt.Errorf("tproxy: SO_ERROR: %w", err)
			return
		}
		if soErr != 0 {
			done <- fmt.Errorf("tproxy: connect to %s:%d: %w", targetIP, targetPort, syscall.Errno(soErr))
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			return err
		}
	case <-pollCtx.Done():
		return context.Cause(pollCtx)
	}

	if err := unix.SetNonblock(fd, false); err != nil {
		return fmt.Errorf("tproxy: clear non-blocking: %w", err)
	}
	return nil
}
