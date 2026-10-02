// Command netnsworker-poc is a standalone proof-of-concept binary that
// validates the netnsworker package's core claim: a Go program can use
// setns(2) to enter a target Docker container's network namespace, set up
// TPROXY rules and a spoofed-source-IP forwarder INSIDE that namespace
// (targeting the namespace's own 127.0.0.1), and have external traffic
// arriving via the container's normal "docker run -p" port mapping come out
// the other end with the real external client's IP preserved -- all without
// touching the container, its port mapping, or any host-level TPROXY rules.
//
// Usage: netnsworker-poc <container-pid> <port> <fwmark>
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"opennofrp/client/internal/netnsworker"
	"opennofrp/client/internal/tproxy"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: netnsworker-poc <container-pid> <port> <fwmark>")
		os.Exit(1)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("invalid pid: %v", err)
	}
	port, err := strconv.ParseUint(os.Args[2], 10, 16)
	if err != nil {
		log.Fatalf("invalid port: %v", err)
	}
	fwmarkInt, err := strconv.ParseUint(os.Args[3], 10, 32)
	if err != nil {
		log.Fatalf("invalid fwmark: %v", err)
	}
	fwmark := uint32(fwmarkInt)
	targetPort := uint16(port)

	cns := netnsworker.ContainerNetns{PID: pid}

	err = cns.RunInNamespace(func() error {
		iface, err := netnsworker.IngressInterface()
		if err != nil {
			return fmt.Errorf("detect ingress interface: %w", err)
		}
		log.Printf("[netnsworker-poc] running inside container netns (pid=%d), ingress interface: %s", pid, iface)

		// Apply the TPROXY mangle rules WITHIN this namespace (we are
		// setns()'d in, so iptables-legacy here operates on this
		// namespace's own tables, not the host's).
		spec := tproxy.RuleSpec{
			PublicPort:   targetPort,
			IngressIface: iface,
			ListenPort:   10001,
			FWMark:       fwmark,
		}
		if err := tproxy.AddTproxyRule(spec); err != nil {
			return fmt.Errorf("add tproxy rule: %w", err)
		}
		log.Printf("[netnsworker-poc] TPROXY rule applied inside container netns")

		if err := tproxy.ApplySysctls(iface); err != nil {
			return fmt.Errorf("apply sysctls: %w", err)
		}
		log.Printf("[netnsworker-poc] sysctls applied inside container netns")

		if err := tproxy.EnsurePolicyRoute(tproxy.DefaultRouteTable, fwmark); err != nil {
			return fmt.Errorf("ensure policy route: %w", err)
		}
		log.Printf("[netnsworker-poc] policy route applied inside container netns")

		return runForwarder(cns, spec, targetPort)
	})
	if err != nil {
		log.Fatalf("[netnsworker-poc] FATAL: %v", err)
	}
}

// runForwarder listens on the TPROXY redirect port (inside the container's
// netns, since we're already setns()'d in by the time this runs) and
// forwards each connection to 127.0.0.1:targetPort within that SAME
// namespace, using IP_TRANSPARENT + SO_MARK to spoof the source IP back to
// the original external client's address.
func runForwarder(cns netnsworker.ContainerNetns, spec tproxy.RuleSpec, targetPort uint16) error {
	lc := net.ListenConfig{Control: controlSetTransparent}
	ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf("0.0.0.0:%d", spec.ListenPort))
	if err != nil {
		return fmt.Errorf("listen on tproxy port %d: %w", spec.ListenPort, err)
	}
	log.Printf("[netnsworker-poc] TPROXY listener on 0.0.0.0:%d (inside container netns)", spec.ListenPort)

	dialer := tproxy.SpoofedDialer{FWMark: spec.FWMark}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[netnsworker-poc] accept error: %v", err)
			continue
		}
		// CRITICAL: do NOT spawn a bare "go handleConn(...)" here. This
		// goroutine must ALSO run on an OS thread that is setns()'d into
		// the target container's network namespace, because the upstream
		// socket() call inside handleConn (via DialSpoofed) creates a brand
		// new file descriptor, and a new fd's network namespace is
		// determined by whichever OS thread's netns is active AT THE TIME
		// unix.Socket() is called -- not by which goroutine logically
		// "belongs" to this accept loop. Go's scheduler is free to run an
		// unlocked goroutine on ANY OS thread, including ones still sitting
		// in the host's root namespace, which is exactly what happened
		// during initial PoC testing: the TPROXY listener worked fine (its
		// socket was created once, synchronously, on the correctly-locked
		// thread during setup), but every per-connection upstream dial
		// silently created its socket in the HOST namespace instead,
		// connecting to the host's own (service-less) 127.0.0.1:9999 and
		// timing out. nsenter-based (Python) testing never hit this because
		// nsenter uses execve(), which carries the namespace to literally
		// every thread of the resulting process -- there's no "escape onto
		// an unlocked thread" possible there. Go's goroutine model has no
		// such blanket guarantee, so each connection handler must
		// independently re-pin itself.
		go func(c net.Conn) {
			if err := cns.Enter(); err != nil {
				log.Printf("[netnsworker-poc] FATAL: per-connection netns Enter failed: %v", err)
				c.Close()
				return
			}
			handleConn(c, dialer, targetPort)
		}(conn)
	}
}

func handleConn(clientConn net.Conn, dialer tproxy.SpoofedDialer, targetPort uint16) {
	defer clientConn.Close()

	remoteAddr, ok := clientConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("[netnsworker-poc] non-TCP remote addr, dropping")
		return
	}
	log.Printf("[netnsworker-poc] accepted connection, original client: %s, original dst (via getsockname): %s",
		remoteAddr, clientConn.LocalAddr())

	upstream, err := dialer.DialSpoofed(context.Background(), remoteAddr.IP, net.ParseIP("127.0.0.1"), targetPort)
	if err != nil {
		log.Printf("[netnsworker-poc] spoofed dial failed: %v", err)
		return
	}
	defer upstream.Close()
	log.Printf("[netnsworker-poc] connected upstream to 127.0.0.1:%d spoofing source %s", targetPort, remoteAddr.IP)

	relay(clientConn, upstream)
}

func relay(a, b net.Conn) {
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
	go cp(a, b)
	go cp(b, a)
	<-done
}

// controlSetTransparent sets IP_TRANSPARENT and SO_REUSEADDR on the
// listening socket before bind(), so accept()ed connections report the
// connection's ORIGINAL destination via getsockname() per TPROXY semantics.
// (Duplicated here rather than imported from the forwarder package, to keep
// this standalone PoC binary's dependency graph minimal and self-contained.)
func controlSetTransparent(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockErr = err
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			sockErr = err
			return
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}
