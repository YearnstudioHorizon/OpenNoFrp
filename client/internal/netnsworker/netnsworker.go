// Package netnsworker lets the OpenNoFrp Client run TPROXY-based
// source-IP-preserving forwarding logic INSIDE a target container's network
// namespace, rather than the Client's own (host) network namespace.
//
// Why this exists: a Docker container running in the default bridge network
// mode (standard "docker run -p") applies MASQUERADE to all traffic entering
// docker0, which overwrites any source-IP spoofing a host-side TPROXY
// forwarder performs before the packet reaches the container. Extensive
// sandbox testing (see docs/01-architecture.md section 6) found no way to
// preserve a spoofed source IP across that MASQUERADE boundary from outside
// the container's namespace.
//
// The fix validated in that same sandbox: instead of fighting the
// MASQUERADE boundary, run the TPROXY proxy process INSIDE the target
// container's own network namespace, pointed at that namespace's OWN
// loopback (127.0.0.1) as the upstream target -- exactly the topology
// that was already proven to work for plain host processes. From inside
// the container's netns, "the local service" and "the proxy" are both
// local to the SAME namespace, so none of the bridge's NAT machinery is
// ever involved; Docker's -p port mapping, iptables DNAT/MASQUERADE rules,
// and the container itself are never touched or reconfigured.
//
// Requirements for this to work (see dialer.go in the tproxy package):
//   - the TPROXY mangle rules (TPROXY + CONNMARK save/restore) must be
//     applied INSIDE the target netns, matching that namespace's own
//     ingress interface (typically "eth0" for a container)
//   - the upstream connect()'s socket must carry SO_MARK matching the
//     fwmark used by those rules (this is the fix discovered through
//     real end-to-end Go testing; the original netns sidecar experiment
//     failed without it and was, at the time, incorrectly attributed to
//     a netns-specific kernel limitation)
//   - the relevant sysctls (route_localnet, accept_local, rp_filter) must
//     be set on "lo", the container's ingress interface, and "all",
//     WITHIN that namespace
package netnsworker

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// ContainerNetns identifies a target container's network namespace by PID
// (the container's init process PID, as seen from the host PID namespace --
// i.e. what `docker inspect --format '{{.State.Pid}}'` returns).
type ContainerNetns struct {
	PID int
}

// nsPath returns the /proc/<pid>/ns/net path for this container.
func (c ContainerNetns) nsPath() string {
	return fmt.Sprintf("/proc/%d/ns/net", c.PID)
}

// RunInNamespace executes fn with the calling goroutine's OS thread's
// network namespace switched to the target container's namespace, then
// switches back before returning.
//
// CRITICAL Go runtime detail: setns(2) only affects the calling OS thread,
// not the whole process, and Go's scheduler can migrate a goroutine between
// OS threads at any preemption point. This function uses
// runtime.LockOSThread() to pin the current goroutine to one OS thread for
// the entire duration of fn, and crucially never calls runtime.UnlockOSThread()
// before returning -- the thread is intentionally left locked-and-discarded
// (Go's runtime will terminate that OS thread rather than ever reuse it for
// another goroutine, per the stdlib's own documented pattern for this exact
// situation: https://pkg.go.dev/runtime#LockOSThread). This guarantees no
// other, unrelated goroutine can ever accidentally end up running on a
// thread that's sitting inside the container's network namespace.
//
// fn is expected to do all of its namespace-sensitive work synchronously
// (e.g. create a TPROXY listener and run its whole accept loop) since this
// function returns only after fn returns.
//
// IMPORTANT CAVEAT discovered via real end-to-end testing: this only
// guarantees the correct namespace for code running on the SAME goroutine
// fn was called on. If fn itself spawns additional goroutines (e.g. "go
// handleConn(...)" per accepted connection, a completely ordinary and
// otherwise-correct Go pattern), those new goroutines are NOT automatically
// pinned to the setns()'d thread -- Go's scheduler is free to run them on
// any OS thread, including ones still sitting in the host's root namespace.
// Any syscall that creates a new namespace-sensitive resource (most
// importantly: socket(2), via net.Dial / unix.Socket) is only guaranteed to
// land in the target namespace if the calling goroutine has independently
// called Enter (see below) on its own dedicated, locked OS thread. See
// netnsworker-poc's runForwarder for the concrete pattern: the accept loop
// itself can run on the thread pinned by RunInNamespace, but EVERY
// per-connection handler goroutine must call Enter again for itself.
func (c ContainerNetns) RunInNamespace(fn func() error) error {
	hostNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("netnsworker: open host netns: %w", err)
	}
	defer hostNS.Close()

	targetNS, err := os.Open(c.nsPath())
	if err != nil {
		return fmt.Errorf("netnsworker: open target netns %s: %w", c.nsPath(), err)
	}
	defer targetNS.Close()

	// Dedicated goroutine, permanently pinned to a dedicated OS thread for
	// its entire lifetime -- see the doc comment above for why this
	// particular combination (new goroutine + LockOSThread + never unlock)
	// is the safe pattern here.
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Deliberately NOT calling runtime.UnlockOSThread(): once this
		// goroutine returns, Go terminates this OS thread rather than
		// ever scheduling another goroutine onto a thread that has been
		// setns()'d into a container's namespace.

		if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("netnsworker: setns into container: %w", err)
			return
		}

		fnErr := fn()

		// Best-effort: switch back before this thread is torn down. Not
		// strictly necessary since the thread is being discarded either
		// way, but cheap defense-in-depth in case any cleanup code in fn's
		// deferred calls (already run by the time we get here) somehow
		// expected to still be in a sane namespace -- it won't, but this
		// avoids ever leaving a *process-visible* side effect of a
		// dangling wrong-namespace thread for longer than necessary.
		_ = unix.Setns(int(hostNS.Fd()), unix.CLONE_NEWNET)

		errCh <- fnErr
	}()

	return <-errCh
}

// Enter pins the CALLING goroutine to a new, dedicated OS thread and
// setns()'s that thread into this container's network namespace. Unlike
// RunInNamespace, this does not run a callback and return -- it mutates the
// current goroutine's thread affinity in place and returns, after which the
// calling goroutine (and only that goroutine, for as long as it keeps
// running on this now-permanently-claimed thread) can safely create
// namespace-sensitive resources (sockets, etc.) that will correctly belong
// to the target namespace.
//
// This MUST be called at the top of every independently-scheduled goroutine
// (i.e. every "go func(){...}()") that needs to create a socket inside the
// target namespace -- RunInNamespace's namespace membership does NOT
// propagate to child goroutines. See the package doc and
// netnsworker-poc/main.go for the concrete failure mode this prevents.
func (c ContainerNetns) Enter() error {
	runtime.LockOSThread()
	// Deliberately never unlocked, for the same reason as RunInNamespace.

	targetNS, err := os.Open(c.nsPath())
	if err != nil {
		return fmt.Errorf("netnsworker: open target netns %s: %w", c.nsPath(), err)
	}
	defer targetNS.Close()

	if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("netnsworker: setns into container: %w", err)
	}
	return nil
}

// IngressInterface returns the name of the primary non-loopback interface
// inside the target namespace (typically "eth0" for a standard Docker
// bridge-network container). This must be called from within
// RunInNamespace's fn, since it inspects the CURRENT namespace's
// interfaces.
func IngressInterface() (string, error) {
	ifaces, err := netInterfacesExcludingLoopback()
	if err != nil {
		return "", err
	}
	if len(ifaces) == 0 {
		return "", fmt.Errorf("netnsworker: no non-loopback interface found in this namespace")
	}
	// A container's netns normally has exactly one non-loopback interface
	// (its veth pair end, conventionally named eth0). If there happen to be
	// multiple (unusual custom network setups), we take the first and let
	// the caller override via config if that's ever wrong in practice.
	return ifaces[0], nil
}
