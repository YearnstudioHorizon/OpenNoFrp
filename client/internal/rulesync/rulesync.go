// Package rulesync is the Client's local reconciler for Server-pushed
// forwarding rules. The Client receives a full RulesSnapshot message from
// the Server after every handshake and after every panel-side rule change,
// and dispatches incoming connection streams to the right local endpoint
// based on the rule ID embedded in each stream's metadata -- picking the
// forwarding strategy (plain / host-netns TPROXY-style spoofed dial /
// container-netns spoofed dial) from a fresh DetectPortOwner probe of the
// local target port.
package rulesync

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"opennofrp/client/internal/envcheck"
	"opennofrp/client/internal/netnsworker"
	"opennofrp/client/internal/tproxy"
	"opennofrp/pkg/protocol"
)

// sharedFWMark is the fwmark used for every spoofed-source connection. It
// must match the one used when installing the host/container policy routes
// and the OUTPUT CONNMARK save/restore pair (tproxy.DefaultFWMark with the
// same value).
const sharedFWMark = tproxy.DefaultFWMark

// Reconciler holds the latest snapshot and per-rule runtime state.
type Reconciler struct {
	Logger   *slog.Logger
	StateDir string

	mu            sync.RWMutex
	rules         map[uint32]protocol.Rule
	preparedNetns map[int]bool // container PID -> whether its netns got sysctls+route yet
	hostSetupDone bool
}

func New(logger *slog.Logger, stateDir string) *Reconciler {
	return &Reconciler{
		Logger:        logger,
		StateDir:      stateDir,
		rules:         make(map[uint32]protocol.Rule),
		preparedNetns: make(map[int]bool),
	}
}

// Apply installs a fresh full snapshot; rules no longer present are
// dropped (their ID lookups on subsequent streams then fail closed).
func (r *Reconciler) Apply(rules []protocol.Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = make(map[uint32]protocol.Rule, len(rules))
	for _, rule := range rules {
		r.rules[uint32(rule.ID)] = rule
	}
	r.Logger.Info("rules snapshot applied", "count", len(rules))
}

// Get looks up a rule by its database ID (carried in StreamMetadata).
func (r *Reconciler) Get(ruleID uint32) (protocol.Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.rules[ruleID]
	return rule, ok
}

// ServeStream dispatches one Server-opened stream using its RuleID. It owns
// blocking on the relay; call from a goroutine.
func (r *Reconciler) ServeStream(ctx context.Context, meta protocol.StreamMetadata, stream net.Conn) {
	defer stream.Close()

	rule, ok := r.Get(meta.RuleID)
	if !ok {
		r.Logger.Error("stream for unknown rule id, dropping", "rule_id", meta.RuleID)
		return
	}

	switch meta.Transport {
	case protocol.TransportTCP:
		r.serveTCP(ctx, rule, meta, stream)
	case protocol.TransportUDP:
		r.serveUDP(ctx, rule, meta, stream)
	default:
		r.Logger.Error("unknown transport on stream metadata", "transport", meta.Transport)
	}
}

func (r *Reconciler) serveTCP(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata, stream net.Conn) {
	target := net.JoinHostPort(rule.LocalIP, fmt.Sprint(rule.LocalPort))

	if !rule.PreserveSourceIP {
		upstream, err := dialPlain(ctx, target)
		if err != nil {
			r.Logger.Warn("plain dial failed, dropping", "rule", rule.Name, "target", target, "error", err)
			return
		}
		defer upstream.Close()
		relay(stream, upstream)
		return
	}

	// Source-IP preservation requested: pick strategy from a live probe of
	// who owns the local target port. Re-running DetectPortOwner on every
	// connection matters because a Docker container restart replaces its
	// PID (different /proc/<pid>/ns/net), and a stale PID would otherwise
	// silently enter the dead namespace.
	owner, err := envcheck.DetectPortOwner(rule.LocalPort)
	if err != nil {
		r.Logger.Warn("cannot determine port owner, falling back to plain forwarding",
			"rule", rule.Name, "port", rule.LocalPort, "error", err)
		upstream, err := dialPlain(ctx, target)
		if err != nil {
			return
		}
		defer upstream.Close()
		relay(stream, upstream)
		return
	}

	switch owner.Kind {
	case envcheck.OwnerHostProcess, envcheck.OwnerDockerHostNetwork:
		if err := r.ensureHostTPROXYReady(); err != nil {
			r.Logger.Warn("host TPROXY environment setup failed, falling back to plain forwarding", "error", err)
			upstream, err := dialPlain(ctx, target)
			if err != nil {
				return
			}
			defer upstream.Close()
			relay(stream, upstream)
			return
		}
		dialer := tproxy.SpoofedDialer{FWMark: sharedFWMark}
		upstream, err := dialer.DialSpoofed(ctx, meta.ClientAddr, net.ParseIP(rule.LocalIP), rule.LocalPort)
		if err != nil {
			r.Logger.Warn("spoofed dial failed, dropping connection", "rule", rule.Name, "error", err)
			return
		}
		defer upstream.Close()
		relay(stream, upstream)

	case envcheck.OwnerDockerBridgeNetwork:
		cns := netnsworker.ContainerNetns{PID: owner.PID}
		if err := r.ensureNetnsReady(cns); err != nil {
			r.Logger.Warn("container netns setup failed, falling back to plain forwarding",
				"rule", rule.Name, "container_pid", owner.PID, "error", err)
			upstream, err := dialPlain(ctx, target)
			if err != nil {
				return
			}
			defer upstream.Close()
			relay(stream, upstream)
			return
		}

		// Bridge container: the entire spoofed-source connection must be
		// created from INSIDE that container's network namespace -- no host
		// iptables/TPROXY can survive Docker's bridge MASQUERADE, see
		// docs/01-architecture.md section 6.5. The goroutine must
		// runtime.LockOSThread-style Enter() this netns before socket().
		containerIP := net.ParseIP("127.0.0.1")
		upstreamCh := make(chan net.Conn, 1)
		errCh := make(chan error, 1)
		go func() {
			if err := cns.Enter(); err != nil {
				errCh <- fmt.Errorf("enter container netns: %w", err)
				return
			}
			dialer := tproxy.SpoofedDialer{FWMark: sharedFWMark}
			upstream, err := dialer.DialSpoofed(ctx, meta.ClientAddr, containerIP, rule.LocalPort)
			if err != nil {
				errCh <- err
				return
			}
			upstreamCh <- upstream
		}()
		select {
		case err := <-errCh:
			r.Logger.Warn("container-netns spoofed dial failed, dropping", "rule", rule.Name, "error", err)
			return
		case upstream := <-upstreamCh:
			defer upstream.Close()
			relay(stream, upstream)
		}

	default:
		r.Logger.Warn("unknown port owner kind, falling back to plain forwarding", "rule", rule.Name, "kind", owner.Kind.String())
		upstream, err := dialPlain(ctx, target)
		if err != nil {
			return
		}
		defer upstream.Close()
		relay(stream, upstream)
	}
}

// UDP for preserve_source_ip is intentionally plain in v1: TPROXY+UDSP
// spoofing is a separate validated-future area (see docs/01-architecture.md),
// so we forward normally and keep the flow alive rather than silently
// producing a non-functional spoofed flow.
func (r *Reconciler) serveUDP(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata, stream net.Conn) {
	if rule.PreserveSourceIP {
		r.Logger.Warn("preserve_source_ip for UDP is not supported yet, forwarding as plain reverse proxy", "rule", rule.Name)
	}
	target := net.JoinHostPort(rule.LocalIP, fmt.Sprint(rule.LocalPort))
	upstream, err := net.Dial("udp", target)
	if err != nil {
		r.Logger.Warn("udp dial failed, dropping", "rule", rule.Name, "target", target, "error", err)
		return
	}
	defer upstream.Close()

	// The stream is a byte pipe, UDP is datagrams: frame each datagram.
	go copyUDPFrames(stream, upstream)
	copyUDPFramesReverse(upstream, stream)
}

// ensureHostTPROXYReady applies the host-level sysctls, policy route, and
// OUTPUT CONNMARK save/restore pair the spoofed dials need, exactly once
// per process. No inbound TPROXY mangle rules: the yamux stream already
// carries the original client address, so the Client dials directly with
// SO_MARK/IP_TRANSPARENT -- but the reply direction still needs CONNMARK
// restoration or the service's SYN-ACK routes out the default gateway and
// the handshake times out (see tproxy.EnsureConnmarkReplyRules).
func (r *Reconciler) ensureHostTPROXYReady() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hostSetupDone {
		return nil
	}
	iface, err := tproxy.DefaultIngressInterface()
	if err != nil {
		return fmt.Errorf("detect ingress interface: %w", err)
	}
	if err := tproxy.ApplySysctls(iface); err != nil {
		return err
	}
	if err := tproxy.EnsurePolicyRoute(tproxy.DefaultRouteTable, sharedFWMark); err != nil {
		return err
	}
	if err := tproxy.EnsureConnmarkReplyRules(sharedFWMark); err != nil {
		return fmt.Errorf("ensure CONNMARK reply rules: %w", err)
	}
	r.hostSetupDone = true
	r.Logger.Info("host TPROXY environment prepared (sysctls + policy route + CONNMARK)", "iface", iface)
	return nil
}

// ensureNetnsReady applies sysctls + policy route inside the container's
// netns, exactly once per container PID. Executed via RunInNamespace so the
// writes land on the container's own eth0/lo/all entries.
func (r *Reconciler) ensureNetnsReady(cns netnsworker.ContainerNetns) error {
	r.mu.Lock()
	if r.preparedNetns[cns.PID] {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	err := cns.RunInNamespace(func() error {
		iface, err := netnsworker.IngressInterface()
		if err != nil {
			return err
		}
		if err := tproxy.ApplySysctls(iface); err != nil {
			return err
		}
		if err := tproxy.EnsurePolicyRoute(tproxy.DefaultRouteTable, sharedFWMark); err != nil {
			return err
		}
		// Same reply-path requirement as the host path, but installed
		// inside the container's netns (we're setns()'d in, so
		// iptables-legacy operates on the container's own tables).
		return tproxy.EnsureConnmarkReplyRules(sharedFWMark)
	})
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.preparedNetns[cns.PID] = true
	r.mu.Unlock()
	r.Logger.Info("container netns TPROXY environment prepared", "container_pid", cns.PID)
	return nil
}

func dialPlain(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
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

// UDP framing over a stream: [uint16 big-endian length][payload] per datagram.
// The first (metadata-bearing) direction already has its header consumed by
// ReadStreamMetadata before this framing begins.
func copyUDPFrames(stream, upstream net.Conn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := upstream.Read(buf)
		if n > 0 {
			if !writeUDPFrame(stream, buf[:n]) {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func copyUDPFramesReverse(upstream, stream net.Conn) {
	for {
		payload, err := readUDPFrame(stream)
		if err != nil {
			return
		}
		if _, err := upstream.Write(payload); err != nil {
			return
		}
	}
}

func writeUDPFrame(w net.Conn, payload []byte) bool {
	if len(payload) > 65535 {
		return false
	}
	hdr := []byte{byte(len(payload) >> 8), byte(len(payload))}
	if _, err := w.Write(hdr); err != nil {
		return false
	}
	if _, err := w.Write(payload); err != nil {
		return false
	}
	return true
}

func readUDPFrame(r net.Conn) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := readFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	payload := make([]byte, n)
	if _, err := readFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func readFull(r net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
