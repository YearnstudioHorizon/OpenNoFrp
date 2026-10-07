// Package listener manages the public-facing TCP/UDP listeners that forward
// traffic into Client sessions. The set of open ports is driven entirely by
// the rules table: enabling a rule opens its public port, disabling closes
// it. Crucially: no raw sockets, no iptables/nftables/routing -- this
// package is the embodiment of the "cloud server stays pure userspace" rule
// from docs/01-architecture.md.
package listener

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"opennofrp/server/internal/session"
)

// RuleView carries just the fields a listener needs from a rules-table row.
type RuleView struct {
	ID       uint32
	ClientID string
	Protocol string // "tcp", "udp" or "tcp+udp" (dual stack)
	Port     uint16
}

// expandRule splits a dual-stack ("tcp+udp") rule into one TCP and one UDP
// view sharing the same rule ID and port. Single-protocol rules are
// returned unchanged.
func expandRule(r RuleView) []RuleView {
	if r.Protocol == "tcp+udp" {
		t, u := r, r
		t.Protocol = "tcp"
		u.Protocol = "udp"
		return []RuleView{t, u}
	}
	return []RuleView{r}
}

// ruleView keeps the old unexported alias shape; use RuleView in new code.
type ruleView = RuleView

// SessionLookup returns the live session for a client ID, or nil when that
// Client is not currently connected. Implemented by the server struct.
type SessionLookup func(clientID string) *session.Session

type Manager struct {
	BindAddr string
	Logger   *slog.Logger
	Lookup   SessionLookup

	mu  sync.Mutex
	tcp map[uint16]*tcpListener
	udp map[uint16]*udpListener
}

type tcpListener struct {
	ln       net.Listener
	ruleID   uint32
	clientID string
	done     chan struct{}
}

type udpListener struct {
	conn     *net.UDPConn
	ruleID   uint32
	clientID string
	done     chan struct{}
	flows    map[string]*udpFlow
}

type udpFlow struct {
	remote *net.UDPAddr
	stream net.Conn
	act    chan struct{} // receives client datagrams from the demux loop
}

func NewManager(bindAddr string, logger *slog.Logger, lookup SessionLookup) *Manager {
	return &Manager{
		BindAddr: bindAddr,
		Logger:   logger,
		Lookup:   lookup,
		tcp:      make(map[uint16]*tcpListener),
		udp:      make(map[uint16]*udpListener),
	}
}

// OpenRule starts listening for the given rule's protocol+port. Idempotent
// per (protocol, port): calling again with the same identity is a no-op,
// calling with a different ruleID for an already-open port returns an error
// (first-come-first-served).
func (m *Manager) OpenRule(r ruleView) error {
	switch r.Protocol {
	case "tcp":
		return m.openTCP(r)
	case "udp":
		return m.openUDP(r)
	case "tcp+udp":
		var errs []error
		for _, v := range expandRule(r) {
			if err := m.OpenRule(v); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	default:
		return fmt.Errorf("listener: unknown protocol %q", r.Protocol)
	}
}

func (m *Manager) openTCP(r ruleView) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.tcp[r.Port]; ok {
		if existing.ruleID == r.ID {
			return nil
		}
		return fmt.Errorf("listener: tcp port %d already open for rule %d", r.Port, existing.ruleID)
	}
	addr := fmt.Sprintf("%s:%d", m.BindAddr, r.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listener: tcp listen on %s: %w", addr, err)
	}
	tl := &tcpListener{ln: ln, ruleID: r.ID, clientID: r.ClientID, done: make(chan struct{})}
	m.tcp[r.Port] = tl
	go m.tcpAcceptLoop(addr, tl)
	m.Logger.Info("opened public TCP listener", "port", r.Port, "rule_id", r.ID)
	return nil
}

func (m *Manager) tcpAcceptLoop(_ string, tl *tcpListener) {
	for {
		conn, err := tl.ln.Accept()
		if err != nil {
			select {
			case <-tl.done:
				return
			default:
			}
			m.Logger.Error("tcp accept failed, closing listener", "rule_id", tl.ruleID, "error", err)
			return
		}
		sess := m.Lookup(tl.clientID)
		if sess == nil {
			m.Logger.Warn("public TCP connection arrived but owning client is offline, dropping",
				"rule_id", tl.ruleID, "remote", conn.RemoteAddr())
			conn.Close()
			continue
		}
		if err := sess.OpenStreamFor(conn, tl.ruleID); err != nil {
			m.Logger.Error("failed to forward connection to client", "rule_id", tl.ruleID, "error", err)
			conn.Close()
		}
	}
}

func (m *Manager) openUDP(r ruleView) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.udp[r.Port]; ok {
		if existing.ruleID == r.ID {
			return nil
		}
		return fmt.Errorf("listener: udp port %d already open for rule %d", r.Port, existing.ruleID)
	}
	addr := fmt.Sprintf("%s:%d", m.BindAddr, r.Port)
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("listener: resolve %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listener: udp listen on %s: %w", addr, err)
	}
	ul := &udpListener{conn: conn, ruleID: r.ID, clientID: r.ClientID, done: make(chan struct{}), flows: make(map[string]*udpFlow)}
	m.udp[r.Port] = ul
	go m.udpLoop(ul)
	m.Logger.Info("opened public UDP listener", "port", r.Port, "rule_id", r.ID)
	return nil
}

func (m *Manager) udpLoop(ul *udpListener) {
	buf := make([]byte, 64*1024)
	for {
		n, remote, err := ul.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ul.done:
				return
			default:
			}
			m.Logger.Error("udp read failed, closing listener", "rule_id", ul.ruleID, "error", err)
			return
		}
		key := remote.String()
		m.mu.Lock()
		flow, ok := ul.flows[key]
		m.mu.Unlock()
		if !ok {
			sess := m.Lookup(ul.clientID)
			if sess == nil {
				m.Logger.Warn("udp datagram for offline client, dropping", "rule_id", ul.ruleID, "remote", key)
				continue
			}
			stream, err := sess.OpenUDPStream(remote, ul.ruleID)
			if err != nil {
				m.Logger.Error("failed to open udp stream", "rule_id", ul.ruleID, "error", err)
				continue
			}
			flow = &udpFlow{remote: remote, stream: stream, act: make(chan struct{}, 64)}
			m.mu.Lock()
			ul.flows[key] = flow
			m.mu.Unlock()
			go m.udpFlowTX(ul, flow) // UDP socket -> stream
			go m.udpFlowRX(ul, flow) // stream -> UDP socket
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if !writeUDPFrame(flow.stream, payload) {
			m.reapFlow(ul, key)
			continue
		}
		// kick the flow's own watchdog so idle flows eventually close
		select {
		case flow.act <- struct{}{}:
		default:
		}
	}
}

// udpFlowTX: remote client datagrams were already framed into the stream by
// udpLoop; this is stream<-socket direction... actually split cleanly:
//
//	udpLoop reads socket, frames to stream (TX towards client)
//	udpFlowRX reads frames from stream, writes them to the UDP socket
//	udpFlowTX currently: watchdog for idle flow + cleanup on done
func (m *Manager) udpFlowTX(ul *udpListener, flow *udpFlow) {
	t := time.NewTimer(120 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-flow.act:
			if !t.Stop() {
				<-t.C
			}
			t.Reset(120 * time.Second)
		case <-t.C:
			m.reapFlow(ul, flow.remote.String())
			return
		case <-ul.done:
			m.reapFlow(ul, flow.remote.String())
			return
		}
	}
}

func (m *Manager) udpFlowRX(ul *udpListener, flow *udpFlow) {
	for {
		payload, err := readUDPFrame(flow.stream)
		if err != nil {
			m.reapFlow(ul, flow.remote.String())
			return
		}
		if _, err := ul.conn.WriteToUDP(payload, flow.remote); err != nil {
			m.reapFlow(ul, flow.remote.String())
			return
		}
	}
}

func (m *Manager) reapFlow(ul *udpListener, key string) {
	m.mu.Lock()
	flow, ok := ul.flows[key]
	if ok {
		delete(ul.flows, key)
	}
	m.mu.Unlock()
	if ok {
		flow.stream.Close()
	}
}

// ClosePort closes the TCP and/or UDP listener on a port. Called when the
// rule driving it is disabled or deleted.
func (m *Manager) ClosePort(protocol string, port uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch protocol {
	case "tcp":
		if tl, ok := m.tcp[port]; ok {
			close(tl.done)
			tl.ln.Close()
			delete(m.tcp, port)
			m.Logger.Info("closed public TCP listener", "port", port)
		}
	case "udp":
		if ul, ok := m.udp[port]; ok {
			close(ul.done)
			for key := range ul.flows {
				m.reapFlowLocked(ul, key)
			}
			ul.conn.Close()
			delete(m.udp, port)
			m.Logger.Info("closed public UDP listener", "port", port)
		}
	}
}

func (m *Manager) reapFlowLocked(ul *udpListener, key string) {
	flow, ok := ul.flows[key]
	if ok {
		delete(ul.flows, key)
		flow.stream.Close()
	}
}

// OpenPorts returns a snapshot of currently open (protocol, port) -> ruleID
// pairs, used by Reconcile to compute the diff.
func (m *Manager) OpenPorts() map[string]uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]uint32)
	for port, tl := range m.tcp {
		out[fmt.Sprintf("tcp:%d", port)] = tl.ruleID
	}
	for port, ul := range m.udp {
		out[fmt.Sprintf("udp:%d", port)] = ul.ruleID
	}
	return out
}

// Reconcile makes the set of open listeners exactly match the desired set:
// opens new/missing ports, closes ports no longer desired, and restarts a
// port whose owning rule ID changed (rule deleted and recreated with the
// same port).
func (m *Manager) Reconcile(desired []RuleView) {
	want := make(map[string]RuleView)
	for _, r := range desired {
		// dual-stack rules become two entries: tcp:port and udp:port
		for _, v := range expandRule(r) {
			want[fmt.Sprintf("%s:%d", v.Protocol, v.Port)] = v
		}
	}
	have := m.OpenPorts()
	for key, ruleID := range have {
		w, ok := want[key]
		if !ok || w.ID != ruleID {
			protocol, portStr, _ := strings.Cut(key, ":")
			var port int
			fmt.Sscanf(portStr, "%d", &port)
			m.ClosePort(protocol, uint16(port))
		}
	}
	for key, r := range want {
		if existingID, ok := have[key]; !ok || existingID != r.ID {
			if err := m.OpenRule(r); err != nil {
				m.Logger.Warn("reconcile: could not open rule port", "rule_id", r.ID, "protocol", r.Protocol, "port", r.Port, "error", err)
			}
		}
	}
}

// CloseRule closes any listener driven by the given rule ID (port+protocol
// not required from the caller because rule IDs map 1:1 at a moment in
// time to one port+protocol row).
func (m *Manager) CloseRule(ruleID uint32, protocol string, port uint16) {
	for _, v := range expandRule(RuleView{ID: ruleID, Protocol: protocol, Port: port}) {
		m.ClosePort(v.Protocol, v.Port)
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
