// Package listener 管理面向公网的 TCP/UDP 监听器，这些监听器将流量转发到
// Client 会话中。打开的端口集合完全由 rules 表驱动：启用一条规则即打开其
// 公网端口，禁用则关闭它。关键在于：不使用原始套接字，不使用
// iptables/nftables/路由——本包正是 docs/01-architecture.md 中“云服务器
// 保持纯用户态”这一原则的体现。
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

// RuleView 仅携带监听器从 rules 表某一行中所需的字段。
type RuleView struct {
	ID       uint32
	ClientID string
	Protocol string // "tcp"、"udp"、"tcp+udp"（双栈）或 "http"
	Port     uint16

	// 以下字段仅用于 http 规则。
	Name        string
	Domains     []string // 已规范化；为空表示匹配任意 Host
	PathPrefix  string   // 已规范化，以 "/" 开头
	OfflinePage string
	// IPSources 是按优先级排列的真实客户端 IP 来源（见 realip.go）。
	IPSources []string
	// TrustedProxies 非空时，仅当 TCP 对端属于其中之一才信任请求头中的 IP。
	TrustedProxies []*net.IPNet
}

// expandRule 将一条双栈（"tcp+udp"）规则拆分为一个 TCP 视图和一个 UDP
// 视图，二者共享相同的规则 ID 和端口。单协议规则原样返回。
func expandRule(r RuleView) []RuleView {
	if r.Protocol == "tcp+udp" {
		t, u := r, r
		t.Protocol = "tcp"
		u.Protocol = "udp"
		return []RuleView{t, u}
	}
	return []RuleView{r}
}

// ruleView 保留旧的未导出别名形式；新代码请使用 RuleView。
type ruleView = RuleView

// SessionLookup 返回某个 client ID 对应的在线会话；若该 Client 当前未连接，
// 则返回 nil。由 server 结构体实现。
type SessionLookup func(clientID string) *session.Session

type Manager struct {
	BindAddr string
	Logger   *slog.Logger
	Lookup   SessionLookup

	mu   sync.Mutex
	tcp  map[uint16]*tcpListener
	udp  map[uint16]*udpListener
	http map[uint16]*httpListener
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
	act    chan struct{} // 接收来自解复用循环的客户端数据报
}

func NewManager(bindAddr string, logger *slog.Logger, lookup SessionLookup) *Manager {
	return &Manager{
		BindAddr: bindAddr,
		Logger:   logger,
		Lookup:   lookup,
		tcp:      make(map[uint16]*tcpListener),
		udp:      make(map[uint16]*udpListener),
		http:     make(map[uint16]*httpListener),
	}
}

// OpenRule 开始监听给定规则的协议+端口。对每个 (protocol, port) 是幂等的：
// 以相同标识再次调用不做任何事；对已打开的端口以不同的 ruleID 调用则返回
// 错误（先到先得）。
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
	if _, ok := m.http[r.Port]; ok {
		return fmt.Errorf("listener: tcp port %d already open as an http listener", r.Port)
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
			go m.udpFlowTX(ul, flow) // UDP 套接字 -> stream
			go m.udpFlowRX(ul, flow) // stream -> UDP 套接字
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if !writeUDPFrame(flow.stream, payload) {
			m.reapFlow(ul, key)
			continue
		}
		// 触发该流自身的看门狗，使空闲流最终能够关闭
		select {
		case flow.act <- struct{}{}:
		default:
		}
	}
}

// udpFlowTX：远端客户端的数据报已由 udpLoop 封帧写入 stream；这是
// stream<-socket 方向……实际上职责划分如下：
//
//	udpLoop 读取套接字，封帧写入 stream（朝向 client 的 TX）
//	udpFlowRX 从 stream 读取帧，将其写入 UDP 套接字
//	udpFlowTX 目前：空闲流的看门狗 + done 时的清理
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

// ClosePort 关闭某个端口上的 TCP 和/或 UDP 监听器。在驱动它的规则被禁用或
// 删除时调用。
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

// OpenPorts 返回当前已打开的 (protocol, port) -> ruleID 映射的快照，供
// Reconcile 计算差异使用。
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

// Reconcile 使已打开的监听器集合与期望集合完全一致：打开新增/缺失的端口，
// 关闭不再需要的端口，并重启所属规则 ID 已变化的端口（规则被删除后以相同
// 端口重新创建）。
func (m *Manager) Reconcile(desired []RuleView) {
	want := make(map[string]RuleView)
	var httpRules []RuleView
	for _, r := range desired {
		if r.Protocol == "http" {
			httpRules = append(httpRules, r)
			continue
		}
		// 双栈规则会变成两个条目：tcp:port 和 udp:port
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
	// 先关闭不再需要的 HTTP 端口并更新路由，再打开 TCP/UDP 端口，
	// 使 http -> tcp 的协议切换能释放端口。
	m.reconcileHTTP(httpRules)
	for key, r := range want {
		if existingID, ok := have[key]; !ok || existingID != r.ID {
			if err := m.OpenRule(r); err != nil {
				m.Logger.Warn("reconcile: could not open rule port", "rule_id", r.ID, "protocol", r.Protocol, "port", r.Port, "error", err)
			}
		}
	}
}

// CloseRule 关闭由给定规则 ID 驱动的所有监听器（之所以不需要调用方提供
// port+protocol，是因为在任一时刻规则 ID 都与一行 port+protocol 一一对应）。
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
