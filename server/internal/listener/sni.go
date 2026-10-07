package listener

// TLS 透传（protocol = "tls"）：Server 只窥探访问者 ClientHello 中的 SNI，按
// 域名路由到对应规则，不解密流量（证书由内网后端自己持有）。多条 TLS 规则
// 可按域名共享同一公网端口。窥探到的原始字节会原样转发给后端。
//
// 每个连接以 TransportTCP 流 + FlagDialAck + SNI 尾部提示的形式发给 Client；
// Client 拨号失败时 Server 直接关闭访问者连接（TLS 层无法返回 HTML 页面）。

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"opennofrp/pkg/protocol"
)

// sniPeekTimeout 是读取 ClientHello 的最长时间。
const sniPeekTimeout = 10 * time.Second

type tlsPassRoute struct {
	RuleID   uint32
	ClientID string
	Name     string
	Domains  []string // 已规范化；为空表示兜底（含未发送 SNI 的连接）
}

type tlsPassListener struct {
	port   uint16
	ln     net.Listener
	done   chan struct{}
	mu     sync.RWMutex
	routes []tlsPassRoute
}

func (tl *tlsPassListener) setRoutes(routes []tlsPassRoute) {
	sorted := append([]tlsPassRoute(nil), routes...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].RuleID < sorted[j].RuleID })
	tl.mu.Lock()
	tl.routes = sorted
	tl.mu.Unlock()
}

// matchSNIRoute 选出与 SNI 最匹配的路由（精确 > 通配 > 兜底）。
func matchSNIRoute(routes []tlsPassRoute, sni string) (tlsPassRoute, bool) {
	host := normalizeRequestHost(sni)
	var best tlsPassRoute
	bestScore := 0
	for _, r := range routes {
		var s int
		if host == "" {
			if len(r.Domains) == 0 {
				s = 1
			}
		} else {
			s = hostMatchScore(host, r.Domains)
		}
		if s > bestScore {
			best, bestScore = r, s
		}
	}
	return best, bestScore > 0
}

// recordingConn 只读地包装连接：记录读到的全部字节，写入一律失败。用于在不
// 完成 TLS 握手的前提下解析 ClientHello。
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

func (c *recordingConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

var errHelloCaptured = errors.New("sni: client hello captured")

// peekClientHello 读取访问者的 ClientHello 并返回其 SNI 与已读出的原始字节
// （必须原样转发给后端）。
func peekClientHello(conn net.Conn) (sni string, peeked []byte, err error) {
	rc := &recordingConn{Conn: conn}
	var hello *tls.ClientHelloInfo
	srv := tls.Server(rc, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			cp := *h
			hello = &cp
			return nil, errHelloCaptured
		},
	})
	_ = srv.Handshake()
	if hello == nil {
		return "", rc.buf.Bytes(), errors.New("sni: not a TLS ClientHello")
	}
	return hello.ServerName, rc.buf.Bytes(), nil
}

func (m *Manager) tlsPassAcceptLoop(tl *tlsPassListener) {
	for {
		conn, err := tl.ln.Accept()
		if err != nil {
			select {
			case <-tl.done:
				return
			default:
			}
			m.Logger.Error("tls passthrough accept failed, closing listener", "port", tl.port, "error", err)
			return
		}
		go m.handleTLSPassConn(tl, conn)
	}
}

func (m *Manager) handleTLSPassConn(tl *tlsPassListener, conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(sniPeekTimeout))
	sni, peeked, err := peekClientHello(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		m.Logger.Warn("tls passthrough: cannot parse ClientHello", "port", tl.port, "remote", conn.RemoteAddr(), "error", err)
		conn.Close()
		return
	}
	tl.mu.RLock()
	route, ok := matchSNIRoute(tl.routes, sni)
	tl.mu.RUnlock()
	if !ok {
		m.Logger.Warn("tls passthrough: no route for sni", "port", tl.port, "sni", sni)
		conn.Close()
		return
	}
	sess := m.Lookup(route.ClientID)
	if sess == nil || !sess.HasCapability(protocol.CapDialAck) {
		m.Logger.Warn("tls passthrough: client offline or outdated", "rule_id", route.RuleID, "sni", sni)
		conn.Close()
		return
	}
	var ip net.IP
	var port uint16
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip, port = ta.IP, uint16(ta.Port)
	}
	stream, err := sess.OpenAckStream(ip, port, route.RuleID, sni, httpDialAckTimeout)
	if err != nil {
		m.Logger.Warn("tls passthrough: backend unavailable", "rule_id", route.RuleID, "sni", sni, "error", err)
		conn.Close()
		return
	}
	if _, err := stream.Write(peeked); err != nil {
		stream.Close()
		conn.Close()
		return
	}
	pipeConns(conn, stream)
}

// pipeConns 双向转发直到任意一方结束，然后关闭两端。
func pipeConns(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

// openTLSPassPort 打开（或更新路由）某个端口上的 TLS 透传监听器。
func (m *Manager) openTLSPassPort(port uint16, routes []tlsPassRoute) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tl, ok := m.tlsPass[port]; ok {
		tl.setRoutes(routes)
		return nil
	}
	if _, ok := m.tcp[port]; ok {
		return fmt.Errorf("listener: tcp port %d already open by a tcp rule", port)
	}
	if _, ok := m.http[port]; ok {
		return fmt.Errorf("listener: tcp port %d already open by an http rule", port)
	}
	addr := net.JoinHostPort(m.BindAddr, strconv.Itoa(int(port)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listener: tls passthrough listen on %s: %w", addr, err)
	}
	tl := &tlsPassListener{port: port, ln: ln, done: make(chan struct{})}
	tl.setRoutes(routes)
	m.tlsPass[port] = tl
	go m.tlsPassAcceptLoop(tl)
	m.Logger.Info("opened public TLS passthrough listener", "port", port, "routes", len(routes))
	return nil
}

func (m *Manager) closeTLSPassPort(port uint16) {
	m.mu.Lock()
	tl, ok := m.tlsPass[port]
	if ok {
		delete(m.tlsPass, port)
	}
	m.mu.Unlock()
	if ok {
		close(tl.done)
		tl.ln.Close()
		m.Logger.Info("closed public TLS passthrough listener", "port", port)
	}
}

// reconcileTLSPass 使 TLS 透传监听器集合与期望的 tls 规则集合一致。
func (m *Manager) reconcileTLSPass(desired []RuleView) {
	byPort := map[uint16][]tlsPassRoute{}
	for _, r := range desired {
		if r.Protocol != "tls" {
			continue
		}
		byPort[r.Port] = append(byPort[r.Port], tlsPassRoute{RuleID: r.ID, ClientID: r.ClientID, Name: r.Name, Domains: r.Domains})
	}
	m.mu.Lock()
	var stale []uint16
	for port := range m.tlsPass {
		if _, ok := byPort[port]; !ok {
			stale = append(stale, port)
		}
	}
	m.mu.Unlock()
	for _, port := range stale {
		m.closeTLSPassPort(port)
	}
	for port, routes := range byPort {
		if err := m.openTLSPassPort(port, routes); err != nil {
			m.Logger.Warn("reconcile: could not open tls passthrough port", "port", port, "error", err)
		}
	}
}
