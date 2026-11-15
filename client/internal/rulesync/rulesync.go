//go:build linux || darwin

// Package rulesync 是 Client 端针对 Server 推送的转发规则的本地协调器。
// 每次握手之后以及面板侧每次修改规则之后，Client 都会从 Server 收到一条
// 完整的 RulesSnapshot 消息，并根据每个流的元数据中携带的规则 ID，把传入的
// 连接流分发到正确的本地端点。
//
// 平台差异通过两个钩子隔离（见 spoofer_linux.go / spoofer_darwin.go）：
// Linux 依据对本地目标端口归属者的探测结果，在宿主机或容器 netns 中使用
// TPROXY 式伪造源地址拨号以保留真实源 IP；macOS 暂不支持源 IP 保留，
// 开启该选项的规则会自动降级为普通转发。
package rulesync

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"opennofrp/pkg/netrelay"
	"opennofrp/pkg/protocol"
)

// Reconciler 保存最新的规则快照以及每条规则的运行时状态。
type Reconciler struct {
	Logger   *slog.Logger
	StateDir string

	mu            sync.RWMutex
	rules         map[uint32]protocol.Rule
	preparedNetns map[int]bool // 容器 PID -> 其 netns 是否已配置 sysctls+路由（仅 Linux 使用）
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

// Apply 安装一份新的完整快照；不再存在的规则会被丢弃（后续流按其 ID
// 查找时将以失败关闭的方式处理）。
func (r *Reconciler) Apply(rules []protocol.Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = make(map[uint32]protocol.Rule, len(rules))
	for _, rule := range rules {
		r.rules[uint32(rule.ID)] = rule
		if rule.PreserveSourceIP && !sourceIPSupported() {
			r.Logger.Warn("rule requests source IP preservation, unsupported on this platform; plain forwarding will be used", "rule", rule.Name)
		}
	}
	r.Logger.Info("rules snapshot applied", "count", len(rules))
}

// Get 按数据库 ID（由 StreamMetadata 携带）查找规则。
func (r *Reconciler) Get(ruleID uint32) (protocol.Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.rules[ruleID]
	return rule, ok
}

// ServeStream 根据 RuleID 分发一个由 Server 打开的流。它会阻塞直到中继结束，
// 应在 goroutine 中调用。
func (r *Reconciler) ServeStream(ctx context.Context, meta protocol.StreamMetadata, stream net.Conn) {
	defer stream.Close()

	rule, ok := r.Get(meta.RuleID)
	if !ok {
		r.Logger.Error("stream for unknown rule id, dropping", "rule_id", meta.RuleID)
		if meta.HasFlag(protocol.FlagDialAck) {
			_, _ = stream.Write([]byte{protocol.DialAckFailed})
		}
		return
	}
	// 端口段规则：按该连接的公网端口偏移映射到对应的本地端口。
	if meta.PortOffset != 0 {
		if rule.RemotePortEnd == 0 || uint32(rule.LocalPort)+uint32(meta.PortOffset) > 65535 {
			r.Logger.Error("stream port offset out of range, dropping", "rule_id", meta.RuleID, "offset", meta.PortOffset)
			if meta.HasFlag(protocol.FlagDialAck) {
				_, _ = stream.Write([]byte{protocol.DialAckFailed})
			}
			return
		}
		rule.LocalPort += meta.PortOffset
	}

	switch meta.Transport {
	case protocol.TransportTCP:
		// Server（HTTP/TLS 模式）要求拨号确认：serveTCP 只有在成功拨通本地服务后
		// 才会开始读写 stream，ackConn 在第一次读/写时先回写 DialAckOK；
		// 若未触碰 stream 即返回（拨号失败），则回写 DialAckFailed，
		// 让 Server 能展示“服务不可用”页面。
		if meta.HasFlag(protocol.FlagDialAck) {
			ac := &ackConn{Conn: stream}
			r.serveTCP(ctx, rule, meta, ac)
			ac.finish()
			return
		}
		r.serveTCP(ctx, rule, meta, stream)
	case protocol.TransportUDP:
		r.serveUDP(ctx, rule, meta, stream)
	default:
		r.Logger.Error("unknown transport on stream metadata", "transport", meta.Transport)
	}
}

// ackConn 包装一个要求拨号确认的流：首次 Read/Write 之前先写出 DialAckOK；
// finish 在从未读写过（即拨号失败）时写出 DialAckFailed。
type ackConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (a *ackConn) ack(status byte) {
	a.once.Do(func() {
		_, a.err = a.Conn.Write([]byte{status})
	})
}

func (a *ackConn) Read(p []byte) (int, error) {
	a.ack(protocol.DialAckOK)
	if a.err != nil {
		return 0, a.err
	}
	return a.Conn.Read(p)
}

func (a *ackConn) Write(p []byte) (int, error) {
	a.ack(protocol.DialAckOK)
	if a.err != nil {
		return 0, a.err
	}
	return a.Conn.Write(p)
}

func (a *ackConn) finish() { a.ack(protocol.DialAckFailed) }

func (r *Reconciler) serveTCP(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata, stream net.Conn) {
	target := net.JoinHostPort(rule.LocalIP, fmt.Sprint(rule.LocalPort))

	if !rule.PreserveSourceIP {
		r.relayPlain(ctx, rule, meta, stream, target)
		return
	}

	// 已要求保留源 IP：交给平台相关的伪造源地址拨号实现。返回 (nil, nil)
	// 表示该路径不可用、回退普通转发；返回错误表示应丢弃该连接。
	upstream, err := r.dialPreservingSource(ctx, rule, meta, target)
	if err != nil {
		r.Logger.Warn("spoofed dial failed, dropping connection", "rule", rule.Name, "error", err)
		return
	}
	if upstream == nil {
		r.relayPlain(ctx, rule, meta, stream, target)
		return
	}
	defer upstream.Close()
	r.relayUpstream(rule, meta, stream, upstream)
}

// relayPlain 以普通转发方式拨号并中继一条流（源 IP 保留不可用时的统一回退路径）。
func (r *Reconciler) relayPlain(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata, stream net.Conn, target string) {
	upstream, err := dialPlain(ctx, target)
	if err != nil {
		r.Logger.Warn("plain dial failed, dropping", "rule", rule.Name, "target", target, "error", err)
		return
	}
	defer upstream.Close()
	r.relayUpstream(rule, meta, stream, upstream)
}

// serveUDP 转发一个 UDP 流。开启 preserve_source_ip 时先尝试伪造源地址拨号
// （平台相关），失败时回退为普通转发，保证流可用。
func (r *Reconciler) serveUDP(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata, stream net.Conn) {
	target := net.JoinHostPort(rule.LocalIP, fmt.Sprint(rule.LocalPort))
	var upstream net.Conn
	if rule.PreserveSourceIP && meta.ClientAddr != nil && !meta.ClientAddr.IsUnspecified() {
		c, err := r.dialSpoofedUDP(ctx, rule, meta)
		if err != nil {
			r.Logger.Warn("udp spoofed dial failed, falling back to plain forwarding", "rule", rule.Name, "error", err)
		} else {
			upstream = c
		}
	}
	if upstream == nil {
		c, err := net.Dial("udp", target)
		if err != nil {
			r.Logger.Warn("udp dial failed, dropping", "rule", rule.Name, "target", target, "error", err)
			return
		}
		upstream = c
	}
	defer upstream.Close()

	// 流是字节管道，而 UDP 是数据报：需对每个数据报进行分帧。
	closeBoth := func() {
		_ = stream.SetDeadline(time.Now())
		_ = upstream.SetDeadline(time.Now())
		_ = stream.Close()
		_ = upstream.Close()
	}
	done := make(chan struct{}, 2)
	go func() {
		copyUDPFrames(stream, upstream)
		closeBoth()
		done <- struct{}{}
	}()
	go func() {
		copyUDPFramesReverse(upstream, stream)
		closeBoth()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func dialPlain(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func relay(a, b net.Conn) { _ = netrelay.Relay(a, b) }

// 在流上对 UDP 分帧：每个数据报格式为 [uint16 大端序长度][payload]。
// 第一个（携带元数据的）方向在分帧开始之前，其头部已被 ReadStreamMetadata 读取消费。
func copyUDPFrames(stream, upstream net.Conn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := upstream.Read(buf)
		if n > 0 || err == nil {
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
	if err := writeAll(w, hdr); err != nil {
		return false
	}
	if err := writeAll(w, payload); err != nil {
		return false
	}
	return true
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
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

func (c *ackConn) CloseWrite() error { return netrelay.CloseWrite(c.Conn) }
