// Package rulesync 是 Client 端针对 Server 推送的转发规则的本地协调器。
// 每次握手之后以及面板侧每次修改规则之后，Client 都会从 Server 收到一条
// 完整的 RulesSnapshot 消息，并根据每个流的元数据中携带的规则 ID，把传入的
// 连接流分发到正确的本地端点——转发策略（plain / 宿主机 netns 中的
// TPROXY 式伪造源地址拨号 / 容器 netns 中的伪造源地址拨号）由对本地目标端口
// 重新执行的 DetectPortOwner 探测结果决定。
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

// sharedFWMark 是所有伪造源地址连接所使用的 fwmark。它必须与安装宿主机/容器
// 策略路由以及 OUTPUT CONNMARK save/restore 规则对时所用的值一致
// （即取值相同的 tproxy.DefaultFWMark）。
const sharedFWMark = tproxy.DefaultFWMark

// Reconciler 保存最新的规则快照以及每条规则的运行时状态。
type Reconciler struct {
	Logger   *slog.Logger
	StateDir string

	mu            sync.RWMutex
	rules         map[uint32]protocol.Rule
	preparedNetns map[int]bool // 容器 PID -> 其 netns 是否已配置 sysctls+路由
	hostSetupDone bool

	// backends 负责多后端规则的负载均衡、故障转移与健康检查（见 backends.go）。
	backends *backendPool
}

func New(logger *slog.Logger, stateDir string) *Reconciler {
	r := &Reconciler{
		Logger:        logger,
		StateDir:      stateDir,
		rules:         make(map[uint32]protocol.Rule),
		preparedNetns: make(map[int]bool),
		backends:      newBackendPool(),
	}
	go r.backends.healthLoop(context.Background(), r.allRules)
	return r
}

// allRules 返回当前快照中全部规则的副本（供健康检查使用）。
func (r *Reconciler) allRules() []protocol.Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]protocol.Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule)
	}
	return out
}

// Apply 安装一份新的完整快照；不再存在的规则会被丢弃（后续流按其 ID
// 查找时将以失败关闭的方式处理）。
func (r *Reconciler) Apply(rules []protocol.Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = make(map[uint32]protocol.Rule, len(rules))
	for _, rule := range rules {
		r.rules[uint32(rule.ID)] = rule
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
		rule.Backends = nil // 端口段规则不支持多后端
	}

	switch meta.Transport {
	case protocol.TransportTCP:
		var conn net.Conn = stream
		var ac *ackConn
		if meta.HasFlag(protocol.FlagDialAck) {
			// Server（HTTP/TLS 模式）要求拨号确认：serveTCP 只有在成功拨通本地服务后
			// 才会开始读写 stream，ackConn 在第一次读/写时先回写 DialAckOK；
			// 若所有后端都未触碰 stream 即返回（拨号失败），则回写 DialAckFailed，
			// 让 Server 能展示“服务不可用”页面。
			ac = &ackConn{Conn: stream}
			conn = ac
		}
		// 多后端：按策略依次尝试，serveTCP 未触碰 stream 即返回视为该后端拨号失败。
		targets := r.backends.order(rule)
		for _, addr := range targets {
			tr, ok := withTarget(rule, addr)
			if !ok {
				continue
			}
			tc := &touchConn{Conn: conn}
			r.serveTCP(ctx, tr, meta, tc)
			if tc.touched.Load() {
				if len(targets) > 1 {
					r.backends.markOK(addr)
				}
				break
			}
			if len(targets) > 1 {
				r.Logger.Warn("backend dial failed, trying next backend", "rule", rule.Name, "backend", addr)
				r.backends.markFailed(addr)
			}
		}
		if ac != nil {
			ac.finish()
		}
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
		upstream, err := dialPlain(ctx, target)
		if err != nil {
			r.Logger.Warn("plain dial failed, dropping", "rule", rule.Name, "target", target, "error", err)
			return
		}
		defer upstream.Close()
		r.relayUpstream(rule, meta, stream, upstream)
		return
	}

	// 已要求保留源 IP：根据对本地目标端口归属者的实时探测来选择策略。
	// 每个连接都重新执行 DetectPortOwner 很重要，因为 Docker 容器重启后
	// 其 PID 会改变（/proc/<pid>/ns/net 也随之不同），否则过期的 PID
	// 会悄无声息地进入已失效的命名空间。
	owner, err := envcheck.DetectPortOwner(rule.LocalPort)
	if err != nil {
		r.Logger.Warn("cannot determine port owner, falling back to plain forwarding",
			"rule", rule.Name, "port", rule.LocalPort, "error", err)
		upstream, err := dialPlain(ctx, target)
		if err != nil {
			return
		}
		defer upstream.Close()
		r.relayUpstream(rule, meta, stream, upstream)
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
			r.relayUpstream(rule, meta, stream, upstream)
			return
		}
		dialer := tproxy.SpoofedDialer{FWMark: sharedFWMark}
		upstream, err := dialer.DialSpoofed(ctx, meta.ClientAddr, net.ParseIP(rule.LocalIP), rule.LocalPort)
		if err != nil {
			r.Logger.Warn("spoofed dial failed, dropping connection", "rule", rule.Name, "error", err)
			return
		}
		defer upstream.Close()
		r.relayUpstream(rule, meta, stream, upstream)

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
			r.relayUpstream(rule, meta, stream, upstream)
			return
		}

		// bridge 网络容器：整个伪造源地址的连接必须在该容器的网络命名空间
		// 【内部】创建——宿主机上的任何 iptables/TPROXY 都无法在 Docker 的
		// bridge MASQUERADE 之后保留下来，参见 docs/01-architecture.md 第 6.5 节。
		// 该 goroutine 必须在调用 socket() 之前以 runtime.LockOSThread 的方式
		// Enter() 此 netns。
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
			r.relayUpstream(rule, meta, stream, upstream)
		}

	default:
		r.Logger.Warn("unknown port owner kind, falling back to plain forwarding", "rule", rule.Name, "kind", owner.Kind.String())
		upstream, err := dialPlain(ctx, target)
		if err != nil {
			return
		}
		defer upstream.Close()
		r.relayUpstream(rule, meta, stream, upstream)
	}
}

// serveUDP 转发一个 UDP 流。开启 preserve_source_ip 时，按本地端口归属者选择
// 伪造源地址拨号（宿主机 netns 或容器 netns 内，与 TCP 相同的策略路由 +
// CONNMARK 回包规则）；任何一步失败都回退为普通转发，保证流可用。
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
	go copyUDPFrames(stream, upstream)
	copyUDPFramesReverse(upstream, stream)
}

// ensureHostTPROXYReady 应用伪造源地址拨号所需的宿主机级 sysctls、策略路由
// 以及 OUTPUT CONNMARK save/restore 规则对，每个进程只执行一次。这里不需要
// 入站 TPROXY mangle 规则：yamux 流已携带原始客户端地址，因此 Client 直接使用
// SO_MARK/IP_TRANSPARENT 拨号——但回包方向仍需要 CONNMARK 恢复，否则服务的
// SYN-ACK 会经默认网关路由出去，导致握手超时（参见 tproxy.EnsureConnmarkReplyRules）。
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

// ensureNetnsReady 在容器的 netns 内应用 sysctls + 策略路由，每个容器 PID
// 只执行一次。通过 RunInNamespace 执行，确保写入落在容器自身的 eth0/lo/all 条目上。
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
		// 回包路径的要求与宿主机路径相同，但安装在容器的 netns 内
		// （我们已通过 setns() 进入，因此 iptables-legacy 操作的是容器自己的表）。
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

// 在流上对 UDP 分帧：每个数据报格式为 [uint16 大端序长度][payload]。
// 第一个（携带元数据的）方向在分帧开始之前，其头部已被 ReadStreamMetadata 读取消费。
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
