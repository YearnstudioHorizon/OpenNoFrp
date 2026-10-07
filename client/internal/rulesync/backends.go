package rulesync

// 多后端负载均衡与故障转移（Client 侧）：一条规则除 LocalIP:LocalPort 外还可携带
// 额外后端（protocol.Rule.Backends）。每个新连接按规则的 LBStrategy 给出后端尝试
// 顺序，拨号失败时依次尝试下一个；失败的后端会被标记为不健康一段时间，周期性的
// TCP 健康检查负责将其恢复。所有后端都不健康时仍会按原顺序尝试（宁可试一次也
// 不直接拒绝）。

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"opennofrp/pkg/protocol"
)

const (
	backendFailCooldown   = 30 * time.Second
	backendHealthInterval = 10 * time.Second
	backendHealthTimeout  = 2 * time.Second
)

type backendPool struct {
	mu        sync.Mutex
	rr        map[uint32]uint32
	unhealthy map[string]time.Time // 后端地址 -> 不健康截止时间
}

func newBackendPool() *backendPool {
	return &backendPool{rr: map[uint32]uint32{}, unhealthy: map[string]time.Time{}}
}

// ruleTargets 返回规则的全部后端地址（主后端在前，去重，忽略非法条目）。
func ruleTargets(rule protocol.Rule) []string {
	primary := net.JoinHostPort(rule.LocalIP, fmt.Sprint(rule.LocalPort))
	out := []string{primary}
	seen := map[string]bool{primary: true}
	for _, b := range rule.Backends {
		b = strings.TrimSpace(b)
		if b == "" || seen[b] {
			continue
		}
		if _, _, err := splitTarget(b); err != nil {
			continue
		}
		seen[b] = true
		out = append(out, b)
	}
	return out
}

func splitTarget(addr string) (string, uint16, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	if net.ParseIP(h) == nil {
		return "", 0, fmt.Errorf("backend %q: host must be an IP", addr)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return "", 0, fmt.Errorf("backend %q: bad port", addr)
	}
	return h, uint16(n), nil
}

// withTarget 返回把 LocalIP/LocalPort 替换为 addr 的规则副本（供现有拨号逻辑复用）。
func withTarget(rule protocol.Rule, addr string) (protocol.Rule, bool) {
	h, p, err := splitTarget(addr)
	if err != nil {
		return rule, false
	}
	rule.LocalIP, rule.LocalPort = h, p
	return rule, true
}

// order 按策略返回本次连接的后端尝试顺序：健康后端在前，不健康后端垫底。
func (p *backendPool) order(rule protocol.Rule) []string {
	targets := ruleTargets(rule)
	if len(targets) == 1 {
		return targets
	}
	p.mu.Lock()
	switch rule.LBStrategy {
	case "failover":
		// 保持配置顺序
	case "random":
		rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	default: // round_robin
		id := uint32(rule.ID)
		start := int(p.rr[id] % uint32(len(targets)))
		p.rr[id]++
		targets = append(targets[start:], targets[:start]...)
	}
	now := time.Now()
	var healthy, sick []string
	for _, t := range targets {
		if until, bad := p.unhealthy[t]; bad && now.Before(until) {
			sick = append(sick, t)
		} else {
			healthy = append(healthy, t)
		}
	}
	p.mu.Unlock()
	return append(healthy, sick...)
}

// touchConn 记录流是否被读写过：serveTCP 只有在拨通后端后才会读写 stream，
// 因此未被触碰表示该后端拨号失败，可以安全地换下一个后端重试。
type touchConn struct {
	net.Conn
	touched atomic.Bool
}

func (t *touchConn) Read(p []byte) (int, error) {
	t.touched.Store(true)
	return t.Conn.Read(p)
}

func (t *touchConn) Write(p []byte) (int, error) {
	t.touched.Store(true)
	return t.Conn.Write(p)
}

// Close 不向下传递：stream 的生命周期由 ServeStream 管理，换后端重试时不能关闭它。
func (t *touchConn) Close() error { return nil }

func (p *backendPool) markFailed(addr string) {
	p.mu.Lock()
	p.unhealthy[addr] = time.Now().Add(backendFailCooldown)
	p.mu.Unlock()
}

func (p *backendPool) markOK(addr string) {
	p.mu.Lock()
	delete(p.unhealthy, addr)
	p.mu.Unlock()
}

// healthLoop 周期性地对多后端规则的每个后端做 TCP 连接探测，直到 ctx 结束。
func (p *backendPool) healthLoop(ctx context.Context, rules func() []protocol.Rule) {
	t := time.NewTicker(backendHealthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		seen := map[string]bool{}
		for _, rule := range rules() {
			targets := ruleTargets(rule)
			if len(targets) < 2 || rule.Protocol == protocol.RuleProtocolUDP {
				continue
			}
			for _, addr := range targets {
				if seen[addr] {
					continue
				}
				seen[addr] = true
				d := net.Dialer{Timeout: backendHealthTimeout}
				c, err := d.DialContext(ctx, "tcp", addr)
				if err != nil {
					p.markFailed(addr)
					continue
				}
				c.Close()
				p.markOK(addr)
			}
		}
	}
}
