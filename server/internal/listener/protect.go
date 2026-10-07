package listener

// 规则级防护（所有协议通用）：
//   - IP 白名单 / 黑名单（CIDR）：黑名单优先；白名单非空时只放行名单内地址；
//   - 单 IP 并发连接数上限（HTTP 规则按并发请求计，UDP 规则按并发流计）；
//   - 单 IP 新建连接速率上限（每分钟，令牌桶；HTTP 规则按请求计）；
//   - 规则级带宽上限（KB/s，该规则所有连接共享，上下行合计）。
// 计数器按规则 ID 保存在 Manager 中，配置不变时 Reconcile 不会重置计数。

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// GuardConfig 是一条规则的防护配置；零值表示不做任何限制。
type GuardConfig struct {
	Allow          []*net.IPNet
	Deny           []*net.IPNet
	MaxConnsPerIP  int // 0 = 不限制
	ConnRatePerMin int // 0 = 不限制
	BandwidthKBps  int // 0 = 不限制
}

func (g GuardConfig) empty() bool {
	return len(g.Allow) == 0 && len(g.Deny) == 0 && g.MaxConnsPerIP <= 0 && g.ConnRatePerMin <= 0 && g.BandwidthKBps <= 0
}

func (g GuardConfig) key() string {
	var b strings.Builder
	for _, n := range g.Allow {
		b.WriteString(n.String())
		b.WriteByte(',')
	}
	b.WriteByte('|')
	for _, n := range g.Deny {
		b.WriteString(n.String())
		b.WriteByte(',')
	}
	fmt.Fprintf(&b, "|%d|%d|%d", g.MaxConnsPerIP, g.ConnRatePerMin, g.BandwidthKBps)
	return b.String()
}

// admit 的拒绝原因。
const (
	guardOK           = ""
	guardDenied       = "denied"
	guardTooManyConns = "too_many_conns"
	guardRateLimited  = "rate_limited"
)

type tokenBucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (b *tokenBucket) refill(now time.Time) {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(b.burst, b.tokens+el*b.rate)
		b.last = now
	}
}

func (b *tokenBucket) allow(now time.Time, n float64) bool {
	b.refill(now)
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// reserve 扣除 n 个令牌（可透支），返回需要等待的时长。
func (b *tokenBucket) reserve(now time.Time, n float64) time.Duration {
	b.refill(now)
	b.tokens -= n
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

type ruleGuard struct {
	cfg GuardConfig
	key string

	mu        sync.Mutex
	conns     map[string]int
	rates     map[string]*tokenBucket
	lastSweep time.Time

	bwMu sync.Mutex
	bw   *tokenBucket
}

func newRuleGuard(cfg GuardConfig) *ruleGuard {
	g := &ruleGuard{cfg: cfg, key: cfg.key(), conns: map[string]int{}, rates: map[string]*tokenBucket{}, lastSweep: time.Now()}
	if cfg.BandwidthKBps > 0 {
		r := float64(cfg.BandwidthKBps) * 1024
		g.bw = newTokenBucket(r, r) // 允许 1 秒突发
	}
	return g
}

func guardIPInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// admit 判断来自 ip 的新连接（或 HTTP 请求）是否放行。放行时返回的 release
// 必须在连接结束时调用（多次调用安全）。g 为 nil 时总是放行。
func (g *ruleGuard) admit(ip net.IP) (release func(), reason string) {
	noop := func() {}
	if g == nil {
		return noop, guardOK
	}
	if ip != nil && guardIPInNets(ip, g.cfg.Deny) {
		return noop, guardDenied
	}
	if len(g.cfg.Allow) > 0 && (ip == nil || !guardIPInNets(ip, g.cfg.Allow)) {
		return noop, guardDenied
	}
	if g.cfg.MaxConnsPerIP <= 0 && g.cfg.ConnRatePerMin <= 0 {
		return noop, guardOK
	}
	key := ""
	if ip != nil {
		key = ip.String()
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked(now)
	if g.cfg.MaxConnsPerIP > 0 && g.conns[key] >= g.cfg.MaxConnsPerIP {
		return noop, guardTooManyConns
	}
	if g.cfg.ConnRatePerMin > 0 {
		b := g.rates[key]
		if b == nil {
			per := float64(g.cfg.ConnRatePerMin)
			b = newTokenBucket(per/60, per)
			g.rates[key] = b
		}
		if !b.allow(now, 1) {
			return noop, guardRateLimited
		}
	}
	if g.cfg.MaxConnsPerIP <= 0 {
		return noop, guardOK
	}
	g.conns[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			g.conns[key]--
			if g.conns[key] <= 0 {
				delete(g.conns, key)
			}
			g.mu.Unlock()
		})
	}, guardOK
}

// sweepLocked 每分钟清理一次已回满（长时间无新连接）的速率桶，防止内存增长。
func (g *ruleGuard) sweepLocked(now time.Time) {
	if now.Sub(g.lastSweep) < time.Minute {
		return
	}
	g.lastSweep = now
	for k, b := range g.rates {
		b.refill(now)
		if b.tokens >= b.burst {
			delete(g.rates, k)
		}
	}
}

// waitBandwidth 为 n 字节扣除带宽令牌，并阻塞到允许继续为止。
func (g *ruleGuard) waitBandwidth(n int) {
	if g == nil || g.bw == nil || n <= 0 {
		return
	}
	g.bwMu.Lock()
	d := g.bw.reserve(time.Now(), float64(n))
	g.bwMu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
}

// allowBandwidth 是非阻塞版本，供 UDP 使用：超出带宽的数据报直接丢弃。
func (g *ruleGuard) allowBandwidth(n int) bool {
	if g == nil || g.bw == nil {
		return true
	}
	g.bwMu.Lock()
	defer g.bwMu.Unlock()
	return g.bw.allow(time.Now(), float64(n))
}

const throttleChunk = 16 * 1024

// throttledConn 对读写双向按规则带宽限速（共享同一令牌桶）。
type throttledConn struct {
	net.Conn
	g *ruleGuard
}

func (c *throttledConn) Read(p []byte) (int, error) {
	if len(p) > throttleChunk {
		p = p[:throttleChunk]
	}
	n, err := c.Conn.Read(p)
	c.g.waitBandwidth(n)
	return n, err
}

func (c *throttledConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		k := min(len(p), throttleChunk)
		c.g.waitBandwidth(k)
		n, err := c.Conn.Write(p[:k])
		total += n
		if err != nil {
			return total, err
		}
		p = p[k:]
	}
	return total, nil
}

// releaseConn 在关闭时调用 release（释放并发连接计数），多次 Close 安全。
type releaseConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *releaseConn) Close() error {
	err := c.Conn.Close()
	if c.release != nil {
		c.once.Do(c.release)
	}
	return err
}

// wrapConn 在规则设置了带宽上限时返回限速包装后的连接，否则原样返回。
func (g *ruleGuard) wrapConn(c net.Conn) net.Conn {
	if g == nil || g.bw == nil {
		return c
	}
	return &throttledConn{Conn: c, g: g}
}

// setGuards 根据期望规则集合更新各规则的防护器；配置未变化的规则保留原有计数。
func (m *Manager) setGuards(desired []RuleView) {
	next := make(map[uint32]*ruleGuard)
	m.guardMu.Lock()
	defer m.guardMu.Unlock()
	for _, r := range desired {
		if r.Guard.empty() {
			continue
		}
		k := r.Guard.key()
		if old, ok := m.guards[r.ID]; ok && old.key == k {
			next[r.ID] = old
			continue
		}
		next[r.ID] = newRuleGuard(r.Guard)
	}
	m.guards = next
}

// guardFor 返回规则的防护器；未配置防护时返回 nil（nil 防护器的方法总是放行）。
func (m *Manager) guardFor(ruleID uint32) *ruleGuard {
	m.guardMu.Lock()
	defer m.guardMu.Unlock()
	return m.guards[ruleID]
}
