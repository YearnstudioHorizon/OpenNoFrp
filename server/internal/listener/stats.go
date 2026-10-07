package listener

// 规则级统计（可观测性）：活跃连接数、累计连接数、被防护拒绝次数、上下行字节、
// 后端（Client 本地服务）拨号失败次数与最近一次错误。HTTP 规则按请求计连接。
// 计数器按规则 ID 保存在 Manager 中，规则从期望集合中移除时一并清除。

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// RuleStats 是某条规则统计数据的快照。
type RuleStats struct {
	RuleID        uint32
	ActiveConns   int64
	TotalConns    uint64
	Rejected      uint64
	BytesIn       uint64 // 访问者 -> 后端
	BytesOut      uint64 // 后端 -> 访问者
	BackendErrors uint64
	LastError     string
	LastErrorAt   time.Time
	LastActive    time.Time
}

type ruleCounters struct {
	active      atomic.Int64
	total       atomic.Uint64
	rejected    atomic.Uint64
	bytesIn     atomic.Uint64
	bytesOut    atomic.Uint64
	backendErrs atomic.Uint64
	lastActive  atomic.Int64 // UnixNano

	mu        sync.Mutex
	lastErr   string
	lastErrAt time.Time
}

func (m *Manager) counters(ruleID uint32) *ruleCounters {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	c := m.stats[ruleID]
	if c == nil {
		c = &ruleCounters{}
		m.stats[ruleID] = c
	}
	return c
}

// statOpened 记录一个新连接（或 HTTP 请求）开始；返回的函数在结束时调用（多次调用安全）。
func (m *Manager) statOpened(ruleID uint32) func() {
	c := m.counters(ruleID)
	c.active.Add(1)
	c.total.Add(1)
	c.lastActive.Store(time.Now().UnixNano())
	var once sync.Once
	return func() { once.Do(func() { c.active.Add(-1) }) }
}

// statRejected 记录一次被规则防护拒绝的连接 / 请求。
func (m *Manager) statRejected(ruleID uint32) {
	m.counters(ruleID).rejected.Add(1)
}

// statBackendError 记录一次后端不可用（Client 离线或拨号本地服务失败）。
func (m *Manager) statBackendError(ruleID uint32, msg string) {
	c := m.counters(ruleID)
	c.backendErrs.Add(1)
	c.mu.Lock()
	c.lastErr = msg
	c.lastErrAt = time.Now()
	c.mu.Unlock()
}

// statBytes 直接累加字节数（UDP 数据报使用）。
func (m *Manager) statBytes(ruleID uint32, in, out int) {
	c := m.counters(ruleID)
	if in > 0 {
		c.bytesIn.Add(uint64(in))
	}
	if out > 0 {
		c.bytesOut.Add(uint64(out))
	}
	c.lastActive.Store(time.Now().UnixNano())
}

// countingConn 统计经过连接的字节数。backendSide 为 true 表示该连接是通往 Client
// 的流（读到的是后端响应 = 下行，写入的是访问者请求 = 上行）。
type countingConn struct {
	net.Conn
	c           *ruleCounters
	backendSide bool
}

func (cc *countingConn) Read(p []byte) (int, error) {
	n, err := cc.Conn.Read(p)
	if n > 0 {
		if cc.backendSide {
			cc.c.bytesOut.Add(uint64(n))
		} else {
			cc.c.bytesIn.Add(uint64(n))
		}
		cc.c.lastActive.Store(time.Now().UnixNano())
	}
	return n, err
}

func (cc *countingConn) Write(p []byte) (int, error) {
	n, err := cc.Conn.Write(p)
	if n > 0 {
		if cc.backendSide {
			cc.c.bytesIn.Add(uint64(n))
		} else {
			cc.c.bytesOut.Add(uint64(n))
		}
		cc.c.lastActive.Store(time.Now().UnixNano())
	}
	return n, err
}

// countConn 返回统计字节数的包装连接。
func (m *Manager) countConn(ruleID uint32, c net.Conn, backendSide bool) net.Conn {
	return &countingConn{Conn: c, c: m.counters(ruleID), backendSide: backendSide}
}

// pruneStats 删除不在期望规则集合中的规则统计。
func (m *Manager) pruneStats(desired []RuleView) {
	keep := make(map[uint32]bool, len(desired))
	for _, r := range desired {
		keep[r.ID] = true
	}
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	for id := range m.stats {
		if !keep[id] {
			delete(m.stats, id)
		}
	}
}

// Stats 返回全部规则统计的快照（按规则 ID 排序）。
func (m *Manager) Stats() []RuleStats {
	m.statsMu.Lock()
	ids := make([]uint32, 0, len(m.stats))
	cs := make(map[uint32]*ruleCounters, len(m.stats))
	for id, c := range m.stats {
		ids = append(ids, id)
		cs[id] = c
	}
	m.statsMu.Unlock()
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]RuleStats, 0, len(ids))
	for _, id := range ids {
		c := cs[id]
		s := RuleStats{
			RuleID:        id,
			ActiveConns:   c.active.Load(),
			TotalConns:    c.total.Load(),
			Rejected:      c.rejected.Load(),
			BytesIn:       c.bytesIn.Load(),
			BytesOut:      c.bytesOut.Load(),
			BackendErrors: c.backendErrs.Load(),
		}
		if la := c.lastActive.Load(); la > 0 {
			s.LastActive = time.Unix(0, la)
		}
		c.mu.Lock()
		s.LastError, s.LastErrorAt = c.lastErr, c.lastErrAt
		c.mu.Unlock()
		out = append(out, s)
	}
	return out
}
