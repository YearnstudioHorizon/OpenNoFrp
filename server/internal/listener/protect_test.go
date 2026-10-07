package listener

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestGuardAllowDeny(t *testing.T) {
	g := newRuleGuard(GuardConfig{
		Allow: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
		Deny:  []*net.IPNet{mustCIDR(t, "10.1.0.0/16")},
	})
	cases := map[string]string{
		"10.2.3.4":    guardOK,
		"10.1.2.3":    guardDenied,
		"192.168.1.1": guardDenied,
	}
	for ip, want := range cases {
		rel, got := g.admit(net.ParseIP(ip))
		rel()
		if got != want {
			t.Errorf("admit(%s) = %q want %q", ip, got, want)
		}
	}
	if _, got := g.admit(nil); got != guardDenied {
		t.Errorf("nil ip with allowlist = %q, want denied", got)
	}
	var nilGuard *ruleGuard
	if _, got := nilGuard.admit(net.ParseIP("1.2.3.4")); got != guardOK {
		t.Errorf("nil guard should allow all")
	}
}

func TestGuardMaxConns(t *testing.T) {
	g := newRuleGuard(GuardConfig{MaxConnsPerIP: 2})
	ip := net.ParseIP("1.2.3.4")
	r1, a := g.admit(ip)
	r2, b := g.admit(ip)
	_, c := g.admit(ip)
	if a != guardOK || b != guardOK || c != guardTooManyConns {
		t.Fatalf("got %q %q %q", a, b, c)
	}
	if _, other := g.admit(net.ParseIP("5.6.7.8")); other != guardOK {
		t.Errorf("other ip should not be limited: %q", other)
	}
	r1()
	r1() // 多次释放安全
	r3, d := g.admit(ip)
	if d != guardOK {
		t.Errorf("after release: %q", d)
	}
	if _, e := g.admit(ip); e != guardTooManyConns {
		t.Errorf("double release must not free two slots: %q", e)
	}
	r2()
	r3()
}

func TestGuardRate(t *testing.T) {
	g := newRuleGuard(GuardConfig{ConnRatePerMin: 3})
	ip := net.ParseIP("1.2.3.4")
	for i := 0; i < 3; i++ {
		if _, r := g.admit(ip); r != guardOK {
			t.Fatalf("attempt %d: %q", i, r)
		}
	}
	if _, r := g.admit(ip); r != guardRateLimited {
		t.Errorf("4th attempt = %q, want rate_limited", r)
	}
}

func TestGuardBandwidth(t *testing.T) {
	g := newRuleGuard(GuardConfig{BandwidthKBps: 64})
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	w := g.wrapConn(a)
	go io.Copy(io.Discard, b)
	buf := make([]byte, 128*1024) // 64 KB 突发 + 64 KB 需约 1 秒
	start := time.Now()
	if _, err := w.Write(buf); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 700*time.Millisecond {
		t.Errorf("bandwidth not limited: wrote 128KB in %v", el)
	}
	if !newRuleGuard(GuardConfig{}).allowBandwidth(1 << 20) {
		t.Errorf("no bandwidth limit should allow all")
	}
}

func TestSetGuardsKeepsState(t *testing.T) {
	m := NewManager("127.0.0.1", slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	cfg := GuardConfig{MaxConnsPerIP: 1}
	m.setGuards([]RuleView{{ID: 1, Guard: cfg}, {ID: 2}})
	g := m.guardFor(1)
	if g == nil || m.guardFor(2) != nil {
		t.Fatalf("unexpected guards: %v %v", g, m.guardFor(2))
	}
	m.setGuards([]RuleView{{ID: 1, Guard: cfg}})
	if m.guardFor(1) != g {
		t.Errorf("unchanged config should keep guard state")
	}
	m.setGuards([]RuleView{{ID: 1, Guard: GuardConfig{MaxConnsPerIP: 5}}})
	if m.guardFor(1) == g {
		t.Errorf("changed config should create new guard")
	}
	m.setGuards(nil)
	if m.guardFor(1) != nil {
		t.Errorf("removed rule should drop guard")
	}
}
