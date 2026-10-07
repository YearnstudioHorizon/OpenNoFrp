package rulesync

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"opennofrp/pkg/protocol"
)

func TestBuildProxyHeaderV1(t *testing.T) {
	cases := []struct {
		src, dst net.IP
		want     string
	}{
		{net.ParseIP("1.2.3.4"), net.ParseIP("127.0.0.1"), "PROXY TCP4 1.2.3.4 127.0.0.1 5555 80\r\n"},
		{net.ParseIP("2001:db8::1"), net.ParseIP("::1"), "PROXY TCP6 2001:db8::1 ::1 5555 80\r\n"},
		{net.ParseIP("1.2.3.4"), net.ParseIP("::1"), "PROXY TCP6 ::ffff:1.2.3.4 ::1 5555 80\r\n"},
		{net.IPv4zero, net.ParseIP("127.0.0.1"), "PROXY UNKNOWN\r\n"},
		{nil, net.ParseIP("127.0.0.1"), "PROXY UNKNOWN\r\n"},
	}
	for _, c := range cases {
		got, err := buildProxyHeader(1, c.src, 5555, c.dst, 80)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Errorf("v1(%v,%v) = %q want %q", c.src, c.dst, got, c.want)
		}
	}
	if _, err := buildProxyHeader(3, nil, 0, nil, 0); err == nil {
		t.Errorf("unsupported version should fail")
	}
}

func TestBuildProxyHeaderV2(t *testing.T) {
	got, err := buildProxyHeader(2, net.ParseIP("1.2.3.4"), 5555, net.ParseIP("10.0.0.1"), 80)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:12], proxyV2Signature) || got[12] != 0x21 || got[13] != 0x11 {
		t.Fatalf("bad v2 prefix: % x", got[:14])
	}
	if n := binary.BigEndian.Uint16(got[14:16]); n != 12 || len(got) != 16+12 {
		t.Fatalf("bad v2 length %d (total %d)", n, len(got))
	}
	if !bytes.Equal(got[16:20], []byte{1, 2, 3, 4}) || !bytes.Equal(got[20:24], []byte{10, 0, 0, 1}) ||
		binary.BigEndian.Uint16(got[24:26]) != 5555 || binary.BigEndian.Uint16(got[26:28]) != 80 {
		t.Errorf("bad v2 address block: % x", got[16:])
	}
	got6, _ := buildProxyHeader(2, net.ParseIP("2001:db8::1"), 1, net.ParseIP("::1"), 2)
	if got6[13] != 0x21 || binary.BigEndian.Uint16(got6[14:16]) != 36 || len(got6) != 16+36 {
		t.Errorf("bad v2 ipv6 header: % x", got6[:16])
	}
	local, _ := buildProxyHeader(2, nil, 0, nil, 0)
	if len(local) != 16 || local[12] != 0x20 {
		t.Errorf("bad v2 LOCAL header: % x", local)
	}
}

func TestRuleTargets(t *testing.T) {
	rule := protocol.Rule{LocalIP: "127.0.0.1", LocalPort: 80, Backends: []string{"127.0.0.1:80", " 10.0.0.2:8080 ", "bad", "host.example:80", "10.0.0.3:8080"}}
	want := []string{"127.0.0.1:80", "10.0.0.2:8080", "10.0.0.3:8080"}
	if got := ruleTargets(rule); !reflect.DeepEqual(got, want) {
		t.Errorf("ruleTargets = %v want %v", got, want)
	}
	tr, ok := withTarget(rule, "10.0.0.2:8080")
	if !ok || tr.LocalIP != "10.0.0.2" || tr.LocalPort != 8080 {
		t.Errorf("withTarget = %+v %v", tr, ok)
	}
}

func TestBackendPoolOrder(t *testing.T) {
	p := newBackendPool()
	rule := protocol.Rule{ID: 1, LocalIP: "10.0.0.1", LocalPort: 80, Backends: []string{"10.0.0.2:80", "10.0.0.3:80"}}

	// 轮询：每次的首选后端依次轮换
	firsts := map[string]bool{}
	for i := 0; i < 3; i++ {
		firsts[p.order(rule)[0]] = true
	}
	if len(firsts) != 3 {
		t.Errorf("round robin did not rotate: %v", firsts)
	}

	// 主备：保持配置顺序；不健康的后端排到最后
	rule.LBStrategy = "failover"
	if got := p.order(rule); !reflect.DeepEqual(got, []string{"10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"}) {
		t.Errorf("failover order = %v", got)
	}
	p.markFailed("10.0.0.1:80")
	if got := p.order(rule); !reflect.DeepEqual(got, []string{"10.0.0.2:80", "10.0.0.3:80", "10.0.0.1:80"}) {
		t.Errorf("failover with unhealthy primary = %v", got)
	}
	p.markOK("10.0.0.1:80")
	if got := p.order(rule)[0]; got != "10.0.0.1:80" {
		t.Errorf("recovered primary not preferred: %v", got)
	}

	// 随机：结果是全部后端的一个排列
	rule.LBStrategy = "random"
	if got := p.order(rule); len(got) != 3 {
		t.Errorf("random order = %v", got)
	}

	// 单后端规则直接返回主后端
	if got := p.order(protocol.Rule{LocalIP: "127.0.0.1", LocalPort: 22}); !reflect.DeepEqual(got, []string{"127.0.0.1:22"}) {
		t.Errorf("single backend = %v", got)
	}
}

func TestTouchConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	tc := &touchConn{Conn: a}
	if tc.touched.Load() {
		t.Fatal("touched before use")
	}
	if err := tc.Close(); err != nil {
		t.Fatal(err)
	}
	go b.Read(make([]byte, 1))
	if _, err := tc.Write([]byte{1}); err != nil {
		t.Fatalf("Close must not close the underlying stream: %v", err)
	}
	if !tc.touched.Load() {
		t.Errorf("write did not mark touched")
	}
}
