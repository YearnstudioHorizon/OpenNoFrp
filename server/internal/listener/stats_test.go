package listener

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
)

func TestRuleStatsCounters(t *testing.T) {
	m := NewManager("127.0.0.1", slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	done := m.statOpened(7)
	m.statOpened(7)()
	m.statRejected(7)
	m.statBackendError(7, "client offline")
	m.statBytes(7, 10, 20)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	visitor := m.countConn(7, a, false)
	go func() {
		b.Write([]byte("hello"))
		buf := make([]byte, 3)
		io.ReadFull(b, buf)
	}()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(visitor, buf); err != nil {
		t.Fatal(err)
	}
	if _, err := visitor.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}

	st := m.Stats()
	if len(st) != 1 {
		t.Fatalf("stats len = %d", len(st))
	}
	s := st[0]
	if s.RuleID != 7 || s.ActiveConns != 1 || s.TotalConns != 2 || s.Rejected != 1 || s.BackendErrors != 1 ||
		s.LastError != "client offline" || s.BytesIn != 15 || s.BytesOut != 23 {
		t.Errorf("unexpected stats: %+v", s)
	}
	done()
	done() // 多次调用安全
	if got := m.Stats()[0].ActiveConns; got != 0 {
		t.Errorf("active after done = %d", got)
	}

	m.pruneStats([]RuleView{{ID: 8}})
	if len(m.Stats()) != 0 {
		t.Errorf("stats for removed rule not pruned")
	}
}

func TestWritePrometheus(t *testing.T) {
	stats := []RuleStats{{RuleID: 3, ActiveConns: 2, TotalConns: 5, BytesIn: 100, BytesOut: 200}}
	labels := map[uint32]RuleLabel{3: {ClientID: "c1", Name: `we"b`, Protocol: "http", Port: 80}}
	var buf bytes.Buffer
	WritePrometheus(&buf, stats, labels, func(id string) bool { return id == "c1" })
	out := buf.String()
	for _, want := range []string{
		"# TYPE opennofrp_rule_active_connections gauge",
		`opennofrp_rule_active_connections{rule_id="3",client_id="c1",name="we\"b",protocol="http",port="80"} 2`,
		`opennofrp_rule_bytes_out_total{rule_id="3",client_id="c1",name="we\"b",protocol="http",port="80"} 200`,
		`opennofrp_rule_last_error_timestamp_seconds{rule_id="3",client_id="c1",name="we\"b",protocol="http",port="80"} 0`,
		`opennofrp_client_online{client_id="c1"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n%s", want, out)
		}
	}
}
