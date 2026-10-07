package listener

// Prometheus 文本格式（text/plain; version=0.0.4）导出规则级统计，供 /metrics 使用。
// 不引入 prometheus 客户端库，手写输出即可满足抓取需求。

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// RuleLabel 是导出指标时附加到每条规则上的标签。
type RuleLabel struct {
	ClientID string
	Name     string
	Protocol string
	Port     uint16
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// WritePrometheus 以 Prometheus 文本格式写出统计数据。labels 可为 nil。
// online 返回某个 Client 是否在线（可为 nil）。
func WritePrometheus(w io.Writer, stats []RuleStats, labels map[uint32]RuleLabel, online func(clientID string) bool) {
	labelOf := func(id uint32) string {
		l := labels[id]
		return fmt.Sprintf(`rule_id="%d",client_id="%s",name="%s",protocol="%s",port="%d"`,
			id, escapeLabel(l.ClientID), escapeLabel(l.Name), escapeLabel(l.Protocol), l.Port)
	}
	type metric struct {
		name, help, typ string
		val             func(RuleStats) string
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	metrics := []metric{
		{"opennofrp_rule_active_connections", "Current active connections (HTTP: in-flight requests).", "gauge", func(s RuleStats) string { return strconv.FormatInt(s.ActiveConns, 10) }},
		{"opennofrp_rule_connections_total", "Total accepted connections (HTTP: requests).", "counter", func(s RuleStats) string { return u(s.TotalConns) }},
		{"opennofrp_rule_rejected_total", "Connections or requests rejected by rule protection.", "counter", func(s RuleStats) string { return u(s.Rejected) }},
		{"opennofrp_rule_bytes_in_total", "Bytes from visitors to the backend.", "counter", func(s RuleStats) string { return u(s.BytesIn) }},
		{"opennofrp_rule_bytes_out_total", "Bytes from the backend to visitors.", "counter", func(s RuleStats) string { return u(s.BytesOut) }},
		{"opennofrp_rule_backend_errors_total", "Backend unavailable events (client offline or local dial failed).", "counter", func(s RuleStats) string { return u(s.BackendErrors) }},
		{"opennofrp_rule_last_error_timestamp_seconds", "Unix time of the last backend error (0 = never).", "gauge", func(s RuleStats) string {
			if s.LastErrorAt.IsZero() {
				return "0"
			}
			return strconv.FormatInt(s.LastErrorAt.Unix(), 10)
		}},
	}
	for _, m := range metrics {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", m.name, m.help, m.name, m.typ)
		for _, s := range stats {
			fmt.Fprintf(w, "%s{%s} %s\n", m.name, labelOf(s.RuleID), m.val(s))
		}
	}
	if online != nil && labels != nil {
		seen := map[string]bool{}
		fmt.Fprintf(w, "# HELP opennofrp_client_online Whether the client has an active session (1/0).\n# TYPE opennofrp_client_online gauge\n")
		for _, l := range labels {
			if l.ClientID == "" || seen[l.ClientID] {
				continue
			}
			seen[l.ClientID] = true
			v := 0
			if online(l.ClientID) {
				v = 1
			}
			fmt.Fprintf(w, "opennofrp_client_online{client_id=\"%s\"} %d\n", escapeLabel(l.ClientID), v)
		}
	}
}
