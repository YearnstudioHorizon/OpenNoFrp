package listener

import "testing"

func TestExpandPortRange(t *testing.T) {
	vs := expandPortRange(RuleView{ID: 1, Protocol: "tcp+udp", Port: 10000, PortEnd: 10002})
	if len(vs) != 3 {
		t.Fatalf("len = %d", len(vs))
	}
	for i, v := range vs {
		if v.Port != uint16(10000+i) || v.PortOffset != uint16(i) || v.PortEnd != 0 || v.ID != 1 {
			t.Errorf("view %d = %+v", i, v)
		}
	}
	if got := expandPortRange(RuleView{Protocol: "tcp", Port: 80}); len(got) != 1 || got[0].PortOffset != 0 {
		t.Errorf("single port: %+v", got)
	}
	if got := expandPortRange(RuleView{Protocol: "http", Port: 80, PortEnd: 90}); len(got) != 1 {
		t.Errorf("http rule must not be expanded: %d", len(got))
	}
	if got := expandPortRange(RuleView{Protocol: "udp", Port: 1, PortEnd: 65535}); len(got) != maxPortRangeSize {
		t.Errorf("range not capped: %d", len(got))
	}
}
