//go:build linux

package tproxy

import (
	"strings"
	"testing"
)

func TestConnmarkReplyProtocols(t *testing.T) {
	rules := connmarkReplyRules(1)
	if len(rules) != 4 {
		t.Fatalf("expected TCP and UDP rule pairs: %v", rules)
	}
	for _, proto := range []string{"tcp", "udp"} {
		for _, action := range []string{"--save-mark", "--restore-mark"} {
			count := 0
			for _, rule := range rules {
				s := strings.Join(rule, " ")
				if strings.Contains(s, "-p "+proto+" ") && strings.Contains(s, action) {
					count++
					if !strings.Contains(s, "--nfmask 0x1 --ctmask 0x1") {
						t.Fatal(s)
					}
				}
			}
			if count != 1 {
				t.Fatalf("%s %s: %d rules", proto, action, count)
			}
		}
	}
}
