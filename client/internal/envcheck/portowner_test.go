//go:build linux

package envcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUDPPortDetection(t *testing.T) {
	p := filepath.Join(t.TempDir(), "udp")
	data := "header\n 0: 00000000:1F90 00000000:0000 07 0 0 0 0 0 123\n 1: 00000000:1F90 00000000:0000 0A 0 0 0 0 0 456\n"
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ proto, want string }{{"udp", "123"}, {"tcp", "456"}} {
		got, err := findListeningInode(p, 8080, tc.proto)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %q, %v", tc.proto, got, err)
		}
	}
}
