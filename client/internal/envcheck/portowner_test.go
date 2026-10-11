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
func TestDockerPortProtocol(t *testing.T) {
	for _, tc := range []struct {
		line, proto string
		port        uint16
		wantPort    uint16
		want        bool
	}{
		{"id image 0.0.0.0:8080->80/udp, [::]:8080->80/udp name", "udp", 8080, 80, true},
		{"id image 0.0.0.0:8080->80/tcp name", "tcp", 8080, 80, true},
		{"id image 0.0.0.0:8080->80/tcp name", "udp", 8080, 0, false},
		{"id image 0.0.0.0:18080->80/udp name", "udp", 8080, 0, false},
		{"id image 0.0.0.0:8080->80/udp name", "tcp", 8080, 0, false},
	} {
		if gotPort, got := publishedContainerPort(tc.line, tc.port, tc.proto); gotPort != tc.wantPort || got != tc.want {
			t.Fatalf("%q %s: got (%d, %v), want (%d, %v)", tc.line, tc.proto, gotPort, got, tc.wantPort, tc.want)
		}
	}
}
