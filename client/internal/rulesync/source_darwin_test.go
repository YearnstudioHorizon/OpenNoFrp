//go:build darwin

package rulesync

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"opennofrp/pkg/protocol"
)

func TestDarwinPreserveSourceIP(t *testing.T) {
	if os.Getenv("OPENNOFRP_TEST_DARWIN_PF") != "1" {
		t.Skip("set OPENNOFRP_TEST_DARWIN_PF=1 and run as root to test with macOS PF")
	}
	r := New(slog.Default(), t.TempDir())
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	for _, tc := range []struct {
		name     string
		network  string
		backend  string
		bind     string
		visitor  string
		preserve bool
	}{
		{"TCP", "tcp4", "127.0.0.1", "127.0.0.1", "198.51.100.27", true},
		{"UDP", "udp4", "127.0.0.1", "127.0.0.1", "198.51.100.28", true},
		{"UDP wildcard", "udp4", "127.0.0.1", "0.0.0.0", "198.51.100.29", true},
		{"plain", "tcp4", "127.0.0.1", "127.0.0.1", "198.51.100.30", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			stream, peer := net.Pipe()
			defer peer.Close()
			deadline, _ := ctx.Deadline()
			if err := peer.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}

			rule := protocol.Rule{ID: 1, Name: tc.name, LocalIP: tc.backend, PreserveSourceIP: tc.preserve}
			meta := protocol.StreamMetadata{RuleID: 1, ClientAddr: net.ParseIP(tc.visitor), ClientPort: 54278}
			var response string
			if tc.network[:3] == "tcp" {
				listener, err := net.ListenTCP(tc.network, &net.TCPAddr{IP: net.ParseIP(tc.bind)})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				listener.SetDeadline(deadline)
				rule.LocalPort = uint16(listener.Addr().(*net.TCPAddr).Port)
				meta.Transport = protocol.TransportTCP
				meta.Flags = protocol.FlagDialAck
				go func() {
					conn, err := listener.AcceptTCP()
					if err == nil {
						defer conn.Close()
						conn.SetDeadline(deadline)
						var request [4]byte
						if _, err := io.ReadFull(conn, request[:]); err == nil {
							fmt.Fprintf(conn, "%s %s\n", conn.RemoteAddr(), request[:])
						}
					}
				}()
				r.Apply([]protocol.Rule{rule})
				go r.ServeStream(ctx, meta, stream)
				var ack [1]byte
				if _, err := io.ReadFull(peer, ack[:]); err != nil || ack[0] != protocol.DialAckOK {
					t.Fatalf("dial ack=%d, err=%v", ack[0], err)
				}
				if _, err := peer.Write([]byte("ping")); err != nil {
					t.Fatal(err)
				}
				b, err := bufio.NewReader(peer).ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				response = b
			} else {
				listener, err := net.ListenUDP(tc.network, &net.UDPAddr{IP: net.ParseIP(tc.bind)})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				listener.SetDeadline(deadline)
				rule.LocalPort = uint16(listener.LocalAddr().(*net.UDPAddr).Port)
				meta.Transport = protocol.TransportUDP
				go func() {
					var request [4096]byte
					n, addr, err := listener.ReadFromUDP(request[:])
					if err == nil {
						listener.WriteToUDP(append([]byte(addr.String()+" "), request[:n]...), addr)
					}
				}()
				r.Apply([]protocol.Rule{rule})
				go r.ServeStream(ctx, meta, stream)
				payload := bytes.Repeat([]byte("u"), 4096)
				if !writeUDPFrame(peer, payload) {
					t.Fatal("could not write UDP request")
				}
				b, err := readUDPFrame(peer)
				if err != nil {
					t.Fatal(err)
				}
				remote, echo, found := bytes.Cut(b, []byte(" "))
				if !found || !bytes.Equal(echo, payload) {
					t.Fatalf("UDP echo payload mismatch (%d bytes returned)", len(echo))
				}
				response = string(remote) + " ping"
			}
			var remote, payload string
			fmt.Sscan(response, &remote, &payload)
			want := tc.visitor
			if !tc.preserve {
				want = tc.backend
			}
			host, _, err := net.SplitHostPort(remote)
			if err != nil || host != want || payload != "ping" {
				t.Errorf("backend replied %q, want peer IP %s and payload ping", response, want)
			}
		})
	}
}
