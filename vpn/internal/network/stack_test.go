package network

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// packetDevice connects Run to an independent client stack without a real TUN.
type packetDevice struct {
	ctx    context.Context
	cancel context.CancelFunc
	link   *channel.Endpoint
	closes atomic.Int32
}

func (d *packetDevice) File() *os.File           { return nil }
func (d *packetDevice) MTU() (int, error)        { return 1280, nil }
func (d *packetDevice) Name() (string, error)    { return "test", nil }
func (d *packetDevice) Events() <-chan tun.Event { return nil }
func (d *packetDevice) BatchSize() int           { return 1 }
func (d *packetDevice) Close() error             { d.closes.Add(1); d.cancel(); return nil }
func (d *packetDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	p := d.link.ReadContext(d.ctx)
	if p.IsNil() {
		return 0, os.ErrClosed
	}
	v := p.ToView()
	p.DecRef()
	sizes[0] = copy(bufs[0][offset:], v.AsSlice())
	v.Release()
	return 1, nil
}
func (d *packetDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b[offset:]...))})
		d.link.InjectInbound(ipv4.ProtocolNumber, p)
		p.DecRef()
	}
	return len(bufs), nil
}

func TestRunTCPAndCancellation(t *testing.T) {
	t.Run("normal", func(t *testing.T) { runTCPAndCancellation(t, false) })
	t.Run("diagnostics", func(t *testing.T) { runTCPAndCancellation(t, true) })
}

func runTCPAndCancellation(t *testing.T, diagnostics bool) {
	var logMu sync.Mutex
	var messages []string
	var diagnostic func(string, ...any)
	if diagnostics {
		diagnostic = func(format string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			messages = append(messages, fmt.Sprintf(format, args...))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	defer client.Close()
	link := channel.New(1024, 1280, "")
	defer link.Close()
	if err := client.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	if err := client.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 203, 0, 2}).WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	client.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	dctx, dcancel := context.WithCancel(context.Background())
	defer dcancel()
	device := &packetDevice{ctx: dctx, cancel: dcancel, link: link}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, device, netip.MustParseAddr("10.203.0.1"), func(_ context.Context, kind string, port uint16) (net.Conn, error) {
			if kind != "tcp" || port != 3001 {
				t.Errorf("unexpected destination %s:%d", kind, port)
			}
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(b, b) }()
			return a, nil
		}, diagnostic)
	}()
	conn, err := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 203, 0, 1}), Port: 3001}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var reply [5]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if string(reply[:]) != "hello" {
		t.Fatalf("reply %q", reply)
	}
	if diagnostics {
		logMu.Lock()
		joined := strings.Join(messages, "\n")
		logMu.Unlock()
		for _, required := range []string{"TUN RX TCP", "TUN TX TCP", "TCP 本机握手完成", "TCP 收到本机数据", "TCP 收到目标响应"} {
			if !strings.Contains(joined, required) {
				t.Errorf("missing %q in diagnostics: %s", required, joined)
			}
		}
		if strings.Contains(joined, "hello") {
			t.Error("diagnostics disclosed application payload")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
	if n := device.closes.Load(); n != 1 {
		t.Fatalf("device closed %d times", n)
	}
}
