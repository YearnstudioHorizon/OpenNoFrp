package network

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"opennofrp/pkg/protocol"
	"opennofrp/pkg/tempvpn"

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
	t.Run("normal", func(t *testing.T) { runTCPAndCancellation(t, false, []byte("hello")) })
	t.Run("diagnostics", func(t *testing.T) { runTCPAndCancellation(t, true, []byte("hello")) })
	t.Run("large-transfer", func(t *testing.T) { runTCPAndCancellation(t, true, bytes.Repeat([]byte("hello"), 256*1024)) })
	t.Run("concurrent-connections", func(t *testing.T) { runConcurrentConnections(t) })
	t.Run("http-keep-alive", func(t *testing.T) { runHTTPKeepAlive(t) })
	t.Run("end-to-end-vpn-yamux-chain", func(t *testing.T) { runEndToEndVPNYamuxChain(t) })
	t.Run("browser-multi-asset-flow", func(t *testing.T) { runBrowserMultiAssetFlow(t) })
}

func runEndToEndVPNYamuxChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Backend server
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
					// Send back a 50KB payload and CLOSE
					body := bytes.Repeat([]byte("A"), 50*1024)
					resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", len(body))
					c.Write([]byte(resp))
					c.Write(body)
					return // Closes connection!
				}
			}(conn)
		}
	}()

	// 2. Server <-> Client yamux session
	csA, csB := net.Pipe()
	defer csA.Close()
	defer csB.Close()
	tunnelCfg := protocol.TunnelYamuxConfig()
	tunnelCfg.LogOutput = io.Discard
	srvSess, err := yamux.Server(csA, tunnelCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srvSess.Close()
	cliSess, err := yamux.Client(csB, tunnelCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cliSess.Close()

	// Client loop
	go func() {
		for {
			s, err := cliSess.AcceptStream()
			if err != nil {
				return
			}
			go func(stream net.Conn) {
				defer stream.Close()
				// Read metadata (like ServeLoopback does)
				meta, err := protocol.ReadStreamMetadata(stream)
				if err != nil {
					t.Logf("client read meta error: %v", err)
					return
				}
				t.Logf("client received meta: %+v", meta)
				if !meta.HasFlag(protocol.FlagTemporaryVPN) {
					return
				}
				targetConn, err := net.Dial("tcp", backend.Addr().String())
				if err != nil {
					t.Logf("client dial backend error: %v", err)
					stream.Write([]byte{protocol.DialAckFailed})
					return
				}
				defer targetConn.Close()
				t.Logf("client writing DialAckOK")
				if _, err := stream.Write([]byte{protocol.DialAckOK}); err != nil {
					t.Logf("client write DialAckOK err: %v", err)
					return
				}
				tempvpn.Relay(ctx, stream, targetConn)
			}(s)
		}
	}()

	// 3. Visitor VPN <-> Server yamux session
	vsA, vsB := net.Pipe()
	defer vsA.Close()
	defer vsB.Close()
	vpnCfg := protocol.VPNYamuxConfig()
	vpnCfg.LogOutput = io.Discard
	vpnSrvSess, err := yamux.Server(vsA, vpnCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer vpnSrvSess.Close()
	vpnCliSess, err := yamux.Client(vsB, vpnCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer vpnCliSess.Close()

	// Server VPN loop (like serveVPNFlow in opennofrp-server)
	go func() {
		for {
			vStream, err := vpnSrvSess.AcceptStream()
			if err != nil {
				return
			}
			go func(stream net.Conn) {
				defer stream.Close()
				var req protocol.VPNDialRequest
				if err := protocol.ReadJSONMessage(stream, &req); err != nil {
					t.Logf("server read json error: %v", err)
					return
				}
				t.Logf("server accepted req: %+v", req)
				cStream, err := srvSess.Open()
				if err != nil {
					t.Logf("srvSess.Open error: %v", err)
					stream.Write([]byte{protocol.DialAckFailed})
					return
				}
				defer cStream.Close()
				meta := protocol.StreamMetadata{
					Transport:  protocol.TransportTCP,
					ClientAddr: net.IPv4(127, 0, 0, 1),
					Flags:      protocol.FlagTemporaryVPN | protocol.FlagDialAck,
					VPNPort:    req.Port,
				}
				if err := meta.WriteHeader(cStream); err != nil {
					t.Logf("meta.WriteHeader error: %v", err)
					stream.Write([]byte{protocol.DialAckFailed})
					return
				}
				var ack [1]byte
				if n, err := io.ReadFull(cStream, ack[:]); err != nil || ack[0] != protocol.DialAckOK {
					t.Logf("server read ack from client: n=%d err=%v, ack=%v", n, err, ack)
					stream.Write([]byte{protocol.DialAckFailed})
					return
				}
				if _, err := stream.Write([]byte{protocol.DialAckOK}); err != nil {
					return
				}
				tempvpn.Relay(ctx, stream, cStream)
			}(vStream)
		}
	}()

	// 4. VPN stack with packetDevice
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

	dial := func(ctx context.Context, kind string, port uint16) (net.Conn, error) {
		stream, err := vpnCliSess.Open()
		if err != nil {
			t.Logf("dial open error: %v", err)
			return nil, err
		}
		if err := protocol.WriteJSONMessage(stream, protocol.VPNDialRequest{Network: kind, Port: port}); err != nil {
			t.Logf("dial write json error: %v", err)
			stream.Close()
			return nil, err
		}
		var ack [1]byte
		if _, err := io.ReadFull(stream, ack[:]); err != nil || ack[0] != protocol.DialAckOK {
			t.Logf("dial ack error: %v, ack: %v", err, ack)
			stream.Close()
			return nil, fmt.Errorf("dial failed")
		}
		return stream, nil
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, device, netip.MustParseAddr("10.203.0.1"), dial)
	}()

	// Run multiple parallel HTTP clients making requests
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			httpClient := &http.Client{
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 203, 0, 1}), Port: 3001}, ipv4.ProtocolNumber)
					},
				},
				Timeout: 5 * time.Second,
			}
			for reqIdx := 0; reqIdx < 2; reqIdx++ {
				resp, err := httpClient.Get(fmt.Sprintf("http://10.203.0.1:3001/test-%d-%d", id, reqIdx))
				if err != nil {
					t.Errorf("worker %d req %d failed: %v", id, reqIdx, err)
					return
				}
				b, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Errorf("worker %d req %d read failed: %v", id, reqIdx, err)
					return
				}
				if len(b) != 50*1024 {
					t.Errorf("worker %d req %d got %d bytes, want %d", id, reqIdx, len(b), 50*1024)
				}
			}
		}(i)
	}
	wg.Wait()
	cancel()
	<-done
}

func runHTTPKeepAlive(t *testing.T) {
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

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					// Reply with HTTP 200 without closing connection
					body := fmt.Sprintf("echo: %s", string(buf[:n]))
					resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
					c.Write([]byte(resp))
				}
			}(conn)
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, device, netip.MustParseAddr("10.203.0.1"), func(ctx context.Context, kind string, port uint16) (net.Conn, error) {
			return net.Dial("tcp", backend.Addr().String())
		})
	}()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 203, 0, 1}), Port: 3001}, ipv4.ProtocolNumber)
			},
		},
		Timeout: 2 * time.Second,
	}

	for i := 0; i < 3; i++ {
		resp, err := httpClient.Get(fmt.Sprintf("http://10.203.0.1:3001/test-%d", i))
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read body %d failed: %v", i, err)
		}
		if !strings.Contains(string(b), fmt.Sprintf("test-%d", i)) {
			t.Fatalf("unexpected body %d: %s", i, string(b))
		}
	}
	cancel()
	<-done
}

func runConcurrentConnections(t *testing.T) {
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
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				buf := make([]byte, 1024)
				n, _ := b.Read(buf)
				b.Write([]byte(fmt.Sprintf("response-to-%s", string(buf[:n]))))
			}()
			return a, nil
		})
	}()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 203, 0, 1}), Port: 3001}, ipv4.ProtocolNumber)
			if err != nil {
				t.Errorf("conn %d dial failed: %v", id, err)
				return
			}
			defer conn.Close()
			msg := fmt.Sprintf("req-%d", id)
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Errorf("conn %d write failed: %v", id, err)
				return
			}
			buf := make([]byte, 64)
			n, err := conn.Read(buf)
			if err != nil {
				t.Errorf("conn %d read failed: %v", id, err)
				return
			}
			expected := fmt.Sprintf("response-to-req-%d", id)
			if string(buf[:n]) != expected {
				t.Errorf("conn %d got %q, want %q", id, string(buf[:n]), expected)
			}
		}(i)
	}
	wg.Wait()
	cancel()
	<-done
}

func runTCPAndCancellation(t *testing.T, diagnostics bool, payload []byte) {
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
	written := make(chan error, 1)
	go func() { _, err := conn.Write(payload); written <- err }()
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatal("TCP reply differs from request")
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

func runBrowserMultiAssetFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Backend server simulating uvicorn/FastAPI with keep-alive
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					req := string(buf[:n])
					if strings.Contains(req, "GET / HTTP") {
						body := bytes.Repeat([]byte("<html>Index</html>"), 1000) // ~18KB
						resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nSet-Cookie: session=1234567890\r\nContent-Length: %d\r\n\r\n", len(body))
						c.Write([]byte(resp))
						c.Write(body)
					} else if strings.Contains(req, "GET /asset") {
						body := bytes.Repeat([]byte("console.log('asset');"), 5000) // ~100KB
						resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
						c.Write([]byte(resp))
						c.Write(body)
					} else {
						resp := "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
						c.Write([]byte(resp))
					}
				}
			}(conn)
		}
	}()

	// 2. Server <-> Client yamux session
	csA, csB := net.Pipe()
	defer csA.Close()
	defer csB.Close()
	srvSess, err := yamux.Server(csA, protocol.TunnelYamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer srvSess.Close()
	cliSess, err := yamux.Client(csB, protocol.TunnelYamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer cliSess.Close()

	// Client loop (running ServeLoopback)
	_, backendPortStr, _ := net.SplitHostPort(backend.Addr().String())
	bPort, _ := strconv.Atoi(backendPortStr)
	go func() {
		for {
			s, err := cliSess.AcceptStream()
			if err != nil {
				return
			}
			go func(stream net.Conn) {
				defer stream.Close()
				meta, err := protocol.ReadStreamMetadata(stream)
				if err != nil {
					return
				}
				tempvpn.ServeLoopback(ctx, meta, stream)
			}(s)
		}
	}()

	// 3. Visitor VPN <-> Server yamux session
	vsA, vsB := net.Pipe()
	defer vsA.Close()
	defer vsB.Close()
	vpnConfig := protocol.VPNYamuxConfig()
	vpnSrvSess, err := yamux.Server(vsA, vpnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer vpnSrvSess.Close()
	vpnCliSess, err := yamux.Client(vsB, vpnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer vpnCliSess.Close()

	// Server VPN loop (like serveVPNFlow in opennofrp-server)
	go func() {
		for {
			vStream, err := vpnSrvSess.AcceptStream()
			if err != nil {
				return
			}
			go func(stream net.Conn) {
				defer stream.Close()
				var req protocol.VPNDialRequest
				if err := protocol.ReadJSONMessage(stream, &req); err != nil {
					return
				}
				cStream, err := srvSess.Open()
				if err != nil {
					stream.Write([]byte{protocol.DialAckFailed})
					return
				}
				defer cStream.Close()
				meta := protocol.StreamMetadata{
					Transport:  protocol.TransportTCP,
					ClientAddr: net.IPv4(127, 0, 0, 1),
					Flags:      protocol.FlagTemporaryVPN | protocol.FlagDialAck,
					VPNPort:    req.Port,
				}
				if err := meta.WriteHeader(cStream); err != nil {
					stream.Write([]byte{protocol.DialAckFailed})
					return
				}
				var ack [1]byte
				if _, err := io.ReadFull(cStream, ack[:]); err != nil || ack[0] != protocol.DialAckOK {
					stream.Write([]byte{protocol.DialAckFailed})
					return
				}
				if _, err := stream.Write([]byte{protocol.DialAckOK}); err != nil {
					return
				}
				tempvpn.Relay(ctx, stream, cStream)
			}(vStream)
		}
	}()

	// 4. VPN stack with packetDevice
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

	dial := func(ctx context.Context, kind string, port uint16) (net.Conn, error) {
		stream, err := vpnCliSess.Open()
		if err != nil {
			return nil, err
		}
		if err := protocol.WriteJSONMessage(stream, protocol.VPNDialRequest{Network: kind, Port: port}); err != nil {
			stream.Close()
			return nil, err
		}
		var ack [1]byte
		if _, err := io.ReadFull(stream, ack[:]); err != nil || ack[0] != protocol.DialAckOK {
			stream.Close()
			return nil, fmt.Errorf("dial failed")
		}
		return stream, nil
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, device, netip.MustParseAddr("10.203.0.1"), dial, t.Logf)
	}()

	// Simulate Browser opening connection 1 (GET /)
	conn1, err := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 203, 0, 1}), Port: uint16(bPort)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("conn1 dial failed: %v", err)
	}
	req1 := "GET / HTTP/1.1\r\nHost: local:3001\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
	if _, err := conn1.Write([]byte(req1)); err != nil {
		t.Fatalf("conn1 write failed: %v", err)
	}
	buf1 := make([]byte, 32*1024)
	n1, err := conn1.Read(buf1)
	if err != nil {
		t.Fatalf("conn1 read failed: %v", err)
	}
	t.Logf("conn1 read %d bytes (keep conn1 OPEN like browser does)", n1)

	// Simulate Browser opening connection 2 (speculative or asset, sending 1819 bytes with large Cookie)
	conn2, err := gonet.DialContextTCP(ctx, client, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 203, 0, 1}), Port: uint16(bPort)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("conn2 dial failed: %v", err)
	}
	largeCookie := strings.Repeat("A", 1500)
	req2 := fmt.Sprintf("GET /asset HTTP/1.1\r\nHost: local:3001\r\nCookie: %s\r\n\r\n", largeCookie)
	t.Logf("conn2 sending %d bytes", len(req2))
	if _, err := conn2.Write([]byte(req2)); err != nil {
		t.Fatalf("conn2 write failed: %v", err)
	}
	buf2 := make([]byte, 32*1024)
	n2, err := conn2.Read(buf2)
	if err != nil {
		t.Fatalf("conn2 read failed: %v", err)
	}
	t.Logf("conn2 read %d bytes", n2)
	if n2 == 0 {
		t.Fatalf("conn2 returned 0 bytes!")
	}

	conn1.Close()
	conn2.Close()
	cancel()
	<-done
}
