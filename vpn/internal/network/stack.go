package network

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"opennofrp/pkg/tempvpn"
)

type Dial func(context.Context, string, uint16) (net.Conn, error)

// Run intercepts only packets for the authorized virtual IP. The TCP/IP stack
// terminates flows locally and forwards each destination port over the tunnel.
func Run(ctx context.Context, device tun.Device, target netip.Addr, dial Dial, diagnostics ...func(string, ...any)) error {
	var diagnostic func(string, ...any)
	if len(diagnostics) > 0 {
		diagnostic = diagnostics[0]
	}
	trace := newPacketTrace(diagnostic)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4}})
	defer s.Close()
	ep := channel.New(1024, 1280, "")
	if err := s.CreateNIC(1, ep); err != nil {
		return fmt.Errorf("create network interface: %s", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(target.AsSlice()).WithPrefix()}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("set network address: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	flows := make(chan struct{}, 256)
	tf := tcp.NewForwarder(s, 0, 128, func(r *tcp.ForwarderRequest) {
		select {
		case flows <- struct{}{}:
		case <-ctx.Done():
			r.Complete(true)
			return
		default:
			r.Complete(true)
			return
		}
		defer func() { <-flows }()
		id := r.ID()
		flow := fmt.Sprintf("%s:%d -> %s:%d", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
		remote, err := dial(ctx, "tcp", r.ID().LocalPort)
		if err != nil {
			r.Complete(true)
			return
		}
		defer remote.Close()
		var q waiter.Queue
		if diagnostic != nil {
			diagnostic("TCP 等待本机握手：%s", flow)
		}
		endpoint, tcpErr := r.CreateEndpoint(&q)
		if tcpErr != nil {
			if diagnostic != nil {
				diagnostic("TCP 本机握手失败：%s：%s", flow, tcpErr)
			}
			r.Complete(true)
			return
		}
		r.Complete(false)
		local := gonet.NewTCPConn(&q, endpoint)
		if diagnostic == nil {
			tempvpn.Relay(ctx, local, remote)
			return
		}
		diagnostic("TCP 本机握手完成：%s", flow)
		observed := &diagnosticConn{Conn: local, log: diagnostic, flow: flow}
		tempvpn.Relay(ctx, observed, remote)
		diagnostic("TCP 转发结束：%s，发送到目标=%d 字节，返回本机=%d 字节", flow, observed.readBytes.Load(), observed.writeBytes.Load())
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	uf := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		var q waiter.Queue
		endpoint, err := r.CreateEndpoint(&q)
		if err != nil {
			return
		}
		conn := gonet.NewUDPConn(s, &q, endpoint)
		select {
		case flows <- struct{}{}:
		default:
			conn.Close()
			return
		}
		go func() {
			defer func() { conn.Close(); <-flows }()
			remote, err := dial(ctx, "udp", r.ID().LocalPort)
			if err != nil {
				return
			}
			defer remote.Close()
			tempvpn.RelayDatagrams(ctx, conn, remote)
		}()
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, packet stack.PacketBufferPtr) bool {
		// The pinned gVisor UDP forwarder retains one packet reference but has
		// no request-release API. CreateEndpoint consumes it synchronously;
		// balance that reference when the forwarder returns.
		defer packet.DecRef()
		return uf.HandlePacket(id, packet)
	})
	var closeOnce sync.Once
	closeNetwork := func() { closeOnce.Do(func() { device.Close(); ep.Close() }) }
	stop := context.AfterFunc(ctx, closeNetwork)
	defer stop()
	defer func() { cancel(); closeNetwork() }()
	errors := make(chan error, 2)
	go func() {
		for {
			packet := ep.ReadContext(ctx)
			if packet.IsNil() {
				errors <- ctx.Err()
				return
			}
			view := packet.ToView()
			packet.DecRef()
			// Linux TUN with virtio headers requires writable headroom. The
			// same offset is accepted by Wintun, which skips the headroom.
			const offset = 16
			data := make([]byte, offset+view.Size())
			copy(data[offset:], view.AsSlice())
			view.Release()
			trace.packet("TUN TX", data[offset:])
			if _, err := device.Write([][]byte{data}, offset); err != nil {
				if diagnostic != nil {
					diagnostic("TUN 写入失败：%v", err)
				}
				errors <- err
				return
			}
		}
	}()
	go func() {
		buffers := make([][]byte, device.BatchSize())
		sizes := make([]int, len(buffers))
		for i := range buffers {
			buffers[i] = make([]byte, 65535)
		}
		for {
			n, err := device.Read(buffers, sizes, 0)
			if err != nil {
				errors <- err
				return
			}
			for i := 0; i < n; i++ {
				data := buffers[i][:sizes[i]]
				trace.packet("TUN RX", data)
				if len(data) < 20 || data[0]>>4 != 4 || netip.AddrFrom4([4]byte{data[16], data[17], data[18], data[19]}) != target {
					continue
				}
				packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data...))})
				ep.InjectInbound(ipv4.ProtocolNumber, packet)
				packet.DecRef()
			}
		}
	}()
	return <-errors
}
