//go:build darwin

// Package darwinsource connects to Mac-local services with the visitor's source IP.
// A userspace TCP/IP stack owns the visitor side of each connection. PF redirects
// packets entering its utun to the local backend and routes stateful replies back
// to the same utun.
package darwinsource

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nic = 1
	// The private link can carry a full IP datagram. Fragmenting before
	// injection would prevent PF from matching the UDP ports for redirection.
	mtu       = 65535
	tunHeader = 4
)

type Dialer struct {
	stack     *stack.Stack
	link      *channel.Endpoint
	device    tun.Device
	pf        *packetFilter
	udp       udpListeners
	cancel    context.CancelFunc
	done      chan struct{}
	loops     sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func New(ctx context.Context) (*Dialer, error) {
	device, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, fmt.Errorf("create source IP utun: %w", err)
	}
	go func() {
		for range device.Events() {
			// Drain interface notifications; the device owns its route listener.
		}
	}()
	pf, err := setupPacketFilter(ctx, device)
	if err != nil {
		device.Close()
		return nil, err
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(256, mtu, "")
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{stack: s, link: link, device: device, pf: pf, cancel: cancel, done: make(chan struct{})}
	if err := s.CreateNIC(nic, link); err != nil {
		d.Close()
		return nil, fmt.Errorf("create source IP netstack NIC: %s", err)
	}
	// Visitor addresses are remote to macOS and may change on every stream.
	s.SetSpoofing(nic, true)
	s.SetPromiscuousMode(nic, true)
	ttl := tcpip.DefaultTTLOption(255)
	s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &ttl)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nic},
	})

	d.loops.Add(2)
	go func() { defer d.loops.Done(); d.send(ctx); cancel() }()
	go func() { defer d.loops.Done(); d.receive(); cancel() }()
	go func() { <-ctx.Done(); d.Close() }()
	return d, nil
}

func (d *Dialer) Done() <-chan struct{} { return d.done }

func (d *Dialer) Close() error {
	d.closeOnce.Do(func() {
		defer close(d.done)
		d.cancel()
		// Stop injecting packets before removing their PF rules.
		deviceErr := d.device.Close()
		d.loops.Wait()
		d.stack.Close()
		d.link.Close()
		d.closeErr = d.pf.close()
		if d.closeErr == nil {
			d.closeErr = deviceErr
		}
	})
	return d.closeErr
}

func (d *Dialer) send(ctx context.Context) {
	buf := make([]byte, tunHeader, tunHeader+mtu)
	buffers := [][]byte{nil}
	for {
		packet := d.link.ReadContext(ctx)
		if packet.IsNil() {
			return
		}
		view := packet.ToView()
		packet.DecRef()
		buffers[0] = append(buf[:tunHeader], view.AsSlice()...)
		view.Release()
		if _, err := d.device.Write(buffers, tunHeader); err != nil && !errors.Is(err, unix.ENOBUFS) {
			return
		}
	}
}

func (d *Dialer) receive() {
	// PF can route an already-fragmented datagram, or a datagram as large as
	// the interface originally selected by the backend.
	buf := make([]byte, 65535+tunHeader)
	buffers := [][]byte{buf}
	sizes := []int{0}
	for {
		n, err := d.device.Read(buffers, sizes, tunHeader)
		if err != nil {
			return
		}
		if n == 0 || sizes[0] == 0 {
			continue
		}
		data := buf[tunHeader : tunHeader+sizes[0]]
		if data[0]>>4 != 4 {
			continue
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data...))})
		d.link.InjectInbound(ipv4.ProtocolNumber, packet)
		packet.DecRef()
	}
}

func (d *Dialer) Dial(ctx context.Context, network string, visitor netip.AddrPort, target netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if network == "udp" {
		target = d.udp.destination(ctx, target, visitor)
	}
	addr, err := d.pf.destination(ctx, target.Addr())
	if err != nil {
		return nil, err
	}
	local := tcpip.FullAddress{NIC: nic, Addr: tcpip.AddrFromSlice(visitor.Addr().AsSlice())}
	remote := tcpip.FullAddress{NIC: nic, Addr: tcpip.AddrFromSlice(addr.AsSlice()), Port: target.Port()}
	switch network {
	case "tcp":
		return gonet.DialTCPWithBind(ctx, d.stack, local, remote, ipv4.ProtocolNumber)
	case "udp":
		local.Port = visitor.Port()
		conn, err := gonet.DialUDP(d.stack, &local, &remote, ipv4.ProtocolNumber)
		if err != nil && local.Port != 0 {
			local.Port = 0
			return gonet.DialUDP(d.stack, &local, &remote, ipv4.ProtocolNumber)
		}
		return conn, err
	default:
		return nil, fmt.Errorf("unsupported transport %q", network)
	}
}
