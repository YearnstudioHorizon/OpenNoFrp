package tproxy

// UDP 源地址伪装拨号：与 TCP 的 DialSpoofed 相同，借助 IP_TRANSPARENT 把 UDP 套接字
// 绑定到访问者的真实 (IP, 端口)，再 connect() 到本地服务，使服务看到的数据报源地址
// 就是访问者地址。回包方向依赖与 TCP 相同的策略路由（fwmark -> 本地投递表）与
// CONNMARK save/restore（conntrack 同样跟踪 UDP 流）。

import (
	"context"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// DialSpoofedUDP 创建一个已 connect 到 (targetIP, targetPort) 的 UDP 套接字，其本地
// （源）地址为 (spoofSourceIP, spoofSourcePort)。若该源端口已被占用，则退回为由内核
// 选择临时端口（源 IP 仍然保留）。返回的 net.Conn 由调用方负责关闭。
func (d SpoofedDialer) DialSpoofedUDP(ctx context.Context, spoofSourceIP net.IP, spoofSourcePort uint16, targetIP net.IP, targetPort uint16) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := d.dialSpoofedUDP(spoofSourceIP, spoofSourcePort, targetIP, targetPort)
	if err != nil && spoofSourcePort != 0 && errors.Is(err, unix.EADDRINUSE) {
		return d.dialSpoofedUDP(spoofSourceIP, 0, targetIP, targetPort)
	}
	return conn, err
}

func (d SpoofedDialer) dialSpoofedUDP(srcIP net.IP, srcPort uint16, targetIP net.IP, targetPort uint16) (net.Conn, error) {
	ipv4 := targetIP.To4() != nil
	if ipv4 != (srcIP.To4() != nil) {
		return nil, fmt.Errorf("tproxy: udp spoof source %s and target %s are different address families", srcIP, targetIP)
	}
	domain := unix.AF_INET6
	level := unix.SOL_IPV6
	if ipv4 {
		domain = unix.AF_INET
		level = unix.SOL_IP
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("tproxy: udp socket: %w", err)
	}
	closeOnErr := func(err error) (net.Conn, error) {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return closeOnErr(fmt.Errorf("tproxy: udp SO_REUSEADDR: %w", err))
	}
	if err := unix.SetsockoptInt(fd, level, unix.IP_TRANSPARENT, 1); err != nil {
		return closeOnErr(fmt.Errorf("tproxy: udp IP_TRANSPARENT: %w (are you root? CAP_NET_ADMIN+CAP_NET_RAW required)", err))
	}
	if d.FWMark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(d.FWMark)); err != nil {
			return closeOnErr(fmt.Errorf("tproxy: udp SO_MARK: %w", err))
		}
	}

	if ipv4 {
		var src, dst unix.SockaddrInet4
		copy(src.Addr[:], srcIP.To4())
		src.Port = int(srcPort)
		if err := unix.Bind(fd, &src); err != nil {
			return closeOnErr(fmt.Errorf("tproxy: udp bind spoofed source %s:%d: %w", srcIP, srcPort, err))
		}
		copy(dst.Addr[:], targetIP.To4())
		dst.Port = int(targetPort)
		if err := unix.Connect(fd, &dst); err != nil {
			return closeOnErr(fmt.Errorf("tproxy: udp connect to %s:%d: %w", targetIP, targetPort, err))
		}
	} else {
		var src, dst unix.SockaddrInet6
		copy(src.Addr[:], srcIP.To16())
		src.Port = int(srcPort)
		if err := unix.Bind(fd, &src); err != nil {
			return closeOnErr(fmt.Errorf("tproxy: udp bind spoofed source [%s]:%d: %w", srcIP, srcPort, err))
		}
		copy(dst.Addr[:], targetIP.To16())
		dst.Port = int(targetPort)
		if err := unix.Connect(fd, &dst); err != nil {
			return closeOnErr(fmt.Errorf("tproxy: udp connect to [%s]:%d: %w", targetIP, targetPort, err))
		}
	}

	file := fileFromFD(fd)
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("tproxy: udp net.FileConn: %w", err)
	}
	return conn, nil
}
