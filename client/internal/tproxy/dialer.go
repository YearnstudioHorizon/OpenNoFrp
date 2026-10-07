package tproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// SpoofedDialer 连接本地服务，同时借助 Linux 的 IP_TRANSPARENT 套接字选项，
// 让该连接的源 IP 显示为任意地址（即原始远端客户端的真实 IP）。这需要
// root/CAP_NET_ADMIN+CAP_NET_RAW 权限，并且目标必须可经由一张把所选源地址
// 视为可本地投递的路由表到达（参见 route.go 中的 EnsurePolicyRoute，本包依赖
// 它事先完成配置）。
//
// Timeout 很重要：在内核级路由/CONNMARK 配置有误的异常情况下，这个 connect()
// 调用会一直挂起，直到 TCP 自身的 SYN 重传超时，而不是快速失败。设置一个宽松
// 但有上限的超时（几秒钟），可以把无声的挂起变成可据以排查的错误。
type SpoofedDialer struct {
	Timeout int // 单位为秒，0 = 使用合理的默认值（4s）

	// FWMark 若非零，则通过 SO_MARK 设置到出站 connect() 所用的套接字上。
	// 这是连接成功的【必要条件】：它让内核的策略路由（参见
	// EnsurePolicyRoute/table 100）把这个新连接——以及至关重要的、由本地服务
	// 发回的 SYN-ACK 回包——识别为属于我们的“本地投递”路由类别。若没有它，
	// 回包的 CONNMARK 恢复将无标记可恢复（该连接从一开始就没有被打标记），
	// 握手会无声地永远无法完成，connect() 会一直挂起直到超时。这一点是在
	// 痛苦的端到端测试中才发现的；事后回看，之前的沙箱验证只覆盖了恰好
	// 不受此影响的场景。必须与对应 tproxy.RuleSpec 中使用的 FWMark 一致。
	FWMark uint32
}

func (d SpoofedDialer) timeoutSeconds() int {
	if d.Timeout <= 0 {
		return 4
	}
	return d.Timeout
}

// DialSpoofed 连接到 (targetIP, targetPort)，并将连接的本地（源）地址设置为
// (spoofSourceIP, 0)——临时端口会被自动选择。返回的 net.Conn 与其他任何 TCP
// 连接的行为相同；由调用方负责关闭它。
func (d SpoofedDialer) DialSpoofed(ctx context.Context, spoofSourceIP net.IP, targetIP net.IP, targetPort uint16) (net.Conn, error) {
	ipv4 := targetIP.To4() != nil
	var domain int
	if ipv4 {
		domain = unix.AF_INET
	} else {
		domain = unix.AF_INET6
	}

	fd, err := unix.Socket(domain, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("tproxy: socket: %w", err)
	}
	// 从这里开始，任何提前返回都必须关闭 fd，以免泄漏。
	closeOnErr := func(err error) (net.Conn, error) {
		unix.Close(fd)
		return nil, err
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return closeOnErr(fmt.Errorf("tproxy: SO_REUSEADDR: %w", err))
	}

	// 正是 IP_TRANSPARENT 使下面的 bind() 能够绑定到非本地地址。
	level := unix.SOL_IP
	if !ipv4 {
		level = unix.SOL_IPV6
	}
	if err := unix.SetsockoptInt(fd, level, unix.IP_TRANSPARENT, 1); err != nil {
		return closeOnErr(fmt.Errorf("tproxy: IP_TRANSPARENT: %w (are you root? CAP_NET_ADMIN+CAP_NET_RAW required)", err))
	}

	if d.FWMark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(d.FWMark)); err != nil {
			return closeOnErr(fmt.Errorf("tproxy: SO_MARK: %w", err))
		}
	}

	if err := bindSpoofedSource(fd, ipv4, spoofSourceIP); err != nil {
		return closeOnErr(err)
	}

	if err := connectWithTimeout(ctx, fd, ipv4, targetIP, targetPort, d.timeoutSeconds()); err != nil {
		return closeOnErr(err)
	}

	file := fileFromFD(fd)
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		return closeOnErr(fmt.Errorf("tproxy: net.FileConn: %w", err))
	}
	return conn, nil
}

func bindSpoofedSource(fd int, ipv4 bool, srcIP net.IP) error {
	if ipv4 {
		var addr unix.SockaddrInet4
		ip4 := srcIP.To4()
		if ip4 == nil {
			return fmt.Errorf("tproxy: spoof source %s is not a valid IPv4 address", srcIP)
		}
		copy(addr.Addr[:], ip4)
		addr.Port = 0
		if err := unix.Bind(fd, &addr); err != nil {
			return fmt.Errorf("tproxy: bind spoofed source %s: %w", srcIP, err)
		}
		return nil
	}
	var addr unix.SockaddrInet6
	ip6 := srcIP.To16()
	if ip6 == nil {
		return fmt.Errorf("tproxy: spoof source %s is not a valid IPv6 address", srcIP)
	}
	copy(addr.Addr[:], ip6)
	addr.Port = 0
	if err := unix.Bind(fd, &addr); err != nil {
		return fmt.Errorf("tproxy: bind spoofed source %s: %w", srcIP, err)
	}
	return nil
}

func connectWithTimeout(ctx context.Context, fd int, ipv4 bool, targetIP net.IP, targetPort uint16, timeoutSeconds int) error {
	// 将套接字设为非阻塞，使 connect() 立即返回 EINPROGRESS，然后采用
	// select/poll 式的等待，其时长同时受调用方 context 和我们自己的超时约束。
	// 正是这样，路由配置错误导致的挂起才会变成一个清晰、有时限的错误，
	// 而不是阻塞整个操作系统 SYN 重试周期（可能长达 2 分钟以上）。
	if err := unix.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("tproxy: set non-blocking: %w", err)
	}

	var connectErr error
	if ipv4 {
		var addr unix.SockaddrInet4
		ip4 := targetIP.To4()
		if ip4 == nil {
			return fmt.Errorf("tproxy: target %s is not a valid IPv4 address", targetIP)
		}
		copy(addr.Addr[:], ip4)
		addr.Port = int(targetPort)
		connectErr = unix.Connect(fd, &addr)
	} else {
		var addr unix.SockaddrInet6
		ip6 := targetIP.To16()
		if ip6 == nil {
			return fmt.Errorf("tproxy: target %s is not a valid IPv6 address", targetIP)
		}
		copy(addr.Addr[:], ip6)
		addr.Port = int(targetPort)
		connectErr = unix.Connect(fd, &addr)
	}

	if connectErr != nil && connectErr != unix.EINPROGRESS {
		return fmt.Errorf("tproxy: connect to %s:%d: %w", targetIP, targetPort, connectErr)
	}

	// 等待套接字变为可写（connect 完成）或超时。
	pollCtx, cancel := context.WithTimeoutCause(ctx, secondsToDuration(timeoutSeconds),
		fmt.Errorf("tproxy: connect to %s:%d timed out after %ds (check: TPROXY rules, policy routing table, CONNMARK save/restore, sysctls -- see docs/01-architecture.md section 6.1)", targetIP, targetPort, timeoutSeconds))
	defer cancel()

	done := make(chan error, 1)
	go func() {
		var pfd unix.PollFd
		pfd.Fd = int32(fd)
		pfd.Events = unix.POLLOUT
		for {
			n, err := unix.Poll([]unix.PollFd{pfd}, 100)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				done <- fmt.Errorf("tproxy: poll: %w", err)
				return
			}
			if n > 0 {
				break
			}
			select {
			case <-pollCtx.Done():
				return
			default:
			}
		}
		soErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			done <- fmt.Errorf("tproxy: SO_ERROR: %w", err)
			return
		}
		if soErr != 0 {
			done <- fmt.Errorf("tproxy: connect to %s:%d: %w", targetIP, targetPort, syscall.Errno(soErr))
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			return err
		}
	case <-pollCtx.Done():
		return context.Cause(pollCtx)
	}

	if err := unix.SetNonblock(fd, false); err != nil {
		return fmt.Errorf("tproxy: clear non-blocking: %w", err)
	}
	return nil
}
