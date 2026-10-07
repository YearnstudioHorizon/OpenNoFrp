// Command netnsworker-poc 是一个独立的概念验证（PoC）二进制程序，用于
// 验证 netnsworker 包的核心论断：Go 程序可以通过 setns(2) 进入目标 Docker
// 容器的网络命名空间，在该命名空间内部（以该命名空间自身的 127.0.0.1 为目标）
// 设置 TPROXY 规则和伪造源 IP 的转发器，使经由容器常规的 "docker run -p"
// 端口映射到达的外部流量从另一端出来时仍保留真实外部客户端的 IP —— 全程
// 无需改动容器、其端口映射或任何主机级 TPROXY 规则。
//
// 用法：netnsworker-poc <container-pid> <port> <fwmark>
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"opennofrp/client/internal/netnsworker"
	"opennofrp/client/internal/tproxy"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: netnsworker-poc <container-pid> <port> <fwmark>")
		os.Exit(1)
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("invalid pid: %v", err)
	}
	port, err := strconv.ParseUint(os.Args[2], 10, 16)
	if err != nil {
		log.Fatalf("invalid port: %v", err)
	}
	fwmarkInt, err := strconv.ParseUint(os.Args[3], 10, 32)
	if err != nil {
		log.Fatalf("invalid fwmark: %v", err)
	}
	fwmark := uint32(fwmarkInt)
	targetPort := uint16(port)

	cns := netnsworker.ContainerNetns{PID: pid}

	err = cns.RunInNamespace(func() error {
		iface, err := netnsworker.IngressInterface()
		if err != nil {
			return fmt.Errorf("detect ingress interface: %w", err)
		}
		log.Printf("[netnsworker-poc] running inside container netns (pid=%d), ingress interface: %s", pid, iface)

		// 在此命名空间内部应用 TPROXY mangle 规则（我们已通过 setns()
		// 进入，因此这里的 iptables-legacy 操作的是该命名空间自己的表，
		// 而不是主机的表）。
		spec := tproxy.RuleSpec{
			PublicPort:   targetPort,
			IngressIface: iface,
			ListenPort:   10001,
			FWMark:       fwmark,
		}
		if err := tproxy.AddTproxyRule(spec); err != nil {
			return fmt.Errorf("add tproxy rule: %w", err)
		}
		log.Printf("[netnsworker-poc] TPROXY rule applied inside container netns")

		if err := tproxy.ApplySysctls(iface); err != nil {
			return fmt.Errorf("apply sysctls: %w", err)
		}
		log.Printf("[netnsworker-poc] sysctls applied inside container netns")

		if err := tproxy.EnsurePolicyRoute(tproxy.DefaultRouteTable, fwmark); err != nil {
			return fmt.Errorf("ensure policy route: %w", err)
		}
		log.Printf("[netnsworker-poc] policy route applied inside container netns")

		return runForwarder(cns, spec, targetPort)
	})
	if err != nil {
		log.Fatalf("[netnsworker-poc] FATAL: %v", err)
	}
}

// runForwarder 在 TPROXY 重定向端口上监听（位于容器的 netns 内，因为运行到
// 这里时我们已经通过 setns() 进入），并将每个连接转发到同一命名空间内的
// 127.0.0.1:targetPort，借助 IP_TRANSPARENT + SO_MARK 将源 IP 伪造为原始
// 外部客户端的地址。
func runForwarder(cns netnsworker.ContainerNetns, spec tproxy.RuleSpec, targetPort uint16) error {
	lc := net.ListenConfig{Control: controlSetTransparent}
	ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf("0.0.0.0:%d", spec.ListenPort))
	if err != nil {
		return fmt.Errorf("listen on tproxy port %d: %w", spec.ListenPort, err)
	}
	log.Printf("[netnsworker-poc] TPROXY listener on 0.0.0.0:%d (inside container netns)", spec.ListenPort)

	dialer := tproxy.SpoofedDialer{FWMark: spec.FWMark}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[netnsworker-poc] accept error: %v", err)
			continue
		}
		// 关键：此处切勿直接启动裸的 "go handleConn(...)"。该 goroutine
		// 同样必须运行在已通过 setns() 进入目标容器网络命名空间的 OS 线程上，
		// 因为 handleConn 内部（经由 DialSpoofed）的上游 socket() 调用会创建
		// 一个全新的文件描述符，而新 fd 所属的网络命名空间取决于调用
		// unix.Socket() 那一刻所在 OS 线程当前生效的 netns —— 而不是该
		// goroutine 在逻辑上"属于"哪个 accept 循环。Go 调度器可以把未锁定的
		// goroutine 调度到任意 OS 线程上，包括仍处于主机根命名空间中的线程，
		// 这正是最初 PoC 测试时发生的情况：TPROXY 监听器工作正常（其 socket
		// 在初始化阶段于正确锁定的线程上同步创建了一次），但每个连接的上游
		// 拨号却悄无声息地在主机命名空间中创建了 socket，连接到主机自身
		// （没有服务的）127.0.0.1:9999 并超时。基于 nsenter 的（Python）测试
		// 从未遇到这个问题，因为 nsenter 使用 execve()，它会把命名空间带到
		// 生成进程的每一个线程上 —— 在那里根本不可能"逃逸到未锁定的线程"。
		// Go 的 goroutine 模型没有这种全面的保证，因此每个连接处理函数都
		// 必须各自重新固定自身。
		go func(c net.Conn) {
			if err := cns.Enter(); err != nil {
				log.Printf("[netnsworker-poc] FATAL: per-connection netns Enter failed: %v", err)
				c.Close()
				return
			}
			handleConn(c, dialer, targetPort)
		}(conn)
	}
}

func handleConn(clientConn net.Conn, dialer tproxy.SpoofedDialer, targetPort uint16) {
	defer clientConn.Close()

	remoteAddr, ok := clientConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("[netnsworker-poc] non-TCP remote addr, dropping")
		return
	}
	log.Printf("[netnsworker-poc] accepted connection, original client: %s, original dst (via getsockname): %s",
		remoteAddr, clientConn.LocalAddr())

	upstream, err := dialer.DialSpoofed(context.Background(), remoteAddr.IP, net.ParseIP("127.0.0.1"), targetPort)
	if err != nil {
		log.Printf("[netnsworker-poc] spoofed dial failed: %v", err)
		return
	}
	defer upstream.Close()
	log.Printf("[netnsworker-poc] connected upstream to 127.0.0.1:%d spoofing source %s", targetPort, remoteAddr.IP)

	relay(clientConn, upstream)
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}

// controlSetTransparent 在 bind() 之前为监听 socket 设置 IP_TRANSPARENT 和
// SO_REUSEADDR，使 accept() 得到的连接按照 TPROXY 语义通过 getsockname()
// 报告该连接的原始目的地址。
// （此处是复制而非从 forwarder 包导入，以保持这个独立 PoC 二进制程序的
// 依赖图最小且自包含。）
func controlSetTransparent(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockErr = err
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			sockErr = err
			return
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}
