package forwarder

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// controlSetTransparent 是一个 net.ListenConfig.Control 钩子，在 bind() 之前
// 为监听 socket 设置 IP_TRANSPARENT 和 SO_REUSEADDR。正是监听 socket 上的
// IP_TRANSPARENT 使 accept() 得到的连接通过 getsockname() 报告该连接的*原始*
// 目的地址，而不是监听器自身绑定的地址（127.0.0.1:ListenPort）。这是整个包
// 所依赖的 TPROXY 特有行为。
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
