package forwarder

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// controlSetTransparent is a net.ListenConfig.Control hook that sets
// IP_TRANSPARENT and SO_REUSEADDR on the listening socket before bind().
// IP_TRANSPARENT on the LISTENING socket is what makes accept()ed
// connections report the connection's *original* destination address via
// getsockname(), rather than the address the listener itself is bound to
// (127.0.0.1:ListenPort). This is the TPROXY-specific behavior this entire
// package depends on.
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
