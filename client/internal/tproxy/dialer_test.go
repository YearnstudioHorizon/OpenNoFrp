//go:build linux

package tproxy

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestTransparentSocketKeepAlive(t *testing.T) {
	for _, domain := range []int{unix.AF_INET, unix.AF_INET6} {
		t.Run(map[int]string{unix.AF_INET: "ipv4", unix.AF_INET6: "ipv6"}[domain], func(t *testing.T) {
			fd, err := unix.Socket(domain, unix.SOCK_STREAM, unix.IPPROTO_TCP)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if err := configureTCPKeepAlive(fd); err != nil {
				t.Fatal(err)
			}
			for _, opt := range []struct{ level, name, want int }{{unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1}, {unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, 30}, {unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 10}, {unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 6}} {
				got, err := unix.GetsockoptInt(fd, opt.level, opt.name)
				if err != nil || got != opt.want {
					t.Fatalf("option %d: got %d, want %d: %v", opt.name, got, opt.want, err)
				}
			}
		})
	}
}
