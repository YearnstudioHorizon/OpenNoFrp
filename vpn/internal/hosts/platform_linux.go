//go:build linux

package hosts

import (
	"os"

	"golang.org/x/sys/unix"
)

func systemPath() string { return "/etc/hosts" }
func lock(f *os.File) (func(), error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN) }, nil
}
func flushCache() {} // Linux resolver/cache behavior varies; no services are restarted.
