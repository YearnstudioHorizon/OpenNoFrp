//go:build windows

package hosts

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

func systemPath() string {
	root, err := windows.GetWindowsDirectory()
	if err != nil {
		return "C:\\Windows\\System32\\drivers\\etc\\hosts"
	}
	return filepath.Join(root, "System32", "drivers", "etc", "hosts")
}
func lock(f *os.File) (func(), error) {
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 0xffffffff, 0xffffffff, &overlapped); err != nil {
		return nil, err
	}
	return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 0xffffffff, 0xffffffff, &overlapped) }, nil
}
func flushCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exec.CommandContext(ctx, "ipconfig.exe", "/flushdns").Run()
}
