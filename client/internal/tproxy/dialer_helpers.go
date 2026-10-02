package tproxy

import (
	"os"
	"time"
)

// fileFromFD wraps a raw file descriptor as an *os.File so it can be handed
// to net.FileConn. The returned *os.File takes ownership of fd for the
// purposes of net.FileConn (which dup()s it internally), so the caller
// should still close the original fd through normal error paths, but once
// net.FileConn succeeds the *os.File itself should be closed (its dup is
// what net.FileConn keeps).
func fileFromFD(fd int) *os.File {
	return os.NewFile(uintptr(fd), "opennofrp-tproxy-upstream")
}

func secondsToDuration(s int) time.Duration {
	return time.Duration(s) * time.Second
}
