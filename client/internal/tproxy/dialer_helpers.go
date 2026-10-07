package tproxy

import (
	"os"
	"time"
)

// fileFromFD 将原始文件描述符包装为 *os.File，以便传给 net.FileConn。
// 就 net.FileConn（其内部会 dup() 该描述符）而言，返回的 *os.File 接管了 fd
// 的所有权，因此调用方在正常的错误路径中仍应关闭原始 fd；但一旦
// net.FileConn 成功，就应关闭该 *os.File 本身（net.FileConn 保留的是它的 dup 副本）。
func fileFromFD(fd int) *os.File {
	return os.NewFile(uintptr(fd), "opennofrp-tproxy-upstream")
}

func secondsToDuration(s int) time.Duration {
	return time.Duration(s) * time.Second
}
