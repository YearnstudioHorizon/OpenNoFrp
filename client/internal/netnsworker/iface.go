package netnsworker

import (
	"fmt"
	"net"
)

// netInterfacesExcludingLoopback 列出当前网络命名空间中的网络接口名称（不含
// "lo"）。必须在 RunInNamespace 回调中调用，才能反映目标命名空间（而非宿主机）
// 的接口。
func netInterfacesExcludingLoopback() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("netnsworker: list interfaces: %w", err)
	}
	var names []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		names = append(names, iface.Name)
	}
	return names, nil
}
