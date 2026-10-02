package netnsworker

import (
	"fmt"
	"net"
)

// netInterfacesExcludingLoopback lists network interface names in the
// current network namespace, excluding "lo". Must be called from within a
// RunInNamespace callback to reflect the target namespace's interfaces,
// not the host's.
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
