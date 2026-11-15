//go:build linux

package controlconn

import "opennofrp/pkg/protocol"

// Linux 平台额外能力：基于 TPROXY/CONNMARK 的 UDP 源 IP 保留。
func init() {
	ClientCapabilities = append(ClientCapabilities, protocol.CapUDPSpoof)
}
