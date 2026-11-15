//go:build darwin

// macOS 平台的源 IP 保留占位实现：受限于无法使用 Linux 的 TPROXY/CONNMARK
// 机制，保留访问者源 IP 的规则会自动降级为普通转发（见 rulesync.go）。
package rulesync

import (
	"context"
	"net"

	"opennofrp/pkg/protocol"
)

// sourceIPSupported 报告本平台是否支持保留访问者源 IP。
func sourceIPSupported() bool { return false }

// dialPreservingSource 在 macOS 上总是返回 (nil, nil)，调用方会回退为普通转发。
func (r *Reconciler) dialPreservingSource(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata, target string) (net.Conn, error) {
	return nil, nil
}

// dialSpoofedUDP 在 macOS 上总是返回错误，调用方会回退为普通转发。
func (r *Reconciler) dialSpoofedUDP(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata) (net.Conn, error) {
	return nil, protocol.ErrNotSupported
}
