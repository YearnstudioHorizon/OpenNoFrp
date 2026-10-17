package protocol

import (
	"time"

	"github.com/hashicorp/yamux"
)

// ControlWriteTimeout allows control messages to survive brief congestion on
// the transport shared with tunnel traffic.
const ControlWriteTimeout = 30 * time.Second

// TunnelYamuxConfig keeps both peers' transport timeouts aligned. Keep sending
// probes every 30 seconds, but allow a minute for writes and probe responses.
func TunnelYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.ConnectionWriteTimeout = 60 * time.Second
	cfg.MaxStreamWindowSize = 1024 * 1024 // 1MB stream window for high throughput WAN transfers
	return cfg
}

// VPNYamuxConfig configures yamux sessions dedicated to temporary VPN access.
func VPNYamuxConfig() *yamux.Config {
	cfg := TunnelYamuxConfig()
	cfg.StreamOpenTimeout = 15 * time.Second
	return cfg
}
