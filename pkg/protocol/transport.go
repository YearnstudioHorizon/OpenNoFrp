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
	return cfg
}
