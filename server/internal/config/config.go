// Package config loads the OpenNoFrp Server configuration (post-refactor:
// the Server is rule-authoritative, so its TOML is about process listeners
// and the SQLite data file, not port-range allowlists -- rule-level access
// control happens at the panel layer via the reserved-ports guard).
package config

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

// Config is the top-level Server configuration.
type Config struct {
	Server ServerConfig `toml:"server"`
	Log    LogConfig    `toml:"log"`
}

// ServerConfig describes the listeners and the data-directory layout of the
// Server/panel process.
type ServerConfig struct {
	// BindAddr the control port binds to (Clients connect here).
	BindAddr string `toml:"bind_addr"` // e.g. "0.0.0.0"
	// ControlPort is the TCP port Clients use for handshake/heartbeat.
	ControlPort int `toml:"control_port"` // e.g. 17000

	// PanelAddr/PanelPort serve the admin web UI.
	PanelAddr string `toml:"panel_addr"` // e.g. "0.0.0.0"
	PanelPort int    `toml:"panel_port"` // e.g. 8080

	// HeartbeatTimeoutSeconds: if no heartbeat (or any stream activity) is
	// seen from a Client within this many seconds, the Server considers it
	// disconnected. Its public listeners stay open (they're rule-driven,
	// not session-driven), but forwarded connections are refused until the
	// Client reconnects.
	HeartbeatTimeoutSeconds int `toml:"heartbeat_timeout_seconds"`

	// DBPath is the SQLite file holding admin account, clients, tokens,
	// rules, and reserved ports.
	DBPath string `toml:"db_path"` // e.g. "/var/lib/opennofrp/opennofrp.db"

	// ClientBinDir holds prebuilt client binaries served by /dl/* so the
	// one-line install command works without the client machine needing Go.
	ClientBinDir string `toml:"client_bin_dir"` // e.g. "/opt/opennofrp/client-bins"

	// PublicBaseURL is the base URL (scheme://host[:port]) external users
	// use to reach the panel. Used when rendering the one-line install
	// command. Defaults to http://<panel_addr-or-detected-host>:<panel_port>.
	PublicBaseURL string `toml:"public_base_url"`

	// TLSCertPath / TLSKeyPath 用于控制通道的 TLS 自签名证书与私钥
	TLSCertPath string `toml:"tls_cert_path"`
	TLSKeyPath  string `toml:"tls_key_path"`
}

type LogConfig struct {
	Level string `toml:"level"`
	File  string `toml:"file"`
}

func Load(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config: invalid: %w", err)
	}
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Server.BindAddr == "" {
		cfg.Server.BindAddr = "0.0.0.0"
	}
	if cfg.Server.ControlPort <= 0 {
		cfg.Server.ControlPort = 17000
	}
	if cfg.Server.PanelAddr == "" {
		cfg.Server.PanelAddr = "0.0.0.0"
	}
	if cfg.Server.PanelPort <= 0 {
		cfg.Server.PanelPort = 8080
	}
	if cfg.Server.HeartbeatTimeoutSeconds <= 0 {
		cfg.Server.HeartbeatTimeoutSeconds = 30
	}
	if cfg.Server.DBPath == "" {
		cfg.Server.DBPath = "/var/lib/opennofrp/opennofrp.db"
	}
	if cfg.Server.ClientBinDir == "" {
		cfg.Server.ClientBinDir = "/opt/opennofrp/client-bins"
	}
	if cfg.Server.TLSCertPath == "" {
		cfg.Server.TLSCertPath = "/var/lib/opennofrp/server.crt"
	}
	if cfg.Server.TLSKeyPath == "" {
		cfg.Server.TLSKeyPath = "/var/lib/opennofrp/server.key"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
}

func validate(cfg *Config) error {
	if cfg.Server.ControlPort <= 0 || cfg.Server.ControlPort > 65535 {
		return fmt.Errorf("server.control_port must be 1-65535, got %d", cfg.Server.ControlPort)
	}
	if cfg.Server.PanelPort <= 0 || cfg.Server.PanelPort > 65535 {
		return fmt.Errorf("server.panel_port must be 1-65535, got %d", cfg.Server.PanelPort)
	}
	return nil
}

// ExampleTOML returns a commented example server configuration.
func ExampleTOML() string {
	return `# OpenNoFrp Server configuration
# This process NEVER touches iptables/nftables/routing/sysctls. It is a
# pure userspace TCP/UDP forwarder. See docs/01-architecture.md.

[server]
bind_addr = "0.0.0.0"
control_port = 17000

panel_addr = "0.0.0.0"
panel_port = 8080

heartbeat_timeout_seconds = 30
db_path = "/var/lib/opennofrp/opennofrp.db"
client_bin_dir = "/opt/opennofrp/client-bins"
# public_base_url = "https://frp.example.com:8080"  # used in generated install commands

[log]
level = "info"
# file = "/var/log/opennofrp/server.log"  # empty = stdout
`
}
