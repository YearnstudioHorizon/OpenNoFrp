// Package config loads and validates the OpenNoFrp Client configuration.
//
// The file format is TOML. After the productization refactor the Client no
// longer defines its own [[proxy]] rules: all forwarding rules live in the
// Server's database, are managed via the web panel, and are pushed to the
// Client over the control connection. The Client's local configuration is
// therefore deliberately minimal -- how to reach the Server, plus the
// one-time registration token used the first time this machine boots.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config is the top-level Client configuration, typically loaded from
// /etc/opennofrp/client.toml (Linux) or a path passed via -c flag.
type Config struct {
	Server ServerConfig `toml:"server"`
	Log    LogConfig    `toml:"log"`
}

// ServerConfig describes how to reach the OpenNoFrp Server control port.
type ServerConfig struct {
	Addr  string `toml:"addr"` // e.g. "120.26.183.14"
	Port  int    `toml:"port"` // control port, e.g. 17000
	Token string `toml:"token"` // one-time registration token from the panel; only needed when no credentials file exists yet

	// HeartbeatIntervalSeconds controls how often the Client sends a
	// heartbeat on the control connection. Defaults to 10 if zero.
	HeartbeatIntervalSeconds int `toml:"heartbeat_interval_seconds"`

	// ReconnectMinSeconds / ReconnectMaxSeconds control exponential backoff
	// when the control connection drops and needs to be re-established.
	ReconnectMinSeconds int `toml:"reconnect_min_seconds"`
	ReconnectMaxSeconds int `toml:"reconnect_max_seconds"`
}

// LogConfig controls logging verbosity/output.
type LogConfig struct {
	Level string `toml:"level"` // "debug", "info", "warn", "error"
	File  string `toml:"file"`  // empty = stdout
}

// CredentialsPath returns where the permanent client_id/client_secret pair
// is persisted after a successful one-time registration. Sits next to the
// main config by default, overridable via the OPENNOFRP_CREDENTIALS env var
// (useful for testing inside the dev VM without touching /etc).
func CredentialsPath(configPath string) string {
	if v := os.Getenv("OPENNOFRP_CREDENTIALS"); v != "" {
		return v
	}
	return filepath.Join(filepath.Dir(configPath), "client_credentials.toml")
}

// Credentials is the permanent identity the Client uses for every
// connection after its one-time registration completes.
type Credentials struct {
	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`
}

// LoadCredentials reads persisted credentials, returning (nil, nil) -- not
// an error -- when the file simply does not exist yet (i.e. this machine
// has never completed registration).
func LoadCredentials(path string) (*Credentials, error) {
	var c Credentials
	if _, err := toml.DecodeFile(path, &c); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("config: decode credentials %s: %w", path, err)
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, fmt.Errorf("config: credentials file %s is missing client_id or client_secret", path)
	}
	return &c, nil
}

// SaveCredentials atomically writes the permanent credentials to path with
// owner-only permissions (the client_secret is a password-equivalent).
func SaveCredentials(path string, c Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: mkdir for credentials: %w", err)
	}
	data := fmt.Sprintf("client_id = %q\nclient_secret = %q\n", c.ClientID, c.ClientSecret)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
		return fmt.Errorf("config: write credentials: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: rename credentials: %w", err)
	}
	return nil
}

// Load reads and validates a Config from the given path.
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
	if cfg.Server.HeartbeatIntervalSeconds <= 0 {
		cfg.Server.HeartbeatIntervalSeconds = 10
	}
	if cfg.Server.ReconnectMinSeconds <= 0 {
		cfg.Server.ReconnectMinSeconds = 1
	}
	if cfg.Server.ReconnectMaxSeconds <= 0 {
		cfg.Server.ReconnectMaxSeconds = 60
	}
	if cfg.Server.Port <= 0 {
		cfg.Server.Port = 17000
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
}

func validate(cfg *Config) error {
	if cfg.Server.Addr == "" {
		return fmt.Errorf("server.addr is required")
	}
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port must be 1-65535, got %d", cfg.Server.Port)
	}
	return nil
}

// ExampleTOML returns a commented example configuration, used by the install
// script to seed a starter config file. After the refactor there is no
// [[proxy]] section here -- rules are created in the web panel instead.
func ExampleTOML() string {
	return `# OpenNoFrp Client configuration
# Forwarding rules are NOT defined here. Open the Server's web panel,
# register this machine, and create rules there; they are pushed to this
# Client automatically over the control connection.

[server]
addr = "YOUR_SERVER_IP"
port = 17000

# One-time registration token, copied from the panel's "add internal
# machine" output. Only needed on the FIRST start of this machine -- after
# that the permanent credentials in client_credentials.toml are used and
# this value can be deleted.
token = "PASTE_REGISTRATION_TOKEN_HERE"

heartbeat_interval_seconds = 10
reconnect_min_seconds = 1
reconnect_max_seconds = 60

[log]
level = "info"
# file = "/var/log/opennofrp/client.log"  # empty = stdout
`
}

// WriteExampleConfig writes a starter config file to path, failing if it
// already exists (the install script should not silently clobber an
// existing configuration).
func WriteExampleConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config: %s already exists, refusing to overwrite", path)
	}
	return os.WriteFile(path, []byte(ExampleTOML()), 0o600)
}
