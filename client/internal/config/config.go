// Package config 负责加载并校验 OpenNoFrp Client 的配置。
//
// 文件格式为 TOML。经过产品化重构后，Client 不再自行定义 [[proxy]] 规则：
// 所有转发规则都存放在 Server 的数据库中，通过 Web 面板管理，并经控制连接
// 推送给 Client。因此 Client 的本地配置被刻意精简 —— 只包含如何连接
// Server，以及本机首次启动时使用的一次性注册 token。
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config 是 Client 的顶层配置，通常从 /etc/opennofrp/client.toml（Linux）
// 或通过 -c 参数传入的路径加载。
type Config struct {
	Server ServerConfig `toml:"server"`
	Log    LogConfig    `toml:"log"`
}

// ServerConfig 描述如何连接 OpenNoFrp Server 的控制端口。
type ServerConfig struct {
	Addr        string `toml:"addr"`        // 例如 "120.26.183.14"
	Port        int    `toml:"port"`        // 控制端口，例如 17000
	Token       string `toml:"token"`       // 来自面板的一次性注册 token；仅在尚不存在凭据文件时需要
	Fingerprint string `toml:"fingerprint"` // 服务端 TLS 证书的 SHA-256 指纹 (Certificate Pinning)

	// HeartbeatIntervalSeconds 控制 Client 在控制连接上发送心跳的频率。
	// 为零时默认为 10。
	HeartbeatIntervalSeconds int `toml:"heartbeat_interval_seconds"`

	// ReconnectMinSeconds / ReconnectMaxSeconds 控制控制连接断开并需要
	// 重新建立时的指数退避。
	ReconnectMinSeconds int `toml:"reconnect_min_seconds"`
	ReconnectMaxSeconds int `toml:"reconnect_max_seconds"`
}

// LogConfig 控制日志的详细程度/输出位置。
type LogConfig struct {
	Level string `toml:"level"` // "debug"、"info"、"warn"、"error"
	File  string `toml:"file"`  // 为空 = stdout
}

// CredentialsPath 返回一次性注册成功后永久 client_id/client_secret 对的
// 持久化位置。默认与主配置文件位于同一目录，可通过环境变量
// OPENNOFRP_CREDENTIALS 覆盖（便于在开发虚拟机中测试而无需改动 /etc）。
func CredentialsPath(configPath string) string {
	if v := os.Getenv("OPENNOFRP_CREDENTIALS"); v != "" {
		return v
	}
	return filepath.Join(filepath.Dir(configPath), "client_credentials.toml")
}

// Credentials 是 Client 在完成一次性注册后用于每次连接的永久身份。
type Credentials struct {
	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`
	Fingerprint  string `toml:"fingerprint"` // 首次信任 (TOFU) 保存的服务端证书指纹
}

// LoadCredentials 读取已持久化的凭据；当文件尚不存在时（即本机从未完成
// 注册）返回 (nil, nil) —— 而不是错误。
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

// SaveCredentials 以仅所有者可访问的权限将永久凭据原子地写入 path
// （client_secret 等同于密码）。
func SaveCredentials(path string, c Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: mkdir for credentials: %w", err)
	}
	data := fmt.Sprintf("client_id = %q\nclient_secret = %q\nfingerprint = %q\n", c.ClientID, c.ClientSecret, c.Fingerprint)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
		return fmt.Errorf("config: write credentials: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: rename credentials: %w", err)
	}
	return nil
}

// Load 从给定路径读取并校验 Config。
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

// ExampleTOML 返回一份带注释的示例配置，供安装脚本生成初始配置文件。
// 重构之后这里不再有 [[proxy]] 段 —— 规则改为在 Web 面板中创建。
func ExampleTOML() string {
	return `# OpenNoFrp Client configuration
# Forwarding rules are NOT defined here. Open the Server's web panel,
# register this machine, and create rules there; they are pushed to this
# Client automatically over the control connection.

[server]
addr = "YOUR_SERVER_IP"
port = 17000

# 服务端 TLS 证书的 SHA-256 指纹 (Certificate Pinning)，用于防中间人攻击。
# 一键安装脚本会自动填入此项；也可留空以启用 TOFU (首次使用自动信任)。
# fingerprint = "SHA256:2D:4F:9A:..."

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

// WriteExampleConfig 将初始配置文件写入 path；若文件已存在则失败
// （安装脚本不应悄无声息地覆盖已有配置）。
func WriteExampleConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config: %s already exists, refusing to overwrite", path)
	}
	return os.WriteFile(path, []byte(ExampleTOML()), 0o600)
}
