// Package config 加载 OpenNoFrp Server 的配置（重构后：Server 是规则的权威来源，
// 因此其 TOML 配置关注的是进程监听地址和 SQLite 数据文件，而不是端口范围白名单——
// 规则级别的访问控制由面板层通过保留端口守卫来实现）。
package config

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

// Config 是 Server 的顶层配置。
type Config struct {
	Server ServerConfig `toml:"server"`
	Log    LogConfig    `toml:"log"`
}

// ServerConfig 描述 Server/面板进程的监听地址以及数据目录布局。
type ServerConfig struct {
	// BindAddr 是控制端口绑定的地址（Client 连接到这里）。
	BindAddr string `toml:"bind_addr"` // 例如 "0.0.0.0"
	// ControlPort 是 Client 用于握手/心跳的 TCP 端口。
	ControlPort int `toml:"control_port"` // 例如 17000

	// PanelAddr/PanelPort 用于提供管理后台 Web UI。
	PanelAddr string `toml:"panel_addr"` // 例如 "0.0.0.0"
	PanelPort int    `toml:"panel_port"` // 例如 8080

	// HeartbeatTimeoutSeconds：如果在这么多秒内没有收到某个 Client 的心跳
	// （或任何流活动），Server 就认为它已断开连接。其公网监听仍保持开启
	// （它们由规则驱动，而非由会话驱动），但在 Client 重新连接之前，转发连接
	// 会被拒绝。
	HeartbeatTimeoutSeconds int `toml:"heartbeat_timeout_seconds"`

	// DBPath 是保存管理员账户、客户端、token、规则和保留端口的 SQLite 文件。
	DBPath string `toml:"db_path"` // 例如 "/var/lib/opennofrp/opennofrp.db"

	// ClientBinDir 存放由 /dl/* 提供下载的预编译客户端二进制文件，使一行安装
	// 命令无需客户端机器安装 Go 即可使用。
	ClientBinDir string `toml:"client_bin_dir"` // 例如 "/opt/opennofrp/client-bins"

	// PublicBaseURL 是外部用户访问面板所用的基础 URL（scheme://host[:port]）。
	// 在渲染一行安装命令时使用。默认为
	// http://<panel_addr-or-detected-host>:<panel_port>。
	PublicBaseURL string `toml:"public_base_url"`

	// TLSCertPath / TLSKeyPath 用于控制通道的 TLS 自签名证书与私钥
	TLSCertPath string `toml:"tls_cert_path"`
	TLSKeyPath  string `toml:"tls_key_path"`

	// ACME（Let's Encrypt 等）自动证书设置，供 HTTPS 规则使用。
	// ACMEEmail 为证书到期/吊销通知邮箱（可为空）。
	ACMEEmail string `toml:"acme_email"`
	// ACMECacheDir 保存已签发证书与 ACME 账户密钥的目录。
	ACMECacheDir string `toml:"acme_cache_dir"`
	// ACMEDirectoryURL 为 ACME 目录地址，留空使用 Let's Encrypt 生产环境。
	ACMEDirectoryURL string `toml:"acme_directory_url"`
	// ACMEAcceptTOS 必须为 true 才会实际向 CA 申请证书（表示同意 CA 服务条款）。
	ACMEAcceptTOS bool `toml:"acme_accept_tos"`
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
	if cfg.Server.ACMECacheDir == "" {
		cfg.Server.ACMECacheDir = "/var/lib/opennofrp/acme"
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

// ExampleTOML 返回一份带注释的服务端示例配置。
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

# ACME automatic certificates for HTTPS rules (Let's Encrypt by default).
# Certificates are only requested when acme_accept_tos = true.
# acme_email = "admin@example.com"
# acme_cache_dir = "/var/lib/opennofrp/acme"
# acme_directory_url = ""  # empty = Let's Encrypt production
# acme_accept_tos = false

[log]
level = "info"
# file = "/var/log/opennofrp/server.log"  # empty = stdout
`
}
