// Package config 加载 OpenNoFrp Server 的配置（重构后：Server 是规则的权威来源，
// 因此其 TOML 配置关注的是进程监听地址和 SQLite 数据文件，而不是端口范围白名单——
// 规则级别的访问控制由面板层通过保留端口守卫来实现）。
package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config 是 Server 的顶层配置。
type Config struct {
	Server ServerConfig `toml:"server"`
	Log    LogConfig    `toml:"log"`
}

// ServerConfig 描述 Server/面板进程的监听地址以及数据目录布局。
type ServerConfig struct {
	// Bound public TCP relays independently of optional per-rule protection.
	MaxTCPConnections     int `toml:"max_tcp_connections"`
	TCPIdleTimeoutSeconds int `toml:"tcp_idle_timeout_seconds"`
	// BindAddr 是控制端口绑定的地址（Client 连接到这里）。
	BindAddr string `toml:"bind_addr"` // 例如 "0.0.0.0"
	// ControlPort 是 Client 用于握手/心跳的 TCP 端口。
	ControlPort int `toml:"control_port"` // 例如 17000

	// PanelAddr/PanelPort 用于提供管理后台 Web UI。
	PanelAddr string `toml:"panel_addr"` // 例如 "127.0.0.1"
	PanelPort int    `toml:"panel_port"` // 例如 8080
	// PanelTLSCert / PanelTLSKey 同时设置时，面板以 HTTPS 方式提供服务（PEM 文件路径）。
	// 两项均留空时，在 panel_addr 上以 HTTP 提供面板。
	PanelTLSCert string `toml:"panel_tls_cert"`
	PanelTLSKey  string `toml:"panel_tls_key"`
	// MetricsToken 非空时，面板的 /metrics 允许以 "Authorization: Bearer <token>"
	// 免登录抓取（供 Prometheus 使用）；为空时 /metrics 需要面板登录会话。
	MetricsToken string `toml:"metrics_token"`

	// HeartbeatTimeoutSeconds：如果在这么多秒内没有收到某个 Client 的心跳
	// （或其他控制消息），Server 就认为它已断开连接。默认 90 秒。其公网监听仍保持开启
	// （它们由规则驱动，而非由会话驱动），但在 Client 重新连接之前，转发连接
	// 会被拒绝。
	HeartbeatTimeoutSeconds int `toml:"heartbeat_timeout_seconds"`

	// DBPath 是保存管理员账户、客户端、token、规则和保留端口的 SQLite 文件。
	DBPath string `toml:"db_path"` // 例如 "/var/lib/opennofrp-server/opennofrp.db"

	// ClientBinDir 存放由 /dl/* 提供下载的预编译客户端二进制文件，使一行安装
	// 命令无需客户端机器安装 Go 即可使用。
	ClientBinDir string `toml:"client_bin_dir"` // 例如 "/opt/opennofrp-server/client-bins"

	// PublicBaseURL 是外部用户访问面板所用的基础 URL（scheme://host[:port]）。
	// 支持 HTTP 和 HTTPS。一键安装和迁移需要 HTTPS。
	PublicBaseURL       string `toml:"public_base_url"`
	PanelTrustedProxies string `toml:"panel_trusted_proxies"`
	ControlHost         string `toml:"control_host"`

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
	if filepath.Clean(path) == "/etc/opennofrp/server.toml" {
		if cfg.Server.DBPath == "" {
			cfg.Server.DBPath = "/var/lib/opennofrp/opennofrp.db"
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
	}

	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config: invalid: %w", err)
	}
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Server.MaxTCPConnections == 0 {
		cfg.Server.MaxTCPConnections = 512
	}
	if cfg.Server.TCPIdleTimeoutSeconds == 0 {
		cfg.Server.TCPIdleTimeoutSeconds = 300
	}
	if cfg.Server.BindAddr == "" {
		cfg.Server.BindAddr = "0.0.0.0"
	}
	if cfg.Server.ControlPort <= 0 {
		cfg.Server.ControlPort = 17000
	}
	if cfg.Server.PanelAddr == "" {
		cfg.Server.PanelAddr = "127.0.0.1"
	}
	if cfg.Server.PanelPort <= 0 {
		cfg.Server.PanelPort = 8080
	}
	if cfg.Server.HeartbeatTimeoutSeconds <= 0 {
		cfg.Server.HeartbeatTimeoutSeconds = 90
	}
	if cfg.Server.DBPath == "" {
		cfg.Server.DBPath = "/var/lib/opennofrp-server/opennofrp.db"
	}
	if cfg.Server.ClientBinDir == "" {
		cfg.Server.ClientBinDir = "/opt/opennofrp-server/client-bins"
	}
	if cfg.Server.TLSCertPath == "" {
		cfg.Server.TLSCertPath = "/var/lib/opennofrp-server/server.crt"
	}
	if cfg.Server.TLSKeyPath == "" {
		cfg.Server.TLSKeyPath = "/var/lib/opennofrp-server/server.key"
	}
	if cfg.Server.ACMECacheDir == "" {
		cfg.Server.ACMECacheDir = "/var/lib/opennofrp-server/acme"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
}

func validate(cfg *Config) error {
	if cfg.Server.MaxTCPConnections < 1 || cfg.Server.TCPIdleTimeoutSeconds < 1 {
		return fmt.Errorf("server TCP connection limit and idle timeout must be positive")
	}
	if cfg.Server.ControlPort <= 0 || cfg.Server.ControlPort > 65535 {
		return fmt.Errorf("server.control_port must be 1-65535, got %d", cfg.Server.ControlPort)
	}
	if cfg.Server.PanelPort <= 0 || cfg.Server.PanelPort > 65535 {
		return fmt.Errorf("server.panel_port must be 1-65535, got %d", cfg.Server.PanelPort)
	}
	if (cfg.Server.PanelTLSCert == "") != (cfg.Server.PanelTLSKey == "") {
		return fmt.Errorf("server.panel_tls_cert and server.panel_tls_key must be set together")
	}
	if cfg.Server.PublicBaseURL != "" {
		if _, err := ParsePublicBaseURL(cfg.Server.PublicBaseURL); err != nil {
			return err
		}
	}
	return nil
}

func ParsePublicBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery ||
		strings.ContainsAny(raw, "#\"'\\") {
		return nil, fmt.Errorf("server.public_base_url must be an HTTP or HTTPS origin")
	}
	u.Path = ""
	return u, nil
}

// ExampleTOML 返回一份带注释的服务端示例配置。
func ExampleTOML() string {
	return `# OpenNoFrp Server configuration
# This process NEVER touches iptables/nftables/routing/sysctls. It is a
# pure userspace TCP/UDP forwarder. See docs/01-architecture.md.

[server]
bind_addr = "0.0.0.0"
control_port = 17000

panel_addr = "127.0.0.1"
panel_port = 8080
# HTTP by default. Set both PEM paths to enable HTTPS on this listener.
# panel_tls_cert = "/etc/opennofrp-server/panel.crt"
# panel_tls_key = "/etc/opennofrp-server/panel.key"
# Allow Prometheus to scrape /metrics with "Authorization: Bearer <token>".
# Empty = /metrics requires a panel login session.
# metrics_token = "change-me"

heartbeat_timeout_seconds = 90
# Total public TCP connections, including pending backend opens.
max_tcp_connections = 512
# Close TCP forwards after this many seconds without traffic in either direction.
tcp_idle_timeout_seconds = 300
db_path = "/var/lib/opennofrp-server/opennofrp.db"
client_bin_dir = "/opt/opennofrp-server/client-bins"
# public_base_url = "https://frp.example.com"
# panel_trusted_proxies = "127.0.0.1/32,::1/128" # only with a trusted HTTPS reverse proxy
# control_host = "control.example.com" # defaults to the public_base_url host for generated configs

# ACME automatic certificates for HTTPS rules (Let's Encrypt by default).
# Certificates are only requested when acme_accept_tos = true.
# acme_email = "admin@example.com"
# acme_cache_dir = "/var/lib/opennofrp-server/acme"
# acme_directory_url = ""  # empty = Let's Encrypt production
# acme_accept_tos = false

[log]
level = "info"
# file = "/var/log/opennofrp/server.log"  # empty = stdout
`
}
