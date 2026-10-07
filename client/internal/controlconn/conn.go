// Package controlconn 管理 Client 到 Server 的连接：首次启动注册（一次性
// token -> 永久凭据）、此后每次连接的握手（client_id/client_secret）、周期性
// 心跳、带指数退避的自动重连、接收规则快照，以及接受 Server 为每个被转发
// 连接打开的 yamux 流。
package controlconn

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"opennofrp/client/internal/config"
	"opennofrp/pkg/crypto/tlsutil"
	"opennofrp/pkg/protocol"
	"opennofrp/pkg/version"
)

// StreamHandler 会在 Server 打开每个新的 yamux 流、且其 StreamMetadata 头部
// 已被读取之后被调用。处理函数负责连接到正确的本地服务（根据匹配规则的设置
// 决定是否伪造源 IP）并中继字节数据。
type StreamHandler func(ctx context.Context, meta protocol.StreamMetadata, stream net.Conn)

// ClientCapabilities 是本版本 Client 在握手时上报给 Server 的可选能力列表。
// 每实现一项新能力（SNI 提示、Proxy Protocol、UDP 伪装、端口段等）就在此追加
// 对应的 protocol.Cap* 常量。
var ClientCapabilities = []string{
	protocol.CapDialAck,
	protocol.CapSNIHint,
	protocol.CapProxyProtocol,
}

// Client 管理到一个 OpenNoFrp Server 的一条逻辑连接，包括自动重连。
type Client struct {
	Cfg    *config.Config
	Logger *slog.Logger
	// OnRules 在 Server 每次推送新的规则快照时被调用（握手后立即调用一次，
	// 之后面板侧每次变更时调用）。必须保证在任意断线后可安全地再次调用 ——
	// 每次重连都会恰好产生一份新的快照。
	OnRules func(rules []protocol.Rule)
	// OnCredentials 在本机完成一次性注册并获得永久凭据时被调用一次；
	// 调用方应将其持久化（参见 config.SaveCredentials）。
	OnCredentials func(c config.Credentials)
	Handler       StreamHandler

	seq                     uint64
	lastObservedFingerprint string
}

// Run 连接到 Server 并持续服务该连接直到 ctx 被取消，失败时以指数退避
// 自动重连。本函数仅在 ctx 被取消时返回。
func (c *Client) Run(ctx context.Context) {
	backoff := time.Duration(c.Cfg.Server.ReconnectMinSeconds) * time.Second
	maxBackoff := time.Duration(c.Cfg.Server.ReconnectMaxSeconds) * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.Logger.Warn("control connection failed, will retry", "error", err, "retry_in", backoff)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", c.Cfg.Server.Addr, c.Cfg.Server.Port)
	c.Logger.Info("connecting to server (TLS encrypted)", "addr", addr)

	configPath := os.Getenv("OPENNOFRP_CLIENT_CONFIG")
	if configPath == "" {
		configPath = "/etc/opennofrp/client.toml"
	}
	credsPath := config.CredentialsPath(configPath)
	creds, _ := config.LoadCredentials(credsPath)

	expectedFP := c.Cfg.Server.Fingerprint
	if expectedFP == "" && creds != nil && creds.Fingerprint != "" {
		expectedFP = creds.Fingerprint
	}

	onFirstSeen := func(fp string) error {
		c.lastObservedFingerprint = fp
		c.Logger.Warn("首次连接服务端，已通过自签名证书建立加密信道 (TOFU)", "fingerprint", fp)
		return nil
	}

	tlsConfig := tlsutil.NewClientTLSConfig(expectedFP, onFirstSeen)

	var d net.Dialer
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("controlconn: dial %s: %w", addr, err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("controlconn: TLS handshake with %s failed: %w", addr, err)
	}
	conn := net.Conn(tlsConn)

	if err := c.handshakeOrRegister(conn); err != nil {
		return err
	}

	session, err := yamux.Client(conn, yamux.DefaultConfig())
	if err != nil {
		return fmt.Errorf("controlconn: start yamux session: %w", err)
	}
	defer session.Close()

	// 一条共享的全双工控制流以相反方向承载心跳（client->server）和规则
	// 快照（server->client）。两个方向是同一底层 yamux 流上相互独立的
	// 字节流，因此不存在交错写入的风险。
	ctrlStream, err := session.Open()
	if err != nil {
		return fmt.Errorf("controlconn: open control stream: %w", err)
	}
	defer ctrlStream.Close()

	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	defer cancelHeartbeat()
	go c.heartbeatLoop(heartbeatCtx, ctrlStream)
	go c.rulesLoop(ctx, ctrlStream)

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			return fmt.Errorf("controlconn: session ended: %w", err)
		}
		go c.serveStream(ctx, stream)
	}
}

// handshakeOrRegister 在 yamux 启动之前，于新建的 TCP 连接上完成控制面的
// 前导交互。如果本机尚无持久化的凭据，它会执行一次性注册交换（注册 token ->
// 永久 client_id/client_secret），通过 OnCredentials 将其持久化，并立即使用
// 这些凭据重新进行握手。
func (c *Client) handshakeOrRegister(conn net.Conn) error {
	configPath := os.Getenv("OPENNOFRP_CLIENT_CONFIG")
	if configPath == "" {
		configPath = "/etc/opennofrp/client.toml"
	}
	credsPath := config.CredentialsPath(configPath)

	creds, err := config.LoadCredentials(credsPath)
	if err != nil {
		return err
	}

	if creds == nil {
		if c.Cfg.Server.Token == "" {
			return fmt.Errorf("controlconn: no credentials at %s and no server.token for first-time registration; generate a registration token in the panel and put it in client.toml", credsPath)
		}
		c.Logger.Info("no credentials found, performing first-time registration", "credentials_path", credsPath)

		hostname, _ := os.Hostname()
		req := protocol.RegisterRequest{
			Type:            protocol.MsgRegisterRequest,
			ProtocolVersion: protocol.ProtocolVersion,
			RegisterToken:   c.Cfg.Server.Token,
			ClientVersion:   version.Version,
			Hostname:        hostname,
		}
		if err := protocol.WriteJSONMessage(conn, req); err != nil {
			return fmt.Errorf("controlconn: send register request: %w", err)
		}
		var rresp protocol.RegisterResponse
		if err := protocol.ReadJSONMessage(conn, &rresp); err != nil {
			return fmt.Errorf("controlconn: read register response: %w", err)
		}
		if !rresp.OK {
			return fmt.Errorf("controlconn: registration rejected: %s", rresp.Error)
		}
		newCreds := config.Credentials{
			ClientID:     rresp.ClientID,
			ClientSecret: rresp.ClientSecret,
			Fingerprint:  c.lastObservedFingerprint,
		}
		if err := config.SaveCredentials(credsPath, newCreds); err != nil {
			return err
		}
		if c.OnCredentials != nil {
			c.OnCredentials(newCreds)
		}
		c.Logger.Info("registered with server, permanent credentials saved", "client_id", newCreds.ClientID, "path", credsPath)
		creds = &newCreds
	}
	req := protocol.HandshakeRequest{
		Type:            protocol.MsgHandshakeRequest,
		ProtocolVersion: protocol.ProtocolVersion,
		ClientID:        creds.ClientID,
		ClientSecret:    creds.ClientSecret,
		ClientVersion:   version.Version,
		Capabilities:    ClientCapabilities,
	}
	if err := protocol.WriteJSONMessage(conn, req); err != nil {
		return fmt.Errorf("controlconn: send handshake: %w", err)
	}
	var resp protocol.HandshakeResponse
	if err := protocol.ReadJSONMessage(conn, &resp); err != nil {
		return fmt.Errorf("controlconn: read handshake response: %w", err)
	}
	if !resp.OK {
		if strings.Contains(resp.Error, "invalid client credentials") {
			// 本地凭据已被服务端吊销或在服务端不存在，自动清理旧凭据以便支持重新注册
			c.Logger.Warn("本地凭据已被服务端拒绝，自动清除过期凭据以支持重新注册", "path", credsPath)
			_ = os.Remove(credsPath)
		}
		return fmt.Errorf("controlconn: server rejected handshake: %s", resp.Error)
	}
	c.Logger.Info("handshake accepted", "server_version", resp.ServerVersion)
	return nil
}

// rulesLoop 读取到达共享控制流上的 server->client RulesSnapshot 消息
// （与我们写心跳的方向相反）。
func (c *Client) rulesLoop(ctx context.Context, ctrlStream net.Conn) {
	for {
		// RulesSnapshot 和 HeartbeatAck 与我们的心跳写入共享控制流，但方向
		// 相反。每个带长度前缀的帧都会解码到这个信封结构中。
		var env struct {
			Type  protocol.ControlMessageType `json:"type"`
			Rules []protocol.Rule             `json:"rules"`
		}
		if err := protocol.ReadJSONMessage(ctrlStream, &env); err != nil {
			if ctx.Err() == nil {
				c.Logger.Warn("rules stream read failed", "error", err)
			}
			return
		}
		switch env.Type {
		case protocol.MsgRulesSnapshot:
			if c.OnRules != nil {
				c.OnRules(env.Rules)
			}
		case protocol.MsgHeartbeatAck:
			// 仅供参考，无需处理
		default:
			c.Logger.Debug("unexpected message on control stream", "type", env.Type)
		}
	}
}

func (c *Client) serveStream(ctx context.Context, stream net.Conn) {
	defer stream.Close()

	meta, err := protocol.ReadStreamMetadata(stream)
	if err != nil {
		c.Logger.Error("failed to read stream metadata", "error", err)
		return
	}

	if c.Handler != nil {
		c.Handler(ctx, meta, stream)
	}
}

func (c *Client) heartbeatLoop(ctx context.Context, ctrlStream net.Conn) {
	interval := time.Duration(c.Cfg.Server.HeartbeatIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			seq := atomic.AddUint64(&c.seq, 1)
			msg := protocol.HeartbeatMessage{
				Type:         protocol.MsgHeartbeat,
				SequenceNum:  seq,
				UnixTimeNano: time.Now().UnixNano(),
			}
			if err := protocol.WriteJSONMessage(ctrlStream, msg); err != nil {
				c.Logger.Warn("heartbeat send failed", "error", err)
				return
			}
		}
	}
}
