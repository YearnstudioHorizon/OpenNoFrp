// Package controlconn manages the Client's connection to the Server: first
// boot registration (one-time token -> permanent credentials), every-later
// handshake (client_id/client_secret), periodic heartbeats, automatic
// reconnection with exponential backoff, rules-snapshot reception, and
// accepting the yamux streams the Server opens for each forwarded connection.
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

// StreamHandler is called for every new yamux stream the Server opens,
// after its StreamMetadata header has already been read. The handler is
// responsible for connecting to the right local service (with or without
// source-IP spoofing, per the matching rule's settings) and relaying bytes.
type StreamHandler func(ctx context.Context, meta protocol.StreamMetadata, stream net.Conn)

// Client manages one logical connection to one OpenNoFrp Server, including
// automatic reconnection.
type Client struct {
	Cfg    *config.Config
	Logger *slog.Logger
	// OnRules is called every time the Server pushes a fresh rules
	// snapshot (once right after handshake, then on every panel-side
	// change). Must be safe to call again after any disconnect -- each
	// reconnect yields exactly one fresh snapshot.
	OnRules func(rules []protocol.Rule)
	// OnCredentials is called once when this machine completes its
	// one-time registration and receives permanent credentials; the
	// caller should persist them (see config.SaveCredentials).
	OnCredentials func(c config.Credentials)
	Handler       StreamHandler

	seq                     uint64
	lastObservedFingerprint string
}

// Run connects to the Server and services the connection until ctx is
// cancelled, automatically reconnecting with exponential backoff on
// failure. This function only returns when ctx is cancelled.
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

	// One shared, full-duplex control stream carries heartbeats
	// (client->server) and rules snapshots (server->client) in opposite
	// directions. The two directions are independent byte streams over the
	// same underlying yamux stream, so there is no interleaving hazard.
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

// handshakeOrRegister speaks the control-plane prelude on the fresh TCP
// conn before yamux starts. If this machine has no persisted credentials
// yet, it performs the one-time registration exchange (register token ->
// permanent client_id/client_secret), persists them via OnCredentials, and
// retries the handshake with them immediately.
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

// rulesLoop reads server->client RulesSnapshot messages arriving on the
// shared control stream (opposite direction from our heartbeat writes).
func (c *Client) rulesLoop(ctx context.Context, ctrlStream net.Conn) {
	for {
		// RulesSnapshot and HeartbeatAck share the control stream with
		// our heartbeat writes, but in the opposite direction. Each
		// length-prefixed frame decodes into this envelope.
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
			// informational only
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
