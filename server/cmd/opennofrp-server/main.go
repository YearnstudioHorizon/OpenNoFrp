// Command opennofrp-server 是 OpenNoFrp 云端 Server 的入口程序。它是一个
// 纯用户态的 TCP/UDP 转发器：从不触碰 iptables/nftables、路由表、TUN/TAP
// 设备或内核网络参数。参见 docs/01-architecture.md 和
// docs/02-risk-assessment.md。
//
// 产品化之后，一个进程同时承载了三项原本彼此独立的职责：由公网规则驱动的
// 端口监听器、Client 控制监听器，以及管理员 Web 面板。
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/net/netutil"

	"opennofrp/pkg/crypto/tlsutil"
	"opennofrp/pkg/protocol"
	"opennofrp/pkg/updater"
	"opennofrp/pkg/version"
	"opennofrp/server/internal/config"
	"opennofrp/server/internal/listener"
	"opennofrp/server/internal/panel"
	"opennofrp/server/internal/session"
	"opennofrp/server/internal/store"
)

const defaultConfigPath = "/etc/opennofrp-server/server.toml"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Println(version.String("opennofrp-server"))
			return
		case "update":
			if err := updater.SelfUpdate(context.Background(), "opennofrp-server"); err != nil {
				fmt.Fprintf(os.Stderr, "更新失败: %v\n", err)
				os.Exit(1)
			}
			return
		case "init-config":
			runInitConfig()
			return
		case "reset-captcha":
			runResetCaptcha()
			return
		}
	}
	runServer()
}

func runInitConfig() {
	path := defaultConfigPath
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "-path" && i+1 < len(os.Args) {
			path = os.Args[i+1]
			i++
		}
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "error: %s already exists, refusing to overwrite\n", path)
		os.Exit(1)
	}
	if err := os.WriteFile(path, []byte(config.ExampleTOML()), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote example config to %s -- edit it before starting the server\n", path)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func runServer() {
	var (
		configPath = defaultConfigPath
	)
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-c" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			i++
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	proxies, bad := listener.ParseTrustedProxies(cfg.Server.PanelTrustedProxies)
	if len(bad) != 0 {
		logger.Error("invalid server.panel_trusted_proxies", "entries", bad)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(cfg.Server.DBPath)
	if err != nil {
		logger.Error("failed to open store", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	if err := ensureAdminSeeded(ctx, st, cfg, logger); err != nil {
		logger.Error("failed to initialize admin account", "error", err)
		os.Exit(1)
	}

	s := &server{
		cfg:      cfg,
		logger:   logger,
		store:    st,
		limiter:  newHandshakeLimiter(),
		sessions: make(map[string]*session.Session),
	}
	s.listener = listener.NewManager(cfg.Server.BindAddr, logger, s.sessionFor)
	s.listener.MaxTCPConnections = cfg.Server.MaxTCPConnections
	s.listener.TCPIdleTimeout = time.Duration(cfg.Server.TCPIdleTimeoutSeconds) * time.Second
	s.listener.SetACME(listener.ACMEConfig{
		Email:        cfg.Server.ACMEEmail,
		CacheDir:     cfg.Server.ACMECacheDir,
		DirectoryURL: cfg.Server.ACMEDirectoryURL,
		AcceptTOS:    cfg.Server.ACMEAcceptTOS,
	})

	// 保留 SSH（及类似的主机管理）端口，确保已启用的规则永远不会与运维人员
	// 自身进入该主机的访问通道发生冲突。
	reserveHostSSHPorts(ctx, st, logger)

	// 在任何 Client 重新连接之前，就先按已存储的规则集启动公网监听器——
	// 启用规则即会将其持久化，因此端口必须在 Server 重启后依然保持开放。
	s.reconcileListeners(ctx)

	// 公网控制监听器（以 TLS 包装，支持 Certificate Pinning 证书固定）
	tlsCert, fingerprint, err := tlsutil.LoadOrCreateCert(cfg.Server.TLSCertPath, cfg.Server.TLSKeyPath, []string{cfg.Server.BindAddr})
	if err != nil {
		logger.Error("failed to load or create TLS certificate", "error", err)
		os.Exit(1)
	}
	logger.Info("server TLS certificate ready", "fingerprint", fingerprint, "cert_path", cfg.Server.TLSCertPath)

	controlAddr := net.JoinHostPort(cfg.Server.BindAddr, strconv.Itoa(cfg.Server.ControlPort))
	rawLn, err := net.Listen("tcp", controlAddr)
	if err != nil {
		logger.Error("failed to listen on control port", "addr", controlAddr, "error", err)
		os.Exit(1)
	}
	tlsConfig := tlsutil.NewServerTLSConfig(tlsCert)
	ln := tls.NewListener(netutil.LimitListener(rawLn, 512), tlsConfig)
	logger.Info("opennofrp-server listening (TLS encrypted)", "control_addr", controlAddr)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go s.acceptControlConns(ctx, ln)

	// 管理面板。
	p := panel.New(st, logger, s.onAnyRuleChanged, cfg.Server.PublicBaseURL,
		cfg.Server.ControlHost, cfg.Server.ControlPort, fingerprint, cfg.Server.ClientBinDir)
	p.TrustedProxies = proxies
	p.ClientStatus = func(clientID string) (bool, string, []string) {
		sess := s.sessionFor(clientID)
		if sess == nil {
			return false, "", nil
		}
		return true, sess.ClientVersion, sess.Capabilities
	}
	p.UpdateClient = s.updateClient
	p.RuleStats = s.listener.Stats
	p.MetricsToken = cfg.Server.MetricsToken
	p.MigrationPaths = &panel.MigrationPaths{
		ConfigFile:   configPath,
		DBPath:       cfg.Server.DBPath,
		TLSCert:      cfg.Server.TLSCertPath,
		TLSKey:       cfg.Server.TLSKeyPath,
		PanelTLSCert: cfg.Server.PanelTLSCert,
		PanelTLSKey:  cfg.Server.PanelTLSKey,
		ACMEDir:      cfg.Server.ACMECacheDir,
		DataDir:      filepath.Dir(cfg.Server.DBPath),
	}
	panelAddr := net.JoinHostPort(cfg.Server.PanelAddr, strconv.Itoa(cfg.Server.PanelPort))
	panelLn, err := net.Listen("tcp", panelAddr)
	if err != nil {
		logger.Error("failed to listen on panel port", "error", err)
		os.Exit(1)
	}
	bounded := netutil.LimitListener(panelLn, 128)
	httpSrv := &http.Server{
		Addr: panelAddr, Handler: p.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	go func() {
		<-ctx.Done()
		httpSrv.Close()
	}()

	// 定期清理过期的面板登录会话。
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			if err := st.PurgeExpiredPanelSessions(ctx); err != nil {
				logger.Warn("failed to purge expired panel sessions", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	go func() {
		var err error
		if cfg.Server.PanelTLSCert != "" && cfg.Server.PanelTLSKey != "" {
			logger.Info("admin panel serving (HTTPS)", "addr", panelAddr)
			err = httpSrv.ServeTLS(bounded, cfg.Server.PanelTLSCert, cfg.Server.PanelTLSKey)
		} else {
			logger.Info("admin panel serving", "addr", panelAddr)
			err = httpSrv.Serve(bounded)
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("panel http server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("opennofrp-server stopped")
}

type server struct {
	rulesMu       sync.Mutex // serialize listener reconciliation and snapshot publication
	clientUpdates sync.Map   // client ID -> in-flight update
	activeVPN     sync.Map   // temporary VPN ID -> active lease
	cfg           *config.Config
	logger        *slog.Logger
	store         *store.Store
	listener      *listener.Manager
	limiter       *handshakeLimiter

	mu       sync.Mutex
	sessions map[string]*session.Session // clientID -> 活跃会话
}

func (s *server) sessionFor(clientID string) *session.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[clientID]
}

func (s *server) registerSession(sess *session.Session) {
	s.mu.Lock()
	old := s.sessions[sess.ClientID]
	s.sessions[sess.ClientID] = sess
	s.mu.Unlock()
	if old != nil {
		old.Yamux.Close() // 顶替陈旧连接；其客户端会自行重试
	}
}

func (s *server) unregisterSession(sess *session.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.sessions[sess.ClientID]; ok && cur == sess {
		delete(s.sessions, sess.ClientID)
	}
}

// onAnyRuleChanged 接入面板：任何规则变更都会刷新公网监听器集合，并且
// 向每个已连接的 Client 推送一份最新快照（每个 Client 只会收到属于自己的
// 已启用规则）。
func (s *server) onAnyRuleChanged() {
	s.rulesMu.Lock()
	defer s.rulesMu.Unlock()
	ctx := context.Background()
	s.reconcileListeners(ctx)

	s.mu.Lock()
	sessions := make([]*session.Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()

	for _, sess := range sessions {
		if _, err := s.store.GetClient(ctx, sess.ClientID); err != nil {
			sess.Yamux.Close()
			continue
		}
		rules, err := s.store.ListEnabledRulesForClient(ctx, sess.ClientID)
		if err != nil {
			s.logger.Warn("failed to load rules for client", "client_id", sess.ClientID, "error", err)
			continue
		}
		if err := sess.PushRulesSnapshot(toWireRules(rules)); err != nil {
			s.logger.Warn("failed to push rules snapshot", "client_id", sess.ClientID, "error", err)
		}
	}
}

func (s *server) reconcileListeners(ctx context.Context) {
	rules, err := s.store.ListAllEnabledRules(ctx)
	if err != nil {
		s.logger.Warn("failed to list enabled rules", "error", err)
		return
	}
	desired := make([]listener.RuleView, 0, len(rules))
	for _, r := range rules {
		v := listener.RuleView{ID: uint32(r.ID), ClientID: r.ClientID, Protocol: r.Protocol, Port: r.RemotePort, PortEnd: r.RemotePortEnd}
		if r.Protocol == "http" {
			v.Name = r.Name
			v.Domains = store.SplitDomains(r.Domains)
			v.PathPrefix = store.NormalizePathPrefix(r.PathPrefix)
			v.OfflinePage = r.OfflinePage
			v.IPSources = listener.ParseIPSources(r.IPSources)
			v.TrustedProxies, _ = listener.ParseTrustedProxies(r.TrustedProxies)
			v.TLSMode = r.TLSMode
			v.TLSCert = r.TLSCert
			v.TLSKey = r.TLSKey
			v.RedirectHTTPS = r.RedirectHTTPS == "1"
			v.StripPrefix = r.StripPrefix == "1"
			v.HostRewrite = r.HostRewrite
			v.ReqHeaders = r.ReqHeaders
			v.RespHeaders = r.RespHeaders
			v.BasicAuth = r.BasicAuth
			v.IPAllow, _ = listener.ParseTrustedProxies(r.IPAllow)
			v.NotFoundPage = r.NotFoundPage
		} else if r.Protocol == "tls" {
			v.Name = r.Name
			v.Domains = store.SplitDomains(r.Domains)
		}
		// 规则级防护（所有协议通用）。
		v.Guard.Allow, _ = listener.ParseTrustedProxies(r.GuardAllow)
		v.Guard.Deny, _ = listener.ParseTrustedProxies(r.GuardDeny)
		v.Guard.MaxConnsPerIP = r.MaxConnsPerIP
		v.Guard.ConnRatePerMin = r.ConnRatePerMin
		v.Guard.BandwidthKBps = r.BandwidthKBps
		desired = append(desired, v)
	}
	s.listener.Reconcile(desired)
}

func (s *server) acceptControlConns(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.logger.Error("accept failed", "error", err)
			continue
		}
		go s.handleControlConn(conn)
	}
}

func (s *server) handleControlConn(conn net.Conn) {
	defer conn.Close()

	ip := ipFromAddr(conn.RemoteAddr())
	release, ok := s.limiter.checkAndAcquire(ip)
	if !ok {
		s.logger.Warn("control connection rejected: IP banned or concurrency limit reached", "remote", conn.RemoteAddr(), "ip", ip)
		return
	}
	defer release()

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	first, err := readControlMessage(conn)
	if err != nil {
		s.limiter.recordFailure(ip)
		s.logger.Warn("first control message read failed", "remote", conn.RemoteAddr(), "error", err)
		return
	}
	if first.Type == protocol.MsgVPNHandshake {
		s.handleVPNConnection(conn, first.raw, ip, release)
		return
	}

	// 第一条消息要么是一次性注册（此时尚无凭据），要么是常规握手。
	if first.Type == protocol.MsgRegisterRequest {
		if !s.limiter.acquireAuth() {
			return
		}
		_, err := s.handleRegister(conn, first, conn.RemoteAddr())
		s.limiter.releaseAuth()
		if err != nil {
			s.limiter.recordFailure(ip)
			return
		}
		// 注册完成后，客户端会在同一条 TCP 连接上以第二条消息发送真正的握手。
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		second, err := readControlMessage(conn)
		if err != nil || second.Type != protocol.MsgHandshakeRequest {
			s.limiter.recordFailure(ip)
			s.logger.Warn("expected handshake after registration", "error", err)
			return
		}
		first = second
	}

	if first.Type != protocol.MsgHandshakeRequest {
		s.limiter.recordFailure(ip)
		s.logger.Warn("first message is neither register nor handshake", "type", first.Type)
		return
	}

	var req protocol.HandshakeRequest
	if err := json.Unmarshal(first.raw, &req); err != nil {
		s.limiter.recordFailure(ip)
		return
	}
	if !s.limiter.acquireAuth() {
		return
	}
	authErr := s.validateHandshake(req)
	s.limiter.releaseAuth()
	if err := authErr; err != nil {
		s.logger.Warn("handshake rejected", "remote", conn.RemoteAddr(), "error", err)
		banned := s.limiter.recordFailure(ip)
		if banned {
			s.logger.Warn("ip banned from control port due to repeated handshake failures", "ip", ip)
		}
		message := "authentication unavailable"
		if errors.Is(err, errClientCredentials) || errors.Is(err, errControlProtocol) {
			message = err.Error()
		}
		protocol.WriteJSONMessage(conn, protocol.HandshakeResponse{
			Type: protocol.MsgHandshakeResponse, OK: false, Error: message,
		})
		return
	}
	s.limiter.recordSuccess(ip)

	ym, err := func() (*yamux.Session, error) {
		if err := protocol.WriteJSONMessage(conn, protocol.HandshakeResponse{
			Type: protocol.MsgHandshakeResponse, OK: true,
			ProtocolVersion: protocol.ProtocolVersion, ServerVersion: version.Version,
		}); err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Time{})
		return yamux.Server(conn, protocol.TunnelYamuxConfig())
	}()
	if err != nil {
		s.logger.Error("failed to start yamux server session", "error", err)
		return
	}
	defer ym.Close()

	// Client 在 yamux 启动后会立即打开其控制流；在此处接受它（这是唯一一条
	// 由 Client 打开的流）。
	handshakeCtx, cancelHandshake := context.WithTimeout(context.Background(), 15*time.Second)
	ctrlStream, err := ym.AcceptStreamWithContext(handshakeCtx)
	cancelHandshake()
	if err != nil {
		return
	}
	release()

	sess := session.New(newSessionID(), req.ClientID, ym, s.logger, ctrlStream)
	sess.ClientVersion = req.ClientVersion
	sess.Capabilities = append([]string(nil), req.Capabilities...)
	if !sess.HasCapability(protocol.CapDialAck) {
		s.logger.Warn("client does not support dial_ack; HTTP/TLS rules for it will return the unavailable page until it is upgraded",
			"client_id", req.ClientID, "client_version", req.ClientVersion)
	}
	s.rulesMu.Lock()
	if _, err := s.store.GetClient(context.Background(), req.ClientID); err != nil {
		s.rulesMu.Unlock()
		return
	}
	s.registerSession(sess)
	defer s.unregisterSession(sess)

	// 握手成功后立即记录该活跃客户端，使面板能马上显示其在线，之后每次心跳
	// 时再次记录。
	_ = s.store.TouchClient(context.Background(), req.ClientID, conn.RemoteAddr().String())

	// 记录活动情况，并持续监视控制流上的心跳。
	go s.watchControlStream(sess, ym, ctrlStream)

	// 推送初始快照。
	if rules, err := s.store.ListEnabledRulesForClient(context.Background(), req.ClientID); err == nil {
		if err := sess.PushRulesSnapshot(toWireRules(rules)); err != nil {
			s.logger.Warn("initial rules snapshot push failed", "error", err)
		}
	}

	s.rulesMu.Unlock()
	s.logger.Info("client session established", "client_id", req.ClientID, "remote", conn.RemoteAddr())

	// The peer is only allowed to initiate its control stream. End the session
	// on a protocol violation so neither that stream nor any queued streams leak.
	if extra, err := ym.AcceptStream(); err == nil {
		extra.Close()
	}

}

// watchControlStream 读取控制流上 client->server 方向的心跳帧，并在心跳
// 停止到达时使会话超时。
func (s *server) watchControlStream(sess *session.Session, ym *yamux.Session, ctrl net.Conn) {
	timeout := time.Duration(s.cfg.Server.HeartbeatTimeoutSeconds) * time.Second
	for {
		var msg struct {
			Type      protocol.ControlMessageType `json:"type"`
			RequestID string                      `json:"request_id"`
			Status    string                      `json:"status"`
			Version   string                      `json:"version"`
			Error     string                      `json:"error"`
		}
		ctrl.SetReadDeadline(time.Now().Add(timeout))
		if err := protocol.ReadJSONMessage(ctrl, &msg); err != nil {
			ym.Close()
			return
		}
		if msg.Type == protocol.MsgHeartbeat {
			sess.Touch()
			_ = s.store.TouchClient(context.Background(), sess.ClientID, ctrl.RemoteAddr().String())
		}
		if msg.Type == protocol.MsgClientUpdateResult {
			sess.ReceiveUpdateResult(protocol.ClientUpdateResult{Type: msg.Type, RequestID: msg.RequestID, Status: msg.Status, Version: msg.Version, Error: msg.Error})
			if msg.Status == "restarting" {
				_ = sess.AcknowledgeUpdate(msg.RequestID)
			}
		}
	}
}

var (
	errClientCredentials = errors.New("invalid client credentials")
	errControlProtocol   = errors.New("incompatible control protocol")
)

func (s *server) validateHandshake(req protocol.HandshakeRequest) error {
	if req.ProtocolVersion != protocol.ProtocolVersion {
		return errControlProtocol
	}
	if len(req.ClientID) == 0 || len(req.ClientSecret) == 0 || len(req.ClientSecret) > 72 {
		return fmt.Errorf("missing client credentials")
	}
	// 客户端 ID 格式轻量校验（16 位 16 进制字符），防畸形探测输入与无谓计算
	if len(req.ClientID) != 16 {
		return fmt.Errorf("invalid client id format")
	}
	for _, c := range req.ClientID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("invalid client id format")
		}
	}
	ok, err := s.store.VerifyClient(context.Background(), req.ClientID, req.ClientSecret)
	if err != nil {
		return fmt.Errorf("verify client: %w", err)
	}
	if !ok {
		return errClientCredentials
	}
	return nil
}

// handleRegister 校验一次性令牌，签发一个新的永久 Client 身份并将其持久化，
// 随后消费该令牌并写回响应。
func (s *server) handleRegister(conn net.Conn, first *controlMsg, remote net.Addr) (string, error) {
	var req protocol.RegisterRequest
	if err := json.Unmarshal(first.raw, &req); err != nil {
		return "", err
	}
	if req.ProtocolVersion != protocol.ProtocolVersion {
		protocol.WriteJSONMessage(conn, protocol.RegisterResponse{Type: protocol.MsgRegisterResponse, Error: errControlProtocol.Error()})
		return "", errControlProtocol
	}

	name := "unnamed"
	if req.Hostname != "" {
		name = req.Hostname
	}
	if len(name) > 255 {
		name = name[:255]
	}
	clientID, clientSecret, err := s.store.RegisterClient(context.Background(), req.RegisterToken, name)
	if err != nil {
		protocol.WriteJSONMessage(conn, protocol.RegisterResponse{Type: protocol.MsgRegisterResponse, Error: "registration rejected"})
		return "", err
	}
	if err := protocol.WriteJSONMessage(conn, protocol.RegisterResponse{
		Type: protocol.MsgRegisterResponse, OK: true, ClientID: clientID, ClientSecret: clientSecret,
	}); err != nil {
		return "", err
	}
	s.logger.Info("registered new client", "client_id", clientID, "remote", remote)
	return clientID, nil
}

// --- 辅助函数 ---------------------------------------------------------------

type controlMsg struct {
	Type protocol.ControlMessageType
	raw  []byte
}

// readControlMessage 读取一条带长度前缀的 JSON 控制消息（即在 yamux 分帧
// 接管之前的握手阶段消息）。
func readControlMessage(conn net.Conn) (*controlMsg, error) {
	// 分发时只需要其 Type 字段；采用两步法解析到通用结构：先读长度前缀，
	// 再读载荷，最后解析。
	lenHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenHdr); err != nil {
		return nil, err
	}
	n := int(lenHdr[0])<<24 | int(lenHdr[1])<<16 | int(lenHdr[2])<<8 | int(lenHdr[3])
	if n <= 0 || n > 1<<20 {
		return nil, fmt.Errorf("bad control message length %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	var env struct {
		Type protocol.ControlMessageType `json:"type"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, err
	}
	return &controlMsg{Type: env.Type, raw: payload}, nil
}

func newSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hostFromAddr(bindAddr string) string {
	if bindAddr == "" || bindAddr == "0.0.0.0" {
		return ""
	}
	return bindAddr
}

// reserveHostSSHPorts 将 OpenSSH 监听的端口加入保留集合，确保面板创建的
// 任何规则都不会与运维人员自身对服务器的管理访问发生冲突。
func reserveHostSSHPorts(ctx context.Context, st *store.Store, logger *slog.Logger) {
	ports := map[uint16]string{22: "ssh(default)"}
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		re := regexp.MustCompile(`^[Pp]ort\s+(\d+)`)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if m := re.FindStringSubmatch(line); m != nil {
				if p, err := strconv.Atoi(m[1]); err == nil && p > 0 && p <= 65535 {
					ports[uint16(p)] = "ssh"
				}
			}
		}
	}
	for port, reason := range ports {
		if err := st.AddReservedPort(ctx, port, reason); err != nil {
			logger.Warn("failed to reserve ssh port", "port", port, "error", err)
		}
	}
}

func toWireRules(rules []store.Rule) []protocol.Rule {
	out := make([]protocol.Rule, 0, len(rules))
	for _, r := range rules {
		out = append(out, protocol.Rule{
			ID: r.ID, Name: r.Name, Protocol: protocol.RuleProtocol(r.Protocol),
			LocalIP: r.LocalIP, LocalPort: r.LocalPort, RemotePort: r.RemotePort,
			PreserveSourceIP: r.PreserveSourceIP,
			ProxyProtocol:    r.ProxyProtocol,
			RemotePortEnd:    r.RemotePortEnd,
		})
	}
	return out
}

// ensureAdminSeeded 在首次启动时创建初始管理员账号，并打印/写出生成的
// 密码。已存在的账号不受影响。
func ensureAdminSeeded(ctx context.Context, st *store.Store, cfg *config.Config, logger *slog.Logger) error {
	exists, err := st.AdminExists(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	pwBytes := make([]byte, 9)
	rand.Read(pwBytes)
	initialPassword := hex.EncodeToString(pwBytes) // 18 个字符的十六进制串
	if err := st.CreateAdmin(ctx, "admin", initialPassword); err != nil {
		return err
	}
	fmt.Printf("\n=== opennofrp: initial admin account ===\nusername: admin\npassword: %s\nchange it in the panel after first login\n\n", initialPassword)
	pwFile := strings.TrimSuffix(cfg.Server.DBPath, ".db") + "-initial-password.txt"
	if err := os.WriteFile(pwFile, []byte("username=admin\npassword="+initialPassword+"\n"), 0o600); err == nil {
		logger.Info("initial admin password written", "path", pwFile)
	}
	return nil
}

// handshakeLimiter 负责控制端口的连接级限速、单 IP 并发控制与防爆破 CPU DoS 封禁 (MEDIUM-2 防御)
type handshakeLimiter struct {
	mu            sync.Mutex
	inFlight      int
	authSlots     chan struct{}
	nextSweep     time.Time
	inFlightPerIP map[string]int       // ip -> 当前并发握手数
	failuresPerIP map[string]failInfo  // ip -> 连续失败记录
	bannedUntil   map[string]time.Time // ip -> 封禁截止时间
}

type failInfo struct {
	count     int
	firstFail time.Time
}

func newHandshakeLimiter() *handshakeLimiter {
	return &handshakeLimiter{
		inFlightPerIP: make(map[string]int),
		authSlots:     make(chan struct{}, 4),
		failuresPerIP: make(map[string]failInfo),
		bannedUntil:   make(map[string]time.Time),
	}
}

const (
	maxInFlightPerIP = 3               // 单 IP 最大并发握手连接数
	maxFailures      = 5               // 统计窗口内最大允许失败次数
	failWindow       = 1 * time.Minute // 失败统计窗口
	banDuration      = 5 * time.Minute // 触发封禁后的时长
)

func (hl *handshakeLimiter) acquireAuth() bool {
	select {
	case hl.authSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (hl *handshakeLimiter) releaseAuth() { <-hl.authSlots }

func (hl *handshakeLimiter) checkAndAcquire(ip string) (func(), bool) {
	hl.mu.Lock()
	defer hl.mu.Unlock()

	now := time.Now()
	if now.After(hl.nextSweep) {
		for source, info := range hl.failuresPerIP {
			if now.Sub(info.firstFail) > failWindow {
				delete(hl.failuresPerIP, source)
			}
		}
		for source, until := range hl.bannedUntil {
			if now.After(until) {
				delete(hl.bannedUntil, source)
			}
		}
		hl.nextSweep = now.Add(time.Minute)
	}
	// 清理过期的封禁记录
	if until, exists := hl.bannedUntil[ip]; exists {
		if now.After(until) {
			delete(hl.bannedUntil, ip)
		} else {
			return nil, false // 仍处于封禁期，立即拒绝，不进入 bcrypt
		}
	}

	// 检查单 IP 并发上限，防止并发连接打满 CPU
	if hl.inFlight >= 128 || hl.inFlightPerIP[ip] >= maxInFlightPerIP {
		return nil, false
	}

	hl.inFlight++
	hl.inFlightPerIP[ip]++
	var once sync.Once
	release := func() {
		once.Do(func() {
			hl.mu.Lock()
			hl.inFlight--
			hl.inFlightPerIP[ip]--
			if hl.inFlightPerIP[ip] <= 0 {
				delete(hl.inFlightPerIP, ip)
			}
			hl.mu.Unlock()
		})
	}
	return release, true
}

func (hl *handshakeLimiter) recordFailure(ip string) bool {
	hl.mu.Lock()
	defer hl.mu.Unlock()

	now := time.Now()
	if len(hl.failuresPerIP)+len(hl.bannedUntil) >= 16384 {
		if _, tracked := hl.failuresPerIP[ip]; !tracked {
			return false
		}
	}
	info, exists := hl.failuresPerIP[ip]
	if !exists || now.Sub(info.firstFail) > failWindow {
		info = failInfo{count: 1, firstFail: now}
	} else {
		info.count++
	}

	if info.count >= maxFailures {
		hl.bannedUntil[ip] = now.Add(banDuration)
		delete(hl.failuresPerIP, ip)
		return true
	}

	hl.failuresPerIP[ip] = info
	return false
}

func (hl *handshakeLimiter) recordSuccess(ip string) {
	hl.mu.Lock()
	defer hl.mu.Unlock()
	delete(hl.failuresPerIP, ip)
	delete(hl.bannedUntil, ip)
}

func ipFromAddr(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
