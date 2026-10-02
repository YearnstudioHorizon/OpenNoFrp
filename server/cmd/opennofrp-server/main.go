// Command opennofrp-server is the entry point for the OpenNoFrp cloud
// Server. It is a pure userspace TCP/UDP forwarder: it never touches
// iptables/nftables, routing tables, TUN/TAP devices, or kernel network
// parameters. See docs/01-architecture.md and docs/02-risk-assessment.md.
//
// Post-productization, one process hosts three things that used to be
// separate concerns: the public-rule-driven port listeners, the Client
// control listener, and the admin web panel.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"

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

const defaultConfigPath = "/etc/opennofrp/server.toml"

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
		sessions: make(map[string]*session.Session),
	}
	s.listener = listener.NewManager(cfg.Server.BindAddr, logger, s.sessionFor)

	// Reserve SSH (and similar host-management) ports so an enabled rule
	// can never collide with the operator's own access path into the box.
	reserveHostSSHPorts(ctx, st, logger)

	// Bring public listeners up to match the stored rule set before any
	// Client has even reconnected -- enabling a rule persists it, so the
	// port must stay open across Server restarts.
	s.reconcileListeners(ctx)

	// Public control listener (wrapped in TLS with Certificate Pinning support)
	tlsCert, fingerprint, err := tlsutil.LoadOrCreateCert(cfg.Server.TLSCertPath, cfg.Server.TLSKeyPath, []string{cfg.Server.BindAddr})
	if err != nil {
		logger.Error("failed to load or create TLS certificate", "error", err)
		os.Exit(1)
	}
	logger.Info("server TLS certificate ready", "fingerprint", fingerprint, "cert_path", cfg.Server.TLSCertPath)

	controlAddr := fmt.Sprintf("%s:%d", cfg.Server.BindAddr, cfg.Server.ControlPort)
	rawLn, err := net.Listen("tcp", controlAddr)
	if err != nil {
		logger.Error("failed to listen on control port", "addr", controlAddr, "error", err)
		os.Exit(1)
	}
	tlsConfig := tlsutil.NewServerTLSConfig(tlsCert)
	ln := tls.NewListener(rawLn, tlsConfig)
	logger.Info("opennofrp-server listening (TLS encrypted)", "control_addr", controlAddr)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go s.acceptControlConns(ctx, ln)

	// Admin panel.
	p := panel.New(st, logger, s.onAnyRuleChanged, cfg.Server.PublicBaseURL,
		hostFromAddr(cfg.Server.BindAddr), cfg.Server.ControlPort, fingerprint, cfg.Server.ClientBinDir)
	panelAddr := fmt.Sprintf("%s:%d", cfg.Server.PanelAddr, cfg.Server.PanelPort)
	httpSrv := &http.Server{Addr: panelAddr, Handler: p.Handler()}
	go func() {
		<-ctx.Done()
		httpSrv.Shutdown(context.Background())
	}()
	go func() {
		logger.Info("admin panel serving", "addr", panelAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("panel http server failed", "error", err)
		}
	}()

	<-ctx.Done()
	logger.Info("opennofrp-server stopped")
}

type server struct {
	cfg      *config.Config
	logger   *slog.Logger
	store    *store.Store
	listener *listener.Manager

	mu       sync.Mutex
	sessions map[string]*session.Session // clientID -> live session
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
		old.Yamux.Close() // displace the stale connection; its client will retry
	}
}

func (s *server) unregisterSession(sess *session.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.sessions[sess.ClientID]; ok && cur == sess {
		delete(s.sessions, sess.ClientID)
	}
}

// onAnyRuleChanged is wired into the panel: any rule mutation refreshes the
// public listener set AND pushes a fresh snapshot to every connected
// Client (each Client receives only its own enabled rules).
func (s *server) onAnyRuleChanged() {
	ctx := context.Background()
	s.reconcileListeners(ctx)

	s.mu.Lock()
	sessions := make([]*session.Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()

	for _, sess := range sessions {
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
		desired = append(desired, listener.RuleView{ID: uint32(r.ID), ClientID: r.ClientID, Protocol: r.Protocol, Port: r.RemotePort})
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

	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	first, err := readControlMessage(conn)
	if err != nil {
		s.logger.Warn("first control message read failed", "remote", conn.RemoteAddr(), "error", err)
		return
	}

	// First message is either a one-time registration (no credentials yet)
	// or the normal handshake.
	if first.Type == protocol.MsgRegisterRequest {
		if _, err := s.handleRegister(conn, first, conn.RemoteAddr()); err != nil {
			return // handleRegister already wrote the error response
		}
		// After registration the client sends the real handshake on the same
		// TCP connection, in a second message.
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		second, err := readControlMessage(conn)
		if err != nil || second.Type != protocol.MsgHandshakeRequest {
			s.logger.Warn("expected handshake after registration", "error", err)
			return
		}
		first = second
	}
	conn.SetReadDeadline(time.Time{})

	if first.Type != protocol.MsgHandshakeRequest {
		s.logger.Warn("first message is neither register nor handshake", "type", first.Type)
		return
	}

	var req protocol.HandshakeRequest
	if err := json.Unmarshal(first.raw, &req); err != nil {
		return
	}
	if err := s.validateHandshake(req); err != nil {
		s.logger.Warn("handshake rejected", "remote", conn.RemoteAddr(), "error", err)
		protocol.WriteJSONMessage(conn, protocol.HandshakeResponse{
			Type: protocol.MsgHandshakeResponse, OK: false, Error: err.Error(),
		})
		return
	}

	ym, err := func() (*yamux.Session, error) {
		if err := protocol.WriteJSONMessage(conn, protocol.HandshakeResponse{
			Type: protocol.MsgHandshakeResponse, OK: true,
			ProtocolVersion: protocol.ProtocolVersion, ServerVersion: version.Version,
		}); err != nil {
			return nil, err
		}
		return yamux.Server(conn, yamux.DefaultConfig())
	}()
	if err != nil {
		s.logger.Error("failed to start yamux server session", "error", err)
		return
	}
	defer ym.Close()

	// The Client opens its control stream immediately after yamux starts;
	// accept it here (this is the only Client-opened stream).
	ctrlStream, err := ym.AcceptStream()
	if err != nil {
		return
	}

	sess := session.New(newSessionID(), req.ClientID, ym, s.logger, ctrlStream)
	s.registerSession(sess)
	defer s.unregisterSession(sess)

	// Record the live client immediately (handshake success) so the panel
	// shows it online right away, then again on every heartbeat.
	_ = s.store.TouchClient(context.Background(), req.ClientID, conn.RemoteAddr().String())

	// Record activity + keep watching heartbeats on the control stream.
	go s.watchControlStream(sess, ym, ctrlStream)

	// Push the initial snapshot.
	if rules, err := s.store.ListEnabledRulesForClient(context.Background(), req.ClientID); err == nil {
		if err := sess.PushRulesSnapshot(toWireRules(rules)); err != nil {
			s.logger.Warn("initial rules snapshot push failed", "error", err)
		}
	}

	s.logger.Info("client session established", "client_id", req.ClientID, "remote", conn.RemoteAddr())

	// The Client accepts server-opened streams; the Server opens those
	// per-public-connection. There is nothing more to read here -- block
	// until the session ends so handleControlConn's deferred cleanup runs.
	for {
		// The Client does not open extra streams; when it does (or when
		// the session dies) AcceptStream returns/errors, at which point
		// deferred cleanup runs. Per-connection streams are opened BY
		// the server (listener path) instead.
		if _, err := ym.AcceptStream(); err != nil {
			return
		}
	}
}

// watchControlStream reads client->server heartbeat frames on the control
// stream and times the session out when they stop arriving.
func (s *server) watchControlStream(sess *session.Session, ym *yamux.Session, ctrl net.Conn) {
	timeout := time.Duration(s.cfg.Server.HeartbeatTimeoutSeconds) * time.Second
	for {
		var msg struct {
			Type protocol.ControlMessageType `json:"type"`
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
	}
}

func (s *server) validateHandshake(req protocol.HandshakeRequest) error {
	if req.ProtocolVersion != protocol.ProtocolVersion {
		return fmt.Errorf("protocol version mismatch: client=%d server=%d", req.ProtocolVersion, protocol.ProtocolVersion)
	}
	ok, err := s.store.VerifyClient(context.Background(), req.ClientID, req.ClientSecret)
	if err != nil {
		return fmt.Errorf("verify client: %w", err)
	}
	if !ok {
		return fmt.Errorf("invalid client credentials")
	}
	return nil
}

// handleRegister validates a one-time token, mints a new permanent Client
// identity, persists it, consumes the token, and writes the response.
func (s *server) handleRegister(conn net.Conn, first *controlMsg, remote net.Addr) (string, error) {
	var req protocol.RegisterRequest
	if err := json.Unmarshal(first.raw, &req); err != nil {
		return "", err
	}
	name := "unnamed"
	if req.Hostname != "" {
		name = req.Hostname
	}
	// Consume token BEFORE minting user to prevent TOCTOU replay: token is
	// tied to this token string, and CreateClient needs a name anyway; the
	// name for the client row we use the register-time label fetched
	// post-consume. Simpler order: mint client, then consume token by
	// verified-once semantics... but consuming second would leak a client row
	// on bad token. Consume first: the token row's label gives us the name.
	// We can't consume without a client id... so: validate token exists & is
	// fresh via a read, mint client, then atomic consume marking consumed_by.
	// To keep it simple and correct, we consume with a placeholder client id
	// of "" then update -- not supported. Instead do: consume-with-id in one
	// tx: first CreateClient, then ConsumeRegisterToken; if consume fails we
	// delete the just-created client row.
	clientID, clientSecret, err := s.store.CreateClient(context.Background(), name)
	if err != nil {
		protocol.WriteJSONMessage(conn, protocol.RegisterResponse{Type: protocol.MsgRegisterResponse, OK: false, Error: err.Error()})
		return "", err
	}
	label, err := s.store.ConsumeRegisterToken(context.Background(), req.RegisterToken, clientID)
	if err != nil {
		s.store.DeleteClient(context.Background(), clientID)
		protocol.WriteJSONMessage(conn, protocol.RegisterResponse{Type: protocol.MsgRegisterResponse, OK: false, Error: err.Error()})
		return "", err
	}
	if label != "" {
		s.store.RenameClient(context.Background(), clientID, label)
	}
	protocol.WriteJSONMessage(conn, protocol.RegisterResponse{
		Type: protocol.MsgRegisterResponse, OK: true, ClientID: clientID, ClientSecret: clientSecret,
	})
	s.logger.Info("registered new client", "client_id", clientID, "name", label, "remote", remote)
	return clientID, nil
}

// --- helpers ---------------------------------------------------------------

type controlMsg struct {
	Type protocol.ControlMessageType
	raw  []byte
}

// readControlMessage reads one length-prefixed JSON control message (the
// handshake-phase messages that happen BEFORE yamux framing takes over).
func readControlMessage(conn net.Conn) (*controlMsg, error) {
	// We only need its Type field to dispatch; unmarshal into a generic map
	// via a two-pass approach: read length prefix, read payload, parse.
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

// reserveHostSSHPorts adds the ports OpenSSH listens on to the reserved set
// so no panel-created rule can ever collide with the operator's own
// management access to the server.
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
		})
	}
	return out
}

// ensureAdminSeeded creates the initial admin account on first boot and
// prints / writes the generated password. Existing accounts are untouched.
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
	initialPassword := hex.EncodeToString(pwBytes) // 18-char hex
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
