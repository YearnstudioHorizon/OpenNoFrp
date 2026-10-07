// Package store is the single source of truth for everything the OpenNoFrp
// Server and its embedded panel need to persist: the panel admin account,
// registered Clients (internal machines running opennofrp-client) and their
// permanent credentials, one-time registration tokens, and forwarding
// rules.
//
// This replaces the original design where a Client's proxy rules lived in
// its own local TOML file and the Server merely validated a port range.
// Now the Server (via the panel) is the sole authority over which ports
// exist and whether they're currently enabled -- see
// docs/03-product-design.md.
//
// Uses modernc.org/sqlite, a CGO-free pure-Go SQLite driver, so the Server
// binary stays a single static executable with no C toolchain/shared
// library dependency at build or deploy time (important for the
// cross-compile-on-Windows-deploy-to-Linux-VM workflow this project uses).
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
)

// Store wraps the SQLite database handle. All methods are safe for
// concurrent use (SQLite itself serializes writers; reads use WAL mode so
// they don't block on writers).
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and
// ensures the schema exists.
func Open(path string) (*Store, error) {
	// _pragma params configure WAL mode (readers don't block writers, and
	// vice versa for the single-writer case this low-traffic control-plane
	// database always is) and a busy timeout (so a brief lock contention
	// retries instead of immediately erroring).
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // modernc.org/sqlite + WAL: one connection avoids "database is locked" under concurrent goroutines
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS admin (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	username TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	secret_hash TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL DEFAULT 0,
	last_seen_addr TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS register_tokens (
	token TEXT PRIMARY KEY,
	label TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	consumed_at INTEGER NOT NULL DEFAULT 0,
	consumed_by_client_id TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	protocol TEXT NOT NULL CHECK (protocol IN ('tcp','udp','tcp+udp')),
	local_ip TEXT NOT NULL DEFAULT '127.0.0.1',
	local_port INTEGER NOT NULL,
	remote_port INTEGER NOT NULL,
	preserve_source_ip INTEGER NOT NULL DEFAULT 1,
	enabled INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	UNIQUE(remote_port)
);

CREATE TABLE IF NOT EXISTS reserved_ports (
	port INTEGER PRIMARY KEY,
	reason TEXT NOT NULL DEFAULT ''
);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	if err := s.migrateRulesDualStack(); err != nil {
		return fmt.Errorf("store: migrate rules dual-stack: %w", err)
	}
	return nil
}

// migrateRulesDualStack rebuilds the rules table of databases created before
// dual-stack ("tcp+udp") rules existed. SQLite cannot alter a CHECK
// constraint in place, so the table is copied into a new one with the
// widened constraint. Idempotent: does nothing once the constraint already
// mentions 'tcp+udp'.
func (s *Store) migrateRulesDualStack() error {
	var ddl string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'rules'`).Scan(&ddl); err != nil {
		return err
	}
	if strings.Contains(ddl, "tcp+udp") {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	const rebuild = `
CREATE TABLE rules_new (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	protocol TEXT NOT NULL CHECK (protocol IN ('tcp','udp','tcp+udp')),
	local_ip TEXT NOT NULL DEFAULT '127.0.0.1',
	local_port INTEGER NOT NULL,
	remote_port INTEGER NOT NULL,
	preserve_source_ip INTEGER NOT NULL DEFAULT 1,
	enabled INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	UNIQUE(remote_port)
);
INSERT INTO rules_new (id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at)
	SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at FROM rules;
DROP TABLE rules;
ALTER TABLE rules_new RENAME TO rules;
`
	if _, err := tx.Exec(rebuild); err != nil {
		return err
	}
	return tx.Commit()
}

// --- Admin account -------------------------------------------------------

// AdminExists reports whether the single admin account has been created
// yet (first-run detection: the Server prints/writes an initial random
// password the first time it starts with no admin row present).
func (s *Store) AdminExists(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin WHERE id = 1`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: check admin exists: %w", err)
	}
	return n > 0, nil
}

// CreateAdmin sets the single admin account's initial username/password.
// Fails if an admin already exists (use SetAdminPassword to change it).
func (s *Store) CreateAdmin(ctx context.Context, username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("store: hash password: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO admin (id, username, password_hash, created_at) VALUES (1, ?, ?, ?)`,
		username, string(hash), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("store: create admin: %w", err)
	}
	return nil
}

// dummyBcryptHash 是一个预先计算好的标准 bcrypt hash (cost 10)，
// 用于在用户名不存在时执行等耗时的 dummy 比对，消除时序侧信道枚举漏洞 (Timing Attack)。
const dummyBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// VerifyAdmin 校验管理员账密。
// 无论用户名正确与否，均保证执行完整的 bcrypt 计算，消除响应耗时差异（防御用户名枚举）。
func (s *Store) VerifyAdmin(ctx context.Context, username, password string) (bool, error) {
	var storedUsername, hash string
	err := s.db.QueryRowContext(ctx, `SELECT username, password_hash FROM admin WHERE id = 1`).Scan(&storedUsername, &hash)

	// 若未初始化或数据库出错
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("store: load admin: %w", err)
	}

	// 如果用户不存在或用户名不匹配，使用 dummyHash 继续执行 bcrypt，伪装成正常核对过程
	isMatchUser := (err == nil && storedUsername == username)
	targetHash := hash
	if !isMatchUser {
		targetHash = dummyBcryptHash
	}

	// 恒定执行一次密码 Hash 校验
	compErr := bcrypt.CompareHashAndPassword([]byte(targetHash), []byte(password))

	if !isMatchUser || compErr != nil {
		return false, nil
	}
	return true, nil
}

// SetAdminPasswordWithOld 修改管理员密码，严格要求提供原密码并在一致时才允许修改
func (s *Store) SetAdminPasswordWithOld(ctx context.Context, oldPassword, newPassword string) (bool, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM admin WHERE id = 1`).Scan(&hash)
	if err != nil {
		return false, fmt.Errorf("store: load admin password: %w", err)
	}

	// 校验旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPassword)); err != nil {
		return false, nil // 旧密码错误
	}

	// 生成新密码 Hash 并更新
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return false, fmt.Errorf("store: hash new password: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE admin SET password_hash = ? WHERE id = 1`, string(newHash))
	if err != nil {
		return false, fmt.Errorf("store: update admin password: %w", err)
	}
	return true, nil
}

// SetAdminPassword changes the admin password (used by the panel's "change
// password" page).
func (s *Store) SetAdminPassword(ctx context.Context, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("store: hash password: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE admin SET password_hash = ? WHERE id = 1`, string(hash))
	if err != nil {
		return fmt.Errorf("store: update admin password: %w", err)
	}
	return nil
}

// CheckRegisterTokenValid 检查一次性注册令牌是否有效（存在、未被消费且未过期）
func (s *Store) CheckRegisterTokenValid(ctx context.Context, token string) (bool, error) {
	var expiresAt, consumedAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT expires_at, consumed_at FROM register_tokens WHERE token = ?`, token,
	).Scan(&expiresAt, &consumedAt)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: query register token: %w", err)
	}
	if consumedAt != 0 || time.Now().Unix() > expiresAt {
		return false, nil
	}
	return true, nil
}

// --- Register tokens -------------------------------------------------------

// RegisterToken is a one-time-use credential embedded in the panel's
// generated one-line install command. A Client exchanges it exactly once
// for a permanent ClientID/ClientSecret pair via RegisterRequest.
type RegisterToken struct {
	Token     string
	Label     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateRegisterToken generates a new random, time-limited registration
// token. label is a human-friendly hint shown in the panel (e.g. "office
// NAS", filled in by the admin when clicking "add internal server").
func (s *Store) CreateRegisterToken(ctx context.Context, label string, ttl time.Duration) (RegisterToken, error) {
	tok, err := randomHex(24)
	if err != nil {
		return RegisterToken{}, err
	}
	now := time.Now()
	exp := now.Add(ttl)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO register_tokens (token, label, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		tok, label, now.Unix(), exp.Unix())
	if err != nil {
		return RegisterToken{}, fmt.Errorf("store: create register token: %w", err)
	}
	return RegisterToken{Token: tok, Label: label, CreatedAt: now, ExpiresAt: exp}, nil
}

// ConsumeRegisterToken atomically validates and marks a registration token
// used, returning an error if it does not exist, is expired, or was
// already consumed. This must be called within the same transaction/flow
// that mints the new Client's credentials so a token can never be
// redeemed twice even under concurrent registration attempts.
func (s *Store) ConsumeRegisterToken(ctx context.Context, token, byClientID string) (label string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback()

	var expiresAt, consumedAt int64
	err = tx.QueryRowContext(ctx,
		`SELECT label, expires_at, consumed_at FROM register_tokens WHERE token = ?`, token,
	).Scan(&label, &expiresAt, &consumedAt)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("register token not found")
	}
	if err != nil {
		return "", fmt.Errorf("store: load register token: %w", err)
	}
	if consumedAt != 0 {
		return "", fmt.Errorf("register token already used")
	}
	if time.Now().Unix() > expiresAt {
		return "", fmt.Errorf("register token expired")
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE register_tokens SET consumed_at = ?, consumed_by_client_id = ? WHERE token = ?`,
		time.Now().Unix(), byClientID, token)
	if err != nil {
		return "", fmt.Errorf("store: consume register token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: commit: %w", err)
	}
	return label, nil
}

// --- Clients -------------------------------------------------------------

// Client is a registered opennofrp-client instance.
type Client struct {
	ID           string
	Name         string
	CreatedAt    time.Time
	LastSeenAt   time.Time
	LastSeenAddr string
}

// CreateClient mints a brand-new Client identity with a random ID and
// secret. The plaintext secret is returned once (to be sent back in
// RegisterResponse) and only its bcrypt hash is persisted -- the Server
// itself cannot recover a lost Client secret, matching the operator-facing
// behavior of "if you lose it, re-run the registration flow for a new
// identity" rather than storing a recoverable shared secret.
func (s *Store) CreateClient(ctx context.Context, name string) (id, secret string, err error) {
	id, err = randomHex(8)
	if err != nil {
		return "", "", err
	}
	secret, err = randomHex(24)
	if err != nil {
		return "", "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("store: hash client secret: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO clients (id, name, secret_hash, created_at) VALUES (?, ?, ?, ?)`,
		id, name, string(hash), time.Now().Unix())
	if err != nil {
		return "", "", fmt.Errorf("store: create client: %w", err)
	}
	return id, secret, nil
}

// VerifyClient checks a ClientID/ClientSecret pair presented in
// HandshakeRequest.
func (s *Store) VerifyClient(ctx context.Context, id, secret string) (bool, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT secret_hash FROM clients WHERE id = ?`, id).Scan(&hash)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: load client: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)); err != nil {
		return false, nil
	}
	return true, nil
}

// TouchClient records that a Client just completed a successful handshake,
// for display in the panel ("last seen").
func (s *Store) TouchClient(ctx context.Context, id, remoteAddr string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE clients SET last_seen_at = ?, last_seen_addr = ? WHERE id = ?`,
		time.Now().Unix(), remoteAddr, id)
	if err != nil {
		return fmt.Errorf("store: touch client: %w", err)
	}
	return nil
}

// ListClients returns every registered Client, for the panel's Client list
// page.
func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, last_seen_at, last_seen_addr FROM clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list clients: %w", err)
	}
	defer rows.Close()

	var out []Client
	for rows.Next() {
		var c Client
		var createdAt, lastSeenAt int64
		if err := rows.Scan(&c.ID, &c.Name, &createdAt, &lastSeenAt, &c.LastSeenAddr); err != nil {
			return nil, fmt.Errorf("store: scan client: %w", err)
		}
		c.CreatedAt = time.Unix(createdAt, 0)
		if lastSeenAt > 0 {
			c.LastSeenAt = time.Unix(lastSeenAt, 0)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetClient returns a single Client by ID, or sql.ErrNoRows if not found.
func (s *Store) GetClient(ctx context.Context, id string) (Client, error) {
	var c Client
	var createdAt, lastSeenAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, created_at, last_seen_at, last_seen_addr FROM clients WHERE id = ?`, id,
	).Scan(&c.ID, &c.Name, &createdAt, &lastSeenAt, &c.LastSeenAddr)
	if err != nil {
		return Client{}, err
	}
	c.CreatedAt = time.Unix(createdAt, 0)
	if lastSeenAt > 0 {
		c.LastSeenAt = time.Unix(lastSeenAt, 0)
	}
	return c, nil
}

// DeleteClient removes a Client and (via ON DELETE CASCADE) all of its
// rules. Does not affect any currently-open network connection; the
// caller is responsible for also disconnecting the live session, if any.
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete client: %w", err)
	}
	return nil
}

// RenameClient updates a Client's display name.
func (s *Store) RenameClient(ctx context.Context, id, name string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE clients SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return fmt.Errorf("store: rename client: %w", err)
	}
	return nil
}

// --- Rules -----------------------------------------------------------------

// Rule is one forwarding rule, as stored. Mirrors protocol.Rule but is the
// persisted form (includes ClientID, Enabled, CreatedAt which are not part
// of the wire message sent to the owning Client).
type Rule struct {
	ID               int64
	ClientID         string
	Name             string
	Protocol         string // "tcp" or "udp"
	LocalIP          string
	LocalPort        uint16
	RemotePort       uint16
	PreserveSourceIP bool
	Enabled          bool
	CreatedAt        time.Time
}

// CreateRule adds a new rule for a Client. It is created disabled by
// default (enabled=false) UNLESS enabled is explicitly passed true -- the
// panel's "add rule" form has an explicit "enable immediately" checkbox so
// operators can stage a rule (e.g. while the internal service isn't up
// yet) without it taking effect.
func (s *Store) CreateRule(ctx context.Context, r Rule) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO rules (client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ClientID, r.Name, r.Protocol, r.LocalIP, r.LocalPort, r.RemotePort, boolToInt(r.PreserveSourceIP), boolToInt(r.Enabled), time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("store: create rule: %w", err)
	}
	return res.LastInsertId()
}

// UpdateRule overwrites an existing rule's mutable fields (not ClientID,
// which is immutable after creation -- to move a rule to a different
// Client, delete and recreate it).
func (s *Store) UpdateRule(ctx context.Context, r Rule) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE rules SET name = ?, protocol = ?, local_ip = ?, local_port = ?, remote_port = ?, preserve_source_ip = ?, enabled = ?
		 WHERE id = ?`,
		r.Name, r.Protocol, r.LocalIP, r.LocalPort, r.RemotePort, boolToInt(r.PreserveSourceIP), boolToInt(r.Enabled), r.ID)
	if err != nil {
		return fmt.Errorf("store: update rule: %w", err)
	}
	return nil
}

// SetRuleEnabled is the dedicated fast-path for the panel's on/off toggle
// button -- flips exactly one column without requiring the caller to
// re-submit every other field.
func (s *Store) SetRuleEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE rules SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	if err != nil {
		return fmt.Errorf("store: set rule enabled: %w", err)
	}
	return nil
}

// DeleteRule removes a rule permanently.
func (s *Store) DeleteRule(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete rule: %w", err)
	}
	return nil
}

// GetRule returns a single rule by ID.
func (s *Store) GetRule(ctx context.Context, id int64) (Rule, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at FROM rules WHERE id = ?`, id)
	return scanRule(row)
}

// ListRulesForClient returns every rule (enabled or not) belonging to a
// Client, for the panel's per-Client rule management page.
func (s *Store) ListRulesForClient(ctx context.Context, clientID string) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at
		 FROM rules WHERE client_id = ? ORDER BY created_at`, clientID)
	if err != nil {
		return nil, fmt.Errorf("store: list rules for client: %w", err)
	}
	defer rows.Close()
	return scanRules(rows)
}

// ListEnabledRulesForClient returns only the currently-enabled rules for a
// Client. This is exactly the set the Server pushes to that Client as a
// RulesSnapshot, and the set listener.Manager should have open public
// listeners for.
func (s *Store) ListEnabledRulesForClient(ctx context.Context, clientID string) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at
		 FROM rules WHERE client_id = ? AND enabled = 1 ORDER BY created_at`, clientID)
	if err != nil {
		return nil, fmt.Errorf("store: list enabled rules for client: %w", err)
	}
	defer rows.Close()
	return scanRules(rows)
}

// ListAllEnabledRules returns every enabled rule across all Clients. Used
// at Server startup to re-open every public listener that should already
// be active (e.g. after a Server restart, before any Client has even
// reconnected yet) -- see docs/03-product-design.md for why listeners are
// driven by the database rather than only by live Client handshakes.
func (s *Store) ListAllEnabledRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at
		 FROM rules WHERE enabled = 1 ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: list all enabled rules: %w", err)
	}
	defer rows.Close()
	return scanRules(rows)
}

// RemotePortInUse reports whether remotePort is already assigned to any
// rule other than excludeRuleID (pass 0 when creating a new rule). Used by
// the panel to give a friendly "port already in use" validation error
// instead of relying solely on the UNIQUE constraint's raw SQL error.
func (s *Store) RemotePortInUse(ctx context.Context, remotePort uint16, excludeRuleID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM rules WHERE remote_port = ? AND id != ?`, remotePort, excludeRuleID,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: check remote port in use: %w", err)
	}
	return n > 0, nil
}

func scanRule(row *sql.Row) (Rule, error) {
	var r Rule
	var preserve, enabled int
	var createdAt int64
	err := row.Scan(&r.ID, &r.ClientID, &r.Name, &r.Protocol, &r.LocalIP, &r.LocalPort, &r.RemotePort, &preserve, &enabled, &createdAt)
	if err != nil {
		return Rule{}, err
	}
	r.PreserveSourceIP = preserve != 0
	r.Enabled = enabled != 0
	r.CreatedAt = time.Unix(createdAt, 0)
	return r, nil
}

func scanRules(rows *sql.Rows) ([]Rule, error) {
	var out []Rule
	for rows.Next() {
		var r Rule
		var preserve, enabled int
		var createdAt int64
		if err := rows.Scan(&r.ID, &r.ClientID, &r.Name, &r.Protocol, &r.LocalIP, &r.LocalPort, &r.RemotePort, &preserve, &enabled, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan rule: %w", err)
		}
		r.PreserveSourceIP = preserve != 0
		r.Enabled = enabled != 0
		r.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Reserved ports ----------------------------------------------------

// ReservedPorts returns the set of ports the operator (or the installer,
// auto-detecting the current SSH port) has marked as off-limits to the
// panel. CreateRule/UpdateRule callers must check this before accepting a
// remote_port -- see docs/03-product-design.md "soft default-deny" design:
// the Server never opens a reserved port no matter what the panel/API is
// asked to do, which is the safety net against an admin fat-fingering a
// rule that collides with SSH or another already-running service on the
// cloud box.
func (s *Store) ReservedPorts(ctx context.Context) (map[uint16]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT port, reason FROM reserved_ports`)
	if err != nil {
		return nil, fmt.Errorf("store: list reserved ports: %w", err)
	}
	defer rows.Close()
	out := make(map[uint16]string)
	for rows.Next() {
		var port int
		var reason string
		if err := rows.Scan(&port, &reason); err != nil {
			return nil, fmt.Errorf("store: scan reserved port: %w", err)
		}
		out[uint16(port)] = reason
	}
	return out, rows.Err()
}

// AddReservedPort marks a port as reserved (never forwardable via a rule).
// Idempotent: re-adding the same port just updates its reason.
func (s *Store) AddReservedPort(ctx context.Context, port uint16, reason string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO reserved_ports (port, reason) VALUES (?, ?) ON CONFLICT(port) DO UPDATE SET reason = excluded.reason`,
		port, reason)
	if err != nil {
		return fmt.Errorf("store: add reserved port: %w", err)
	}
	return nil
}

// RemoveReservedPort un-reserves a port (panel operator override, for the
// rare case the auto-detected reservation was wrong).
func (s *Store) RemoveReservedPort(ctx context.Context, port uint16) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM reserved_ports WHERE port = ?`, port)
	if err != nil {
		return fmt.Errorf("store: remove reserved port: %w", err)
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
