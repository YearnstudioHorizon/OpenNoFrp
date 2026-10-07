// Package store 是 OpenNoFrp Server 及其内嵌面板所有需要持久化数据的唯一
// 可信来源：面板管理员账户、已注册的 Client（运行 opennofrp-client 的内网
// 机器）及其永久凭据、一次性注册令牌，以及转发规则。
//
// 这取代了最初的设计：原先 Client 的代理规则存放在其本地 TOML 文件中，
// Server 只负责校验端口范围。现在 Server（通过面板）是决定哪些端口存在、
// 以及它们当前是否启用的唯一权威——参见 docs/03-product-design.md。
//
// 使用 modernc.org/sqlite，一个无需 CGO 的纯 Go SQLite 驱动，因此 Server
// 二进制在构建和部署时始终是单个静态可执行文件，不依赖 C 工具链或共享库
// （这对本项目所采用的“在 Windows 上交叉编译、部署到 Linux 虚拟机”的
// 工作流非常重要）。
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

// Store 封装 SQLite 数据库句柄。所有方法均可安全地并发使用（SQLite 本身会
// 串行化写操作；读操作使用 WAL 模式，因此不会被写操作阻塞）。
type Store struct {
	db *sql.DB
}

// Open 打开位于 path 的 SQLite 数据库（必要时创建），并确保 schema 已存在。
func Open(path string) (*Store, error) {
	// _pragma 参数配置 WAL 模式（读不阻塞写，写也不阻塞读——这个低流量的
	// 控制面数据库始终处于单写者场景）以及 busy timeout（使短暂的锁竞争会
	// 重试，而不是立即报错）。
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // modernc.org/sqlite + WAL：使用单个连接，避免并发 goroutine 下出现 "database is locked"
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
	protocol TEXT NOT NULL CHECK (protocol IN ('tcp','udp','tcp+udp','http','tls')),
	local_ip TEXT NOT NULL DEFAULT '127.0.0.1',
	local_port INTEGER NOT NULL,
	remote_port INTEGER NOT NULL,
	preserve_source_ip INTEGER NOT NULL DEFAULT 1,
	enabled INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	domains TEXT NOT NULL DEFAULT '',
	path_prefix TEXT NOT NULL DEFAULT '',
	offline_page TEXT NOT NULL DEFAULT '',
	ip_sources TEXT NOT NULL DEFAULT '',
	trusted_proxies TEXT NOT NULL DEFAULT '',
	tls_mode TEXT NOT NULL DEFAULT '',
	tls_cert TEXT NOT NULL DEFAULT '',
	tls_key TEXT NOT NULL DEFAULT '',
	redirect_https TEXT NOT NULL DEFAULT '',
	strip_prefix TEXT NOT NULL DEFAULT '',
	host_rewrite TEXT NOT NULL DEFAULT '',
	req_headers TEXT NOT NULL DEFAULT '',
	resp_headers TEXT NOT NULL DEFAULT '',
	basic_auth TEXT NOT NULL DEFAULT '',
	ip_allow TEXT NOT NULL DEFAULT '',
	not_found_page TEXT NOT NULL DEFAULT '',
	guard_allow TEXT NOT NULL DEFAULT '',
	guard_deny TEXT NOT NULL DEFAULT '',
	max_conns_per_ip INTEGER NOT NULL DEFAULT 0,
	conn_rate_per_min INTEGER NOT NULL DEFAULT 0,
	bandwidth_kbps INTEGER NOT NULL DEFAULT 0,
	backends TEXT NOT NULL DEFAULT '',
	lb_strategy TEXT NOT NULL DEFAULT '',
	proxy_protocol INTEGER NOT NULL DEFAULT 0,
	remote_port_end INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reserved_ports (
	port INTEGER PRIMARY KEY,
	reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS panel_sessions (
	token_hash TEXT PRIMARY KEY,
	csrf_token TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL DEFAULT '',
	token_hash TEXT NOT NULL UNIQUE,
	prefix TEXT NOT NULL DEFAULT '',
	read_only INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL DEFAULT 0
);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	// 先补齐缺失的列，再按需重建表（重建时会复制全部列）。
	if err := s.ensureRuleColumns(); err != nil {
		return fmt.Errorf("store: migrate rules columns: %w", err)
	}
	if err := s.migrateRulesDualStack(); err != nil {
		return fmt.Errorf("store: migrate rules dual-stack: %w", err)
	}
	return nil
}

// migrateRulesDualStack 重建在 HTTP 规则出现之前创建的数据库中的 rules 表
// （包括更早的、尚不支持 "tcp+udp" 的版本）。SQLite 无法原地修改 CHECK
// 约束或删除 UNIQUE 约束，因此会将该表复制到一个新表中：
//   - protocol 允许 'http'；
//   - 去掉 UNIQUE(remote_port)：多个 HTTP 规则可以按域名/路径共享同一端口，
//     端口冲突改由应用层（RuleConflict）检查；
//   - 新增 domains / path_prefix / offline_page 列。
//
// 该操作是幂等的：一旦约束中已包含 'http'，便不做任何事。
func (s *Store) migrateRulesDualStack() error {
	var ddl string
	if err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'rules'`).Scan(&ddl); err != nil {
		return err
	}
	if strings.Contains(ddl, "'tls'") {
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
	protocol TEXT NOT NULL CHECK (protocol IN ('tcp','udp','tcp+udp','http','tls')),
	local_ip TEXT NOT NULL DEFAULT '127.0.0.1',
	local_port INTEGER NOT NULL,
	remote_port INTEGER NOT NULL,
	preserve_source_ip INTEGER NOT NULL DEFAULT 1,
	enabled INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	domains TEXT NOT NULL DEFAULT '',
	path_prefix TEXT NOT NULL DEFAULT '',
	offline_page TEXT NOT NULL DEFAULT '',
	ip_sources TEXT NOT NULL DEFAULT '',
	trusted_proxies TEXT NOT NULL DEFAULT '',
	tls_mode TEXT NOT NULL DEFAULT '',
	tls_cert TEXT NOT NULL DEFAULT '',
	tls_key TEXT NOT NULL DEFAULT '',
	redirect_https TEXT NOT NULL DEFAULT '',
	strip_prefix TEXT NOT NULL DEFAULT '',
	host_rewrite TEXT NOT NULL DEFAULT '',
	req_headers TEXT NOT NULL DEFAULT '',
	resp_headers TEXT NOT NULL DEFAULT '',
	basic_auth TEXT NOT NULL DEFAULT '',
	ip_allow TEXT NOT NULL DEFAULT '',
	not_found_page TEXT NOT NULL DEFAULT '',
	guard_allow TEXT NOT NULL DEFAULT '',
	guard_deny TEXT NOT NULL DEFAULT '',
	max_conns_per_ip INTEGER NOT NULL DEFAULT 0,
	conn_rate_per_min INTEGER NOT NULL DEFAULT 0,
	bandwidth_kbps INTEGER NOT NULL DEFAULT 0,
	backends TEXT NOT NULL DEFAULT '',
	lb_strategy TEXT NOT NULL DEFAULT '',
	proxy_protocol INTEGER NOT NULL DEFAULT 0,
	remote_port_end INTEGER NOT NULL DEFAULT 0
);
INSERT INTO rules_new (id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at,
	domains, path_prefix, offline_page, ip_sources, trusted_proxies, tls_mode, tls_cert, tls_key, redirect_https,
	strip_prefix, host_rewrite, req_headers, resp_headers, basic_auth, ip_allow, not_found_page,
	guard_allow, guard_deny, max_conns_per_ip, conn_rate_per_min, bandwidth_kbps, backends, lb_strategy, proxy_protocol, remote_port_end)
	SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at,
	domains, path_prefix, offline_page, ip_sources, trusted_proxies, tls_mode, tls_cert, tls_key, redirect_https,
	strip_prefix, host_rewrite, req_headers, resp_headers, basic_auth, ip_allow, not_found_page,
	guard_allow, guard_deny, max_conns_per_ip, conn_rate_per_min, bandwidth_kbps, backends, lb_strategy, proxy_protocol, remote_port_end FROM rules;
DROP TABLE rules;
ALTER TABLE rules_new RENAME TO rules;
`
	if _, err := tx.Exec(rebuild); err != nil {
		return err
	}
	return tx.Commit()
}

// ensureRuleColumns 为已经升级到 HTTP 版本、但缺少后续新增列的 rules 表补齐
// 列（ALTER TABLE ADD COLUMN 可在 SQLite 中原地执行）。幂等。
func (s *Store) ensureRuleColumns() error {
	rows, err := s.db.Query(`PRAGMA table_info(rules)`)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, col := range []string{"domains", "path_prefix", "offline_page", "ip_sources", "trusted_proxies", "tls_mode", "tls_cert", "tls_key", "redirect_https",
		"strip_prefix", "host_rewrite", "req_headers", "resp_headers", "basic_auth", "ip_allow", "not_found_page",
		"guard_allow", "guard_deny", "backends", "lb_strategy"} {
		if have[col] {
			continue
		}
		if _, err := s.db.Exec(fmt.Sprintf(`ALTER TABLE rules ADD COLUMN %s TEXT NOT NULL DEFAULT ''`, col)); err != nil {
			return err
		}
	}
	for _, col := range []string{"max_conns_per_ip", "conn_rate_per_min", "bandwidth_kbps", "proxy_protocol", "remote_port_end"} {
		if have[col] {
			continue
		}
		if _, err := s.db.Exec(fmt.Sprintf(`ALTER TABLE rules ADD COLUMN %s INTEGER NOT NULL DEFAULT 0`, col)); err != nil {
			return err
		}
	}
	return nil
}

// --- 管理员账户 -------------------------------------------------------

// AdminExists 报告唯一的管理员账户是否已创建（首次运行检测：当 Server
// 首次启动且不存在管理员记录时，会打印/写入一个初始随机密码）。
func (s *Store) AdminExists(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin WHERE id = 1`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: check admin exists: %w", err)
	}
	return n > 0, nil
}

// CreateAdmin 设置唯一管理员账户的初始用户名/密码。
// 若管理员已存在则失败（修改密码请使用 SetAdminPassword）。
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

// dummyBcryptHash 是一个预先计算好的标准 bcrypt 哈希 (cost 10)，
// 用于在用户名不存在时执行等耗时的虚拟比对，消除时序侧信道枚举漏洞（时序攻击）。
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

	// 恒定执行一次密码哈希校验
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

	// 生成新密码哈希并更新
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

// SetAdminPassword 修改管理员密码（供面板的“修改密码”页面使用）。
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

// ---- 面板登录会话 ----------------------------------------------------------
//
// 会话持久化在 SQLite 中，Server 重启后已登录的管理员无需重新登录。数据库中只
// 保存会话 Cookie 的 SHA-256 哈希，数据库泄露也无法直接冒用会话。

// CreatePanelSession 保存一个新的面板会话。
func (s *Store) CreatePanelSession(ctx context.Context, tokenHash, csrfToken string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO panel_sessions (token_hash, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, csrfToken, time.Now().Unix(), expiresAt.Unix())
	if err != nil {
		return fmt.Errorf("store: create panel session: %w", err)
	}
	return nil
}

// GetPanelSession 返回会话的 CSRF 令牌与过期时间；不存在或已过期时 ok 为 false
// （已过期的会话会被顺带删除）。
func (s *Store) GetPanelSession(ctx context.Context, tokenHash string) (csrfToken string, expiresAt time.Time, ok bool, err error) {
	var exp int64
	err = s.db.QueryRowContext(ctx,
		`SELECT csrf_token, expires_at FROM panel_sessions WHERE token_hash = ?`, tokenHash).Scan(&csrfToken, &exp)
	if err == sql.ErrNoRows {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("store: get panel session: %w", err)
	}
	expiresAt = time.Unix(exp, 0)
	if time.Now().After(expiresAt) {
		_ = s.DeletePanelSession(ctx, tokenHash)
		return "", time.Time{}, false, nil
	}
	return csrfToken, expiresAt, true, nil
}

// DeletePanelSession 删除一个面板会话（退出登录）。
func (s *Store) DeletePanelSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM panel_sessions WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return fmt.Errorf("store: delete panel session: %w", err)
	}
	return nil
}

// DeleteAllPanelSessions 删除全部面板会话（修改密码后踢出所有已登录会话）。
func (s *Store) DeleteAllPanelSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM panel_sessions`)
	if err != nil {
		return fmt.Errorf("store: delete all panel sessions: %w", err)
	}
	return nil
}

// PurgeExpiredPanelSessions 清理已过期的面板会话。
func (s *Store) PurgeExpiredPanelSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM panel_sessions WHERE expires_at < ?`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("store: purge panel sessions: %w", err)
	}
	return nil
}

// ---- REST API 令牌 ---------------------------------------------------------
//
// API 令牌用于以 "Authorization: Bearer <token>" 调用 /api/v1/*。数据库中只保存
// 令牌的 SHA-256 哈希（由调用方计算）以及便于识别的前缀。

// APIToken 是一条 API 令牌记录（不含明文）。
type APIToken struct {
	ID         int64
	Name       string
	Prefix     string
	ReadOnly   bool
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// CreateAPIToken 保存一个新的 API 令牌（tokenHash 为明文令牌的 SHA-256 十六进制）。
func (s *Store) CreateAPIToken(ctx context.Context, name, tokenHash, prefix string, readOnly bool) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens (name, token_hash, prefix, read_only, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, tokenHash, prefix, boolToInt(readOnly), time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("store: create api token: %w", err)
	}
	return res.LastInsertId()
}

// LookupAPIToken 按哈希查找令牌；找到时顺带更新 last_used_at。
func (s *Store) LookupAPIToken(ctx context.Context, tokenHash string) (APIToken, bool, error) {
	var t APIToken
	var ro int
	var created, used int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, prefix, read_only, created_at, last_used_at FROM api_tokens WHERE token_hash = ?`, tokenHash).
		Scan(&t.ID, &t.Name, &t.Prefix, &ro, &created, &used)
	if err == sql.ErrNoRows {
		return APIToken{}, false, nil
	}
	if err != nil {
		return APIToken{}, false, fmt.Errorf("store: lookup api token: %w", err)
	}
	t.ReadOnly = ro != 0
	t.CreatedAt = time.Unix(created, 0)
	now := time.Now()
	t.LastUsedAt = now
	_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now.Unix(), t.ID)
	return t, true, nil
}

// ListAPITokens 返回全部 API 令牌（按创建时间排序）。
func (s *Store) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, prefix, read_only, created_at, last_used_at FROM api_tokens ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list api tokens: %w", err)
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var ro int
		var created, used int64
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &ro, &created, &used); err != nil {
			return nil, fmt.Errorf("store: scan api token: %w", err)
		}
		t.ReadOnly = ro != 0
		t.CreatedAt = time.Unix(created, 0)
		if used > 0 {
			t.LastUsedAt = time.Unix(used, 0)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken 吊销一个 API 令牌。
func (s *Store) DeleteAPIToken(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete api token: %w", err)
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

// --- 注册令牌 -------------------------------------------------------

// RegisterToken 是一种一次性凭据，嵌入在面板生成的单行安装命令中。Client
// 通过 RegisterRequest 用它换取一对永久的 ClientID/ClientSecret，且仅能
// 兑换一次。
type RegisterToken struct {
	Token     string
	Label     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateRegisterToken 生成一个新的随机、限时注册令牌。label 是在面板中
// 显示的便于识别的提示（例如“办公室 NAS”，由管理员点击“添加内网服务器”
// 时填写）。
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

// ConsumeRegisterToken 以原子方式校验注册令牌并将其标记为已使用；若令牌
// 不存在、已过期或已被消费，则返回错误。必须在为新 Client 签发凭据的同一
// 事务/流程中调用此方法，这样即使存在并发注册尝试，令牌也绝不会被兑换
// 两次。
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

// --- 客户端 -------------------------------------------------------------

// Client 是一个已注册的 opennofrp-client 实例。
type Client struct {
	ID           string
	Name         string
	CreatedAt    time.Time
	LastSeenAt   time.Time
	LastSeenAddr string
}

// CreateClient 签发一个全新的 Client 身份，带有随机 ID 和密钥。明文密钥
// 只返回一次（随 RegisterResponse 回传），持久化的仅是其 bcrypt 哈希——
// Server 自身无法恢复丢失的 Client 密钥，这与面向运维者的行为一致：
// “如果丢失，就重新执行注册流程以获取新身份”，而不是存储一个可恢复的
// 共享密钥。
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

// VerifyClient 校验 HandshakeRequest 中提供的 ClientID/ClientSecret 对。
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

// TouchClient 记录某个 Client 刚刚完成了一次成功握手，用于在面板中显示
// （“最后在线”）。
func (s *Store) TouchClient(ctx context.Context, id, remoteAddr string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE clients SET last_seen_at = ?, last_seen_addr = ? WHERE id = ?`,
		time.Now().Unix(), remoteAddr, id)
	if err != nil {
		return fmt.Errorf("store: touch client: %w", err)
	}
	return nil
}

// ListClients 返回所有已注册的 Client，供面板的 Client 列表页面使用。
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

// GetClient 按 ID 返回单个 Client；若未找到则返回 sql.ErrNoRows。
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

// DeleteClient 删除一个 Client 及其所有规则（通过 ON DELETE CASCADE）。
// 不会影响任何当前已打开的网络连接；如有在线会话，调用方需负责同时断开它。
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete client: %w", err)
	}
	return nil
}

// RenameClient 更新 Client 的显示名称。
func (s *Store) RenameClient(ctx context.Context, id, name string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE clients SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return fmt.Errorf("store: rename client: %w", err)
	}
	return nil
}

// --- 规则 -----------------------------------------------------------------

// Rule 是一条已存储的转发规则。它与 protocol.Rule 相对应，但属于持久化
// 形式（包含 ClientID、Enabled、CreatedAt，这些字段不属于发送给所属
// Client 的线上消息）。
type Rule struct {
	ID               int64
	ClientID         string
	Name             string
	Protocol         string // "tcp"、"udp"、"tcp+udp" 或 "http"
	LocalIP          string
	LocalPort        uint16
	RemotePort       uint16
	PreserveSourceIP bool
	Enabled          bool
	CreatedAt        time.Time

	// 以下字段仅对 protocol = "http" 有意义。
	// Domains 是逗号分隔的域名列表（支持 "*.example.com" 通配），为空表示
	// 匹配该端口上的任意 Host（兜底规则）。
	Domains string
	// PathPrefix 是 URL 路径前缀（例如 "/api"），为空等同于 "/"。
	PathPrefix string
	// OfflinePage 是后端不可用（Client 离线或本地服务未启动）时返回给访问者
	// 的自定义 HTML；为空时使用内置默认页面。
	OfflinePage string
	// IPSources 是逗号分隔、按优先级排列的真实客户端 IP 来源列表，取值：
	// remote_addr、x-forwarded-for、x-real-ip、cf-connecting-ip、
	// true-client-ip、x-client-ip、forwarded。为空等同于 "remote_addr"。
	IPSources string
	// TrustedProxies 是逗号分隔的 CIDR/IP 列表：只有当 TCP 对端地址属于其中之一时
	// 才信任请求头中的 IP。为空表示信任任意对端（适用于前面一定有 CDN 的场景）。
	TrustedProxies string
	// TLSMode 决定 HTTP 规则所在端口是否终止 TLS（HTTPS）：
	//   ""       = 明文 HTTP；
	//   "acme"   = 按 Domains 通过 ACME 自动申请/续期证书；
	//   "custom" = 使用 TLSCert/TLSKey 中上传的 PEM 证书与私钥。
	// 同一端口上的 HTTP 规则必须使用一致的“是否 TLS”设置。
	TLSMode string
	TLSCert string // PEM 证书链（TLSMode = "custom"）
	TLSKey  string // PEM 私钥（TLSMode = "custom"）
	// RedirectHTTPS 为 "1" 时，明文 HTTP 端口（80）上匹配该规则域名的请求会被
	// 301 跳转到 HTTPS。仅在 TLSMode 非空时有意义。
	RedirectHTTPS string
	// StripPrefix 为 "1" 时，转发给后端前去掉 PathPrefix（/api/x -> /x）。
	StripPrefix string
	// HostRewrite 非空时，发往后端的 Host 头改写为该值。
	HostRewrite string
	// ReqHeaders / RespHeaders 是每行一个 "Name: Value" 的自定义请求/响应头；
	// 值为空（"Name:"）表示删除该头。
	ReqHeaders  string
	RespHeaders string
	// BasicAuth 是每行一个 "user:bcrypt哈希" 的 Basic Auth 账户列表，为空表示不启用。
	BasicAuth string
	// IPAllow 是逗号分隔的 IP/CIDR 白名单（基于提取出的真实 IP），为空表示不限制。
	IPAllow string
	// NotFoundPage 是该端口上无匹配路由时返回的自定义 404 HTML（取该端口上任意
	// 一条设置了该字段的规则）。
	NotFoundPage string

	// 规则级防护（所有协议通用）。
	// GuardAllow / GuardDeny 是逗号分隔的 IP/CIDR 白名单 / 黑名单（黑名单优先）。
	GuardAllow string
	GuardDeny  string
	// MaxConnsPerIP 是单 IP 并发连接（HTTP 为并发请求）上限，0 = 不限制。
	MaxConnsPerIP int
	// ConnRatePerMin 是单 IP 每分钟新建连接（HTTP 为请求）上限，0 = 不限制。
	ConnRatePerMin int
	// BandwidthKBps 是该规则所有连接共享的带宽上限（KB/s），0 = 不限制。
	BandwidthKBps int

	// 多后端负载均衡（tcp/http/tls 规则）。
	// Backends 是每行或逗号分隔的额外后端 "ip:port"（主后端仍为 LocalIP:LocalPort）。
	Backends string
	// LBStrategy：""/"round_robin" = 轮询，"random" = 随机，"failover" = 主备。
	LBStrategy string

	// ProxyProtocol 为 1 或 2 时，Client 向后端发送 PROXY 协议 v1/v2 头；0 = 不发送。
	ProxyProtocol int

	// RemotePortEnd 非 0 时表示端口段规则（仅 tcp/udp/tcp+udp）：公网端口
	// RemotePort..RemotePortEnd 依次映射到本地端口 LocalPort..LocalPort+(End-RemotePort)。
	RemotePortEnd uint16
}

// CreateRule 为某个 Client 添加一条新规则。默认以禁用状态创建
// （enabled=false），除非显式传入 enabled 为 true——面板的“添加规则”表单
// 有一个明确的“立即启用”复选框，以便运维者可以预先配置一条规则（例如在
// 内网服务尚未启动时）而不让其生效。
func (s *Store) CreateRule(ctx context.Context, r Rule) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO rules (client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at, domains, path_prefix, offline_page, ip_sources, trusted_proxies, tls_mode, tls_cert, tls_key, redirect_https,
		 strip_prefix, host_rewrite, req_headers, resp_headers, basic_auth, ip_allow, not_found_page,
		 guard_allow, guard_deny, max_conns_per_ip, conn_rate_per_min, bandwidth_kbps, backends, lb_strategy, proxy_protocol, remote_port_end)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ClientID, r.Name, r.Protocol, r.LocalIP, r.LocalPort, r.RemotePort, boolToInt(r.PreserveSourceIP), boolToInt(r.Enabled), time.Now().Unix(),
		r.Domains, r.PathPrefix, r.OfflinePage, r.IPSources, r.TrustedProxies, r.TLSMode, r.TLSCert, r.TLSKey, r.RedirectHTTPS,
		r.StripPrefix, r.HostRewrite, r.ReqHeaders, r.RespHeaders, r.BasicAuth, r.IPAllow, r.NotFoundPage,
		r.GuardAllow, r.GuardDeny, r.MaxConnsPerIP, r.ConnRatePerMin, r.BandwidthKBps, r.Backends, r.LBStrategy, r.ProxyProtocol, r.RemotePortEnd)
	if err != nil {
		return 0, fmt.Errorf("store: create rule: %w", err)
	}
	return res.LastInsertId()
}

// UpdateRule 覆盖现有规则的可变字段（不包括 ClientID，它在创建后不可变——
// 若要将规则移到另一个 Client，请删除后重新创建）。
func (s *Store) UpdateRule(ctx context.Context, r Rule) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE rules SET name = ?, protocol = ?, local_ip = ?, local_port = ?, remote_port = ?, preserve_source_ip = ?, enabled = ?,
		 domains = ?, path_prefix = ?, offline_page = ?, ip_sources = ?, trusted_proxies = ?,
		 tls_mode = ?, tls_cert = ?, tls_key = ?, redirect_https = ?,
		 strip_prefix = ?, host_rewrite = ?, req_headers = ?, resp_headers = ?, basic_auth = ?, ip_allow = ?, not_found_page = ?,
		 guard_allow = ?, guard_deny = ?, max_conns_per_ip = ?, conn_rate_per_min = ?, bandwidth_kbps = ?, backends = ?, lb_strategy = ?, proxy_protocol = ?, remote_port_end = ?
		 WHERE id = ?`,
		r.Name, r.Protocol, r.LocalIP, r.LocalPort, r.RemotePort, boolToInt(r.PreserveSourceIP), boolToInt(r.Enabled),
		r.Domains, r.PathPrefix, r.OfflinePage, r.IPSources, r.TrustedProxies,
		r.TLSMode, r.TLSCert, r.TLSKey, r.RedirectHTTPS,
		r.StripPrefix, r.HostRewrite, r.ReqHeaders, r.RespHeaders, r.BasicAuth, r.IPAllow, r.NotFoundPage,
		r.GuardAllow, r.GuardDeny, r.MaxConnsPerIP, r.ConnRatePerMin, r.BandwidthKBps, r.Backends, r.LBStrategy, r.ProxyProtocol, r.RemotePortEnd, r.ID)
	if err != nil {
		return fmt.Errorf("store: update rule: %w", err)
	}
	return nil
}

// SetRuleEnabled 是面板开关按钮专用的快速路径——只切换一列，调用方无需
// 重新提交其他所有字段。
func (s *Store) SetRuleEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE rules SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	if err != nil {
		return fmt.Errorf("store: set rule enabled: %w", err)
	}
	return nil
}

// DeleteRule 永久删除一条规则。
func (s *Store) DeleteRule(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete rule: %w", err)
	}
	return nil
}

// GetRule 按 ID 返回单条规则。
func (s *Store) GetRule(ctx context.Context, id int64) (Rule, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at, domains, path_prefix, offline_page, ip_sources, trusted_proxies, tls_mode, tls_cert, tls_key, redirect_https, strip_prefix, host_rewrite, req_headers, resp_headers, basic_auth, ip_allow, not_found_page, guard_allow, guard_deny, max_conns_per_ip, conn_rate_per_min, bandwidth_kbps, backends, lb_strategy, proxy_protocol, remote_port_end FROM rules WHERE id = ?`, id)
	return scanRule(row)
}

// ListRulesForClient 返回属于某个 Client 的所有规则（无论是否启用），供
// 面板中按 Client 划分的规则管理页面使用。
func (s *Store) ListRulesForClient(ctx context.Context, clientID string) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at, domains, path_prefix, offline_page, ip_sources, trusted_proxies, tls_mode, tls_cert, tls_key, redirect_https, strip_prefix, host_rewrite, req_headers, resp_headers, basic_auth, ip_allow, not_found_page, guard_allow, guard_deny, max_conns_per_ip, conn_rate_per_min, bandwidth_kbps, backends, lb_strategy, proxy_protocol, remote_port_end
		 FROM rules WHERE client_id = ? ORDER BY created_at`, clientID)
	if err != nil {
		return nil, fmt.Errorf("store: list rules for client: %w", err)
	}
	defer rows.Close()
	return scanRules(rows)
}

// ListEnabledRulesForClient 仅返回某个 Client 当前已启用的规则。这正是
// Server 以 RulesSnapshot 形式推送给该 Client 的集合，也是
// listener.Manager 应为其打开公网监听器的集合。
func (s *Store) ListEnabledRulesForClient(ctx context.Context, clientID string) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at, domains, path_prefix, offline_page, ip_sources, trusted_proxies, tls_mode, tls_cert, tls_key, redirect_https, strip_prefix, host_rewrite, req_headers, resp_headers, basic_auth, ip_allow, not_found_page, guard_allow, guard_deny, max_conns_per_ip, conn_rate_per_min, bandwidth_kbps, backends, lb_strategy, proxy_protocol, remote_port_end
		 FROM rules WHERE client_id = ? AND enabled = 1 ORDER BY created_at`, clientID)
	if err != nil {
		return nil, fmt.Errorf("store: list enabled rules for client: %w", err)
	}
	defer rows.Close()
	return scanRules(rows)
}

// ListAllEnabledRules 返回所有 Client 的全部已启用规则。在 Server 启动时
// 使用，用于重新打开所有本应处于活动状态的公网监听器（例如在 Server 重启
// 后、尚无任何 Client 重新连接之前）——关于为什么监听器由数据库驱动，而
// 不仅仅由在线 Client 的握手驱动，参见 docs/03-product-design.md。
func (s *Store) ListAllEnabledRules(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at, domains, path_prefix, offline_page, ip_sources, trusted_proxies, tls_mode, tls_cert, tls_key, redirect_https, strip_prefix, host_rewrite, req_headers, resp_headers, basic_auth, ip_allow, not_found_page, guard_allow, guard_deny, max_conns_per_ip, conn_rate_per_min, bandwidth_kbps, backends, lb_strategy, proxy_protocol, remote_port_end
		 FROM rules WHERE enabled = 1 ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: list all enabled rules: %w", err)
	}
	defer rows.Close()
	return scanRules(rows)
}

// RemotePortInUse 报告 remotePort 是否已被除 excludeRuleID 之外的任何规则
// 占用（创建新规则时传 0）。面板用它给出友好的“端口已被占用”校验错误，
// 而不是仅依赖 UNIQUE 约束产生的原始 SQL 错误。
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

// RuleConflict 检查候选规则 c 与除 c.ID 之外的现有规则在公网端口上是否冲突。
// 冲突规则：
//   - 传输层重叠（tcp 与 tcp / tcp+udp / http；udp 与 udp / tcp+udp）的
//     非 HTTP 规则不能共享端口；
//   - HTTP 规则之间可以共享端口，但 (域名, 路径前缀) 组合不能重叠；
//   - HTTP 规则不能与 tcp / tcp+udp 规则共享端口（同端口的纯 UDP 规则允许）。
//
// 无冲突时返回 (nil, nil)；有冲突时返回与之冲突的现有规则。
func (s *Store) RuleConflict(ctx context.Context, c Rule) (*Rule, error) {
	// 端口段规则：按区间 [RemotePort, RemotePortEnd] 判断重叠。
	cEnd := c.RemotePort
	if c.RemotePortEnd > c.RemotePort {
		cEnd = c.RemotePortEnd
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, name, protocol, local_ip, local_port, remote_port, preserve_source_ip, enabled, created_at, domains, path_prefix, offline_page, ip_sources, trusted_proxies, tls_mode, tls_cert, tls_key, redirect_https, strip_prefix, host_rewrite, req_headers, resp_headers, basic_auth, ip_allow, not_found_page, guard_allow, guard_deny, max_conns_per_ip, conn_rate_per_min, bandwidth_kbps, backends, lb_strategy, proxy_protocol, remote_port_end
		 FROM rules WHERE remote_port <= ? AND MAX(remote_port, remote_port_end) >= ? AND id != ?`, cEnd, c.RemotePort, c.ID)
	if err != nil {
		return nil, fmt.Errorf("store: check rule conflict: %w", err)
	}
	defer rows.Close()
	existing, err := scanRules(rows)
	if err != nil {
		return nil, err
	}
	for i := range existing {
		e := existing[i]
		if rulesConflict(c, e) {
			return &e, nil
		}
	}
	return nil, nil
}

func usesTCP(proto string) bool {
	return proto == "tcp" || proto == "tcp+udp" || proto == "http" || proto == "tls"
}
func usesUDP(proto string) bool { return proto == "udp" || proto == "tcp+udp" }

// domainsOverlap 报告两组域名是否重叠：两者都为空（都是兜底）或有相同域名。
func domainsOverlap(a, b string) bool {
	da, db := SplitDomains(a), SplitDomains(b)
	if len(da) == 0 || len(db) == 0 {
		return len(da) == 0 && len(db) == 0
	}
	set := make(map[string]bool, len(da))
	for _, d := range da {
		set[d] = true
	}
	for _, d := range db {
		if set[d] {
			return true
		}
	}
	return false
}

func rulesConflict(a, b Rule) bool {
	// TLS 透传规则之间可按 SNI 域名共享端口；与其它 TCP 类规则（含 HTTP）不能共用端口。
	if a.Protocol == "tls" && b.Protocol == "tls" {
		return domainsOverlap(a.Domains, b.Domains)
	}
	if a.Protocol == "http" && b.Protocol == "http" {
		// 同一端口要么全部是 HTTPS（终止 TLS），要么全部是明文 HTTP。
		if (a.TLSMode != "") != (b.TLSMode != "") {
			return true
		}
		if NormalizePathPrefix(a.PathPrefix) != NormalizePathPrefix(b.PathPrefix) {
			return false
		}
		da, db := SplitDomains(a.Domains), SplitDomains(b.Domains)
		if len(da) == 0 || len(db) == 0 {
			return len(da) == 0 && len(db) == 0
		}
		set := make(map[string]bool, len(da))
		for _, d := range da {
			set[d] = true
		}
		for _, d := range db {
			if set[d] {
				return true
			}
		}
		return false
	}
	return (usesTCP(a.Protocol) && usesTCP(b.Protocol)) || (usesUDP(a.Protocol) && usesUDP(b.Protocol))
}

// SplitDomains 将逗号/空白分隔的域名列表规范化（小写、去空、去重、去末尾点）。
func SplitDomains(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';'
	})
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(f)), ".")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// NormalizePathPrefix 规范化路径前缀：保证以 "/" 开头，去掉末尾的 "/"（根路径除外）。
func NormalizePathPrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

func scanRule(row *sql.Row) (Rule, error) {
	var r Rule
	var preserve, enabled int
	var createdAt int64
	err := row.Scan(&r.ID, &r.ClientID, &r.Name, &r.Protocol, &r.LocalIP, &r.LocalPort, &r.RemotePort, &preserve, &enabled, &createdAt, &r.Domains, &r.PathPrefix, &r.OfflinePage, &r.IPSources, &r.TrustedProxies, &r.TLSMode, &r.TLSCert, &r.TLSKey, &r.RedirectHTTPS, &r.StripPrefix, &r.HostRewrite, &r.ReqHeaders, &r.RespHeaders, &r.BasicAuth, &r.IPAllow, &r.NotFoundPage, &r.GuardAllow, &r.GuardDeny, &r.MaxConnsPerIP, &r.ConnRatePerMin, &r.BandwidthKBps, &r.Backends, &r.LBStrategy, &r.ProxyProtocol, &r.RemotePortEnd)
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
		if err := rows.Scan(&r.ID, &r.ClientID, &r.Name, &r.Protocol, &r.LocalIP, &r.LocalPort, &r.RemotePort, &preserve, &enabled, &createdAt, &r.Domains, &r.PathPrefix, &r.OfflinePage, &r.IPSources, &r.TrustedProxies, &r.TLSMode, &r.TLSCert, &r.TLSKey, &r.RedirectHTTPS, &r.StripPrefix, &r.HostRewrite, &r.ReqHeaders, &r.RespHeaders, &r.BasicAuth, &r.IPAllow, &r.NotFoundPage, &r.GuardAllow, &r.GuardDeny, &r.MaxConnsPerIP, &r.ConnRatePerMin, &r.BandwidthKBps, &r.Backends, &r.LBStrategy, &r.ProxyProtocol, &r.RemotePortEnd); err != nil {
			return nil, fmt.Errorf("store: scan rule: %w", err)
		}
		r.PreserveSourceIP = preserve != 0
		r.Enabled = enabled != 0
		r.CreatedAt = time.Unix(createdAt, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- 保留端口 ----------------------------------------------------

// ReservedPorts 返回运维者（或安装程序，它会自动检测当前 SSH 端口）标记为
// 面板禁止使用的端口集合。CreateRule/UpdateRule 的调用方在接受
// remote_port 之前必须检查此集合——参见 docs/03-product-design.md 中的
// “软性默认拒绝”设计：无论面板/API 收到什么请求，Server 都绝不会打开保留
// 端口，这是防止管理员误操作、创建与 SSH 或云主机上其他已运行服务冲突的
// 规则的安全网。
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

// AddReservedPort 将一个端口标记为保留（永远不能通过规则转发）。
// 幂等：重复添加同一端口只会更新其原因。
func (s *Store) AddReservedPort(ctx context.Context, port uint16, reason string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO reserved_ports (port, reason) VALUES (?, ?) ON CONFLICT(port) DO UPDATE SET reason = excluded.reason`,
		port, reason)
	if err != nil {
		return fmt.Errorf("store: add reserved port: %w", err)
	}
	return nil
}

// RemoveReservedPort 取消某个端口的保留（面板运维者的手动覆盖，用于自动
// 检测出的保留有误的少数情况）。
func (s *Store) RemoveReservedPort(ctx context.Context, port uint16) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM reserved_ports WHERE port = ?`, port)
	if err != nil {
		return fmt.Errorf("store: remove reserved port: %w", err)
	}
	return nil
}

// --- 辅助函数 ---------------------------------------------------------------

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
