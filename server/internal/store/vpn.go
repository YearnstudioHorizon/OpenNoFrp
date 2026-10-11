package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type TemporaryVPN struct {
	ID                         int64
	ClientID, Name, ClientName string
	CreatedAt, ExpiresAt       time.Time
	Revoked                    bool
}

func VPNTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) CreateTemporaryVPN(ctx context.Context, clientID, name string, ttl time.Duration) (TemporaryVPN, string, error) {
	if ttl < time.Minute || ttl > 24*time.Hour || strings.TrimSpace(name) == "" || len(name) > 120 {
		return TemporaryVPN{}, "", errors.New("invalid temporary VPN settings")
	}
	token, err := randomHex(32)
	if err != nil {
		return TemporaryVPN{}, "", err
	}
	token = "onfr_vpn_" + token
	now := time.Now()
	expires := now.Add(ttl)
	result, err := s.db.ExecContext(ctx, `INSERT INTO temporary_vpn (client_id,name,token_hash,created_at,expires_at) VALUES (?,?,?,?,?)`, clientID, name, VPNTokenHash(token), now.Unix(), expires.Unix())
	if err != nil {
		return TemporaryVPN{}, "", err
	}
	id, err := result.LastInsertId()
	return TemporaryVPN{ID: id, ClientID: clientID, Name: name, CreatedAt: now, ExpiresAt: expires}, token, err
}

func (s *Store) LookupTemporaryVPN(ctx context.Context, hash string) (TemporaryVPN, error) {
	var v TemporaryVPN
	var created, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT id,client_id,name,created_at,expires_at,revoked FROM temporary_vpn WHERE token_hash=? AND revoked=0 AND expires_at>?`, hash, time.Now().Unix()).Scan(&v.ID, &v.ClientID, &v.Name, &created, &expires, &v.Revoked)
	v.CreatedAt = time.Unix(created, 0)
	v.ExpiresAt = time.Unix(expires, 0)
	return v, err
}

func (s *Store) ListTemporaryVPN(ctx context.Context) ([]TemporaryVPN, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT v.id,v.client_id,v.name,v.created_at,v.expires_at,v.revoked,c.name FROM temporary_vpn v JOIN clients c ON c.id=v.client_id ORDER BY v.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []TemporaryVPN{}
	for rows.Next() {
		var v TemporaryVPN
		var created, expires int64
		if err := rows.Scan(&v.ID, &v.ClientID, &v.Name, &created, &expires, &v.Revoked, &v.ClientName); err != nil {
			return nil, err
		}
		v.CreatedAt = time.Unix(created, 0)
		v.ExpiresAt = time.Unix(expires, 0)
		values = append(values, v)
	}
	return values, rows.Err()
}
func (s *Store) RevokeTemporaryVPN(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE temporary_vpn SET revoked=1 WHERE id=?`, id)
	return err
}
