package store

import (
	"context"
	"database/sql"
	"encoding/json"
)

// CaptchaSettings contains the login verification provider and its credentials.
// Secrets stay in the server database and are never sent to browser templates.
type CaptchaSettings struct {
	Provider        string `json:"provider"`
	FCaptchaURL     string `json:"fcaptcha_url"`
	FCaptchaSiteKey string `json:"fcaptcha_site_key"`
	FCaptchaSecret  string `json:"fcaptcha_secret"`
	GeetestID       string `json:"geetest_id"`
	GeetestKey      string `json:"geetest_key"`
}

func (s *Store) CaptchaSettings(ctx context.Context) (CaptchaSettings, error) {
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM panel_settings WHERE key = 'captcha'`).Scan(&data)
	if err == sql.ErrNoRows {
		return CaptchaSettings{Provider: "none"}, nil
	}
	if err != nil {
		return CaptchaSettings{}, err
	}
	var settings CaptchaSettings
	err = json.Unmarshal([]byte(data), &settings)
	return settings, err
}

func (s *Store) SaveCaptchaSettings(ctx context.Context, settings CaptchaSettings) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO panel_settings (key, value) VALUES ('captcha', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, string(data))
	return err
}
