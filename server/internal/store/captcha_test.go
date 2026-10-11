package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCaptchaSettingsPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "captcha.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := st.CaptchaSettings(context.Background())
	if err != nil || s.Provider != "none" {
		t.Fatal("invalid migration default", err)
	}
	want := CaptchaSettings{Provider: "geetest", FCaptchaURL: "https://captcha.example.test", FCaptchaSiteKey: "site", FCaptchaSecret: "secret", GeetestID: "id", GeetestKey: "key"}
	if err := st.SaveCaptchaSettings(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.CaptchaSettings(context.Background())
	if err != nil || got != want {
		t.Fatal("settings did not persist", err)
	}
}
