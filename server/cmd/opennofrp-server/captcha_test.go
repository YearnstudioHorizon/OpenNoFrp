package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"opennofrp/server/internal/store"
)

func TestResetCaptchaPreservesCredentials(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "server.db")
	cfg := filepath.Join(dir, "server.toml")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAdmin(context.Background(), "admin", "pass1234"); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCaptchaSettings(context.Background(), store.CaptchaSettings{Provider: "geetest", GeetestID: "id", GeetestKey: "key"}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := os.WriteFile(cfg, []byte("[server]\ndb_path = "+strconv.Quote(filepath.ToSlash(db))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := resetCaptcha(cfg); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s, err := st.CaptchaSettings(context.Background())
	if err != nil || s.Provider != "none" || s.GeetestKey != "key" {
		t.Fatal("incorrect recovery", err)
	}
	ok, err := st.VerifyAdmin(context.Background(), "admin", "pass1234")
	if err != nil || !ok {
		t.Fatal("admin credentials changed", err)
	}
}
