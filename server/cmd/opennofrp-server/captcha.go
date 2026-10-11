package main

import (
	"context"
	"fmt"
	"os"

	"opennofrp/server/internal/config"
	"opennofrp/server/internal/store"
)

// Local-only recovery for an unavailable provider or incorrect credentials.
func runResetCaptcha() {
	path := defaultConfigPath
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] != "-c" || i+1 >= len(os.Args) {
			fmt.Fprintln(os.Stderr, "用法: opennofrp-server reset-captcha [-c server.toml]")
			os.Exit(1)
		}
		i++
		path = os.Args[i]
	}
	if err := resetCaptcha(path); err != nil {
		fmt.Fprintf(os.Stderr, "重置人机验证失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("登录人机验证已关闭，请登录面板重新配置；管理员密码保持不变。")
}

func resetCaptcha(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(cfg.Server.DBPath); err != nil {
		return err
	}
	st, err := store.Open(cfg.Server.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	s, err := st.CaptchaSettings(context.Background())
	if err != nil {
		return err
	}
	s.Provider = "none"
	return st.SaveCaptchaSettings(context.Background(), s)
}
