//go:build darwin

// Command opennofrp-client 是 OpenNoFrp 本地 Client 的入口程序（macOS 版）。
// 与 Linux 版不同：macOS 版不支持基于 TPROXY 的源 IP 保留（开启该选项的规则
// 自动降级为普通转发），也没有 envcheck / tproxy-teardown 子命令；服务由
// launchd（而非 systemd）管理，默认目录遵循 /Library/Application Support 布局。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"opennofrp/client/internal/config"
	"opennofrp/client/internal/controlconn"
	"opennofrp/client/internal/rulesync"
	"opennofrp/pkg/protocol"
	"opennofrp/pkg/tempvpn"
	"opennofrp/pkg/updater"
	"opennofrp/pkg/version"
)

const defaultConfigPath = "/Library/Application Support/OpenNoFrp/client.toml"
const defaultStateDir = "/Library/Application Support/OpenNoFrp"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Println(version.String("opennofrp-client"))
			return
		case "update":
			if err := updater.SelfUpdate(context.Background(), "opennofrp-client"); err != nil {
				fmt.Fprintf(os.Stderr, "更新失败: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("更新完成，如已通过 launchd 运行请执行: launchctl kickstart -k system/org.opennofrp.client")
			return
		case "init-config":
			runInitConfig()
			return
		}
	}

	runClient()
}

func runInitConfig() {
	fs := flag.NewFlagSet("init-config", flag.ExitOnError)
	path := fs.String("path", defaultConfigPath, "where to write the example config")
	fs.Parse(os.Args[2:])

	if err := os.MkdirAll(filepath.Dir(*path), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := config.WriteExampleConfig(*path); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote example config to %s -- set server.addr and server.token, then you're done\n", *path)
}

func runClient() {
	fs := flag.NewFlagSet("opennofrp-client", flag.ExitOnError)
	configPath := fs.String("c", defaultConfigPath, "path to client.toml")
	stateDir := fs.String("state-dir", defaultStateDir, "directory for runtime state")
	fs.Parse(os.Args[1:])

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	os.Setenv("OPENNOFRP_CLIENT_CONFIG", *configPath)

	rules := rulesync.New(logger, *stateDir)

	if err := os.MkdirAll(*stateDir, 0o755); err != nil {
		logger.Warn("failed to create state dir", "dir", *stateDir, "error", err)
	}

	client := &controlconn.Client{
		Cfg:    cfg,
		Logger: logger,
		OnRules: func(rs []protocol.Rule) {
			rules.Apply(rs)
		},
		Handler:    rules.ServeStream,
		VPNHandler: tempvpn.ServeLoopback,
	}
	// 自更新：下载新二进制后通过 launchctl 重启自身服务（若以 launchd 运行）。
	executable, execErr := os.Executable()
	if execErr == nil {
		executable, execErr = filepath.EvalSymlinks(executable)
	}
	if execErr == nil {
		client.Update = func(ctx context.Context) (updater.Result, error) {
			return updater.SelfUpdateWithResult(ctx, "opennofrp-client")
		}
		client.Restart = func() error { return restartViaLaunchd(executable) }
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("opennofrp-client starting", "config", *configPath)
	client.Run(sigCtx)
	logger.Info("opennofrp-client stopped")
}

// restartViaLaunchd 在更新二进制后重启自身：优先 kickstart launchd 服务
// （LaunchDaemons 系统域）；若以用户代理（LaunchAgents）运行则 kickstart 对应
// GUI 域；两者都不是（手动前台运行）则提示手动重启。
func restartViaLaunchd(executable string) error {
	label := "org.opennofrp.client"
	if _, err := exec.Command("launchctl", "print", "system/"+label).Output(); err == nil {
		return exec.Command("launchctl", "kickstart", "-k", "system/"+label).Run()
	}
	guiTarget := fmt.Sprintf("gui/%d/%s", os.Getuid(), label)
	if _, err := exec.Command("launchctl", "print", guiTarget).Output(); err == nil {
		return exec.Command("launchctl", "kickstart", "-k", guiTarget).Run()
	}
	// 非 launchd 托管（例如手动前台运行）：直接退出进程，让用户自行重启。
	fmt.Println("[opennofrp] updated; not managed by launchd, please restart the client manually")
	os.Exit(0)
	return nil
}
