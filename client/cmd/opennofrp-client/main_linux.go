//go:build linux

// Command opennofrp-client 是 OpenNoFrp 本地 Client 的入口程序（Linux 版）。
// 经过产品化重构后，其配置被刻意精简为：如何连接 Server，以及首次启动时使用的
// 一次性 token。所有转发规则均由 Server（通过面板管理）经控制连接下发；本进程只需
// 遵照执行即可。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"opennofrp/client/internal/config"
	"opennofrp/client/internal/controlconn"
	"opennofrp/client/internal/envcheck"
	"opennofrp/client/internal/rulesync"
	"opennofrp/pkg/protocol"
	"opennofrp/pkg/tempvpn"
	"opennofrp/pkg/updater"
	"opennofrp/pkg/version"
)

const defaultConfigPath = "/etc/opennofrp-client/client.toml"
const defaultStateDir = "/var/lib/opennofrp-client"

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
			return
		case "envcheck":
			runEnvcheck()
			return
		case "init-config":
			runInitConfig()
			return
		case "tproxy-teardown":
			runTproxyTeardown()
			return
		}
	}

	runClient()
}

func runEnvcheck() {
	report := envcheck.RunAll()
	report.Print()
	if !report.OK() {
		os.Exit(1)
	}
}

func runInitConfig() {
	fs := flag.NewFlagSet("init-config", flag.ExitOnError)
	path := fs.String("path", defaultConfigPath, "where to write the example config")
	fs.Parse(os.Args[2:])

	if err := os.MkdirAll(dirOf(*path), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := config.WriteExampleConfig(*path); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote example config to %s -- set server.addr and server.token, then you're done\n", *path)
}

// runTproxyTeardown 根据持久化的状态文件，移除本 Client 实例所做的全部
// 主机级 TPROXY 规则/路由/sysctl 变更。
func runTproxyTeardown() {
	fs := flag.NewFlagSet("tproxy-teardown", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "directory for TPROXY state")
	fs.Parse(os.Args[2:])

	if err := rulesync.TeardownNetwork(*stateDir); err != nil {
		fmt.Fprintf(os.Stderr, "error during teardown: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("TPROXY state torn down (rules removed, sysctls restored)")
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func runClient() {
	fs := flag.NewFlagSet("opennofrp-client", flag.ExitOnError)
	configPath := fs.String("c", defaultConfigPath, "path to client.toml")
	stateDir := fs.String("state-dir", defaultStateDir, "directory for TPROXY state")
	fs.Parse(os.Args[1:])

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// 除非被 OPENNOFRP_CREDENTIALS 覆盖，controlconn 会在此配置文件所在目录
	// 下解析其凭据文件；这里将该路径发布到环境变量中，使控制连接无需层层
	// 传参即可找到同一个文件。
	os.Setenv("OPENNOFRP_CLIENT_CONFIG", *configPath)

	rules := rulesync.New(logger, *stateDir)
	rules.StrictSourceIP = cfg.Server.StrictSourceIP

	if err := os.MkdirAll(*stateDir, 0700); err != nil {
		logger.Error("create client state directory", "error", err)
		os.Exit(1)
	}
	if err := rulesync.TeardownNetwork(*stateDir); err != nil {
		logger.Error("recover previous client network changes", "error", err)
		os.Exit(1)
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
	// Resolve the path before installation: after atomic replacement Linux may
	// report the old executable as '(deleted)'. Exec keeps PID, arguments and env.
	executable, execErr := os.Executable()
	if execErr == nil {
		executable, execErr = filepath.EvalSymlinks(executable)
	}
	if execErr == nil {
		client.Update = func(ctx context.Context) (updater.Result, error) {
			return updater.SelfUpdateWithResult(ctx, "opennofrp-client")
		}
		client.Restart = func() error {
			if err := syscall.Exec(executable, os.Args, os.Environ()); err != nil {
				return errors.Join(err, updater.RestorePrevious(executable))
			}
			return nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("opennofrp-client starting", "config", *configPath)
	client.Run(sigCtx)
	if err := rules.TeardownNetwork(); err != nil {
		logger.Error("restore original network settings", "error", err)
		os.Exit(1)
	}
	logger.Info("opennofrp-client stopped")
}
