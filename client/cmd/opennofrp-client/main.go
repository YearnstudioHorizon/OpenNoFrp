// Command opennofrp-client is the entry point for the OpenNoFrp local
// Client. Its configuration is deliberately minimal after the productization
// refactor: how to reach the Server, and the one-time token used on first
// boot. All forwarding rules come from the Server (panel-managed) over the
// control connection; this process only has to honour them.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"opennofrp/client/internal/config"
	"opennofrp/client/internal/controlconn"
	"opennofrp/client/internal/envcheck"
	"opennofrp/client/internal/rulesync"
	"opennofrp/client/internal/tproxy"
	"opennofrp/pkg/protocol"
)

const defaultConfigPath = "/etc/opennofrp/client.toml"
const defaultStateDir = "/var/lib/opennofrp"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "envcheck" {
		runEnvcheck()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "init-config" {
		runInitConfig()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "tproxy-teardown" {
		runTproxyTeardown()
		return
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

// runTproxyTeardown removes every host-level TPROXY rule/route/sysctl
// change this Client instance has made, based on the persisted state file.
func runTproxyTeardown() {
	fs := flag.NewFlagSet("tproxy-teardown", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "directory for TPROXY state")
	fs.Parse(os.Args[2:])

	mgr := tproxy.Manager{StateDir: *stateDir}
	if err := mgr.Teardown(); err != nil {
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

	// Controlconn resolves its credentials file next to this config path
	// unless OPENNOFRP_CREDENTIALS overrides it; publish the path so the
	// control connection finds the same file without threading args.
	os.Setenv("OPENNOFRP_CLIENT_CONFIG", *configPath)

	rules := rulesync.New(logger, *stateDir)

	st, err := os.Stat(*stateDir)
	if err != nil {
		os.MkdirAll(*stateDir, 0o700)
	}
	_ = st

	client := &controlconn.Client{
		Cfg:    cfg,
		Logger: logger,
		OnRules: func(rs []protocol.Rule) {
			rules.Apply(rs)
		},
		Handler: rules.ServeStream,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("opennofrp-client starting", "config", *configPath)
	client.Run(sigCtx)
	logger.Info("opennofrp-client stopped")
}
