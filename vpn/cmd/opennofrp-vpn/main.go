package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
	"opennofrp/pkg/crypto/tlsutil"
	"opennofrp/pkg/protocol"
	"opennofrp/pkg/tempvpn"
	"opennofrp/pkg/version"
	"opennofrp/vpn/internal/hosts"
	"opennofrp/vpn/internal/network"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(version.String("opennofrp-vpn"))
		return
	}
	file := flag.String("config", "opennofrp-vpn.json", "从面板下载的临时 VPN 配置文件")
	host := flag.String("host", "", "可选 HOST 别名，例如 local；多个用逗号分隔，覆盖配置中的 hosts")
	verbose := flag.Bool("verbose", false, "显示目标端口连接诊断日志")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *file, *host, *verbose); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "临时 VPN 已断开：", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, path, hostOverride string, verbose bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) > 16<<10 {
		return fmt.Errorf("配置文件过大")
	}
	var config tempvpn.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	if hostOverride != "" {
		config.Hosts = strings.Split(hostOverride, ",")
	}
	config.Hosts, err = tempvpn.NormalizeHosts(config.Hosts)
	if err != nil {
		return err
	}
	if len(tlsutil.NormalizeFingerprint(config.Fingerprint)) != 64 || !strings.HasPrefix(config.Token, "onfr_vpn_") || config.ExpiresAt <= time.Now().Unix() {
		return fmt.Errorf("配置无效或已过期，请重新从面板创建临时 VPN")
	}
	serverHost, _, err := net.SplitHostPort(config.Server)
	if err != nil {
		return fmt.Errorf("服务端地址无效：%w", err)
	}
	for _, name := range config.Hosts {
		if strings.EqualFold(strings.TrimSuffix(serverHost, "."), name) {
			return fmt.Errorf("HOST 别名不能与服务端控制地址相同")
		}
	}
	deadlineCtx, cancel := context.WithDeadline(ctx, time.Unix(config.ExpiresAt, 0))
	defer cancel()
	raw, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(deadlineCtx, "tcp", config.Server)
	if err != nil {
		return err
	}
	defer raw.Close()
	stopClose := context.AfterFunc(deadlineCtx, func() { raw.Close() })
	defer stopClose()
	conn := tls.Client(raw, tlsutil.NewClientTLSConfig(config.Fingerprint, nil))
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := conn.HandshakeContext(deadlineCtx); err != nil {
		return err
	}
	if err := protocol.WriteJSONMessage(conn, protocol.VPNHandshake{Type: protocol.MsgVPNHandshake, ProtocolVersion: protocol.ProtocolVersion, Token: config.Token}); err != nil {
		return err
	}
	var response protocol.VPNHandshakeResponse
	if err := protocol.ReadJSONMessage(conn, &response); err != nil {
		return err
	}
	if !response.OK {
		return fmt.Errorf("%s", response.Error)
	}
	if response.VirtualIP != "10.203.0.1" || response.ExpiresAt <= time.Now().Unix() {
		return fmt.Errorf("服务端返回的 VPN 配置无效")
	}
	conn.SetDeadline(time.Time{})
	ymConfig := yamux.DefaultConfig()
	ymConfig.StreamOpenTimeout = 15 * time.Second
	ym, err := yamux.Client(conn, ymConfig)
	if err != nil {
		return err
	}
	defer ym.Close()
	device, cleanup, err := network.OpenDevice()
	if err != nil {
		return err
	}
	defer cleanup()
	cleanupHosts, err := hosts.Install(config.Hosts, response.VirtualIP)
	if err != nil {
		return err
	}
	defer func() {
		if err := cleanupHosts(); err != nil {
			fmt.Fprintln(os.Stderr, "清理 HOST 映射失败，请检查系统 hosts 文件：", err)
		}
	}()
	if len(config.Hosts) > 0 {
		fmt.Printf("HOST 映射：%s -> %s\n", strings.Join(config.Hosts, ", "), response.VirtualIP)
	}
	runCtx, stopRun := context.WithDeadline(deadlineCtx, time.Unix(response.ExpiresAt, 0))
	defer stopRun()
	go func() {
		select {
		case <-ym.CloseChan():
			stopRun()
		case <-runCtx.Done():
		}
	}()
	stopSession := context.AfterFunc(runCtx, func() { ym.Close() })
	defer stopSession()
	fmt.Printf("临时 VPN 已连接。访问 10.203.0.1:<原端口> 即访问目标机器的 127.0.0.1:<原端口>。\n支持 TCP / UDP；到期或按 Ctrl+C 后断开。有效至 %s\n", time.Unix(response.ExpiresAt, 0).Local().Format(time.RFC3339))
	dial := func(ctx context.Context, kind string, port uint16) (result net.Conn, dialErr error) {
		if verbose {
			fmt.Fprintf(os.Stderr, "收到 VPN 端口请求：%s 127.0.0.1:%d\n", kind, port)
		}
		defer func() {
			if dialErr != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "连接目标 127.0.0.1:%d (%s) 失败：%v\n", port, kind, dialErr)
			} else if verbose && dialErr == nil {
				fmt.Fprintf(os.Stderr, "目标端口已连接：%s 127.0.0.1:%d\n", kind, port)
			}
		}()
		stream, err := ym.Open()
		if err != nil {
			return nil, err
		}
		stream.SetDeadline(time.Now().Add(15 * time.Second))
		if err := protocol.WriteJSONMessage(stream, protocol.VPNDialRequest{Network: kind, Port: port}); err != nil {
			stream.Close()
			return nil, err
		}
		var ack [1]byte
		if _, err := io.ReadFull(stream, ack[:]); err != nil {
			stream.Close()
			return nil, err
		}
		if ack[0] != protocol.DialAckOK {
			stream.Close()
			return nil, fmt.Errorf("目标端口不可用")
		}
		stream.SetDeadline(time.Time{})
		return stream, nil
	}
	err = network.Run(runCtx, device, netip.MustParseAddr(response.VirtualIP), dial)
	if deadlineCtx.Err() != nil {
		return deadlineCtx.Err()
	}
	if ym.IsClosed() {
		return fmt.Errorf("服务端连接关闭，临时凭据可能已到期、被撤销或目标机器已离线")
	}
	return err
}
