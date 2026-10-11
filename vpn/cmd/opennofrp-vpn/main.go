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
	"opennofrp/vpn/internal/network"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(version.String("opennofrp-vpn"))
		return
	}
	file := flag.String("config", "opennofrp-vpn.json", "从面板下载的临时 VPN 配置文件")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *file); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "临时 VPN 已断开：", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, path string) error {
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
	if len(tlsutil.NormalizeFingerprint(config.Fingerprint)) != 64 || !strings.HasPrefix(config.Token, "onfr_vpn_") || config.ExpiresAt <= time.Now().Unix() {
		return fmt.Errorf("配置无效或已过期，请重新从面板创建临时 VPN")
	}
	if _, _, err := net.SplitHostPort(config.Server); err != nil {
		return fmt.Errorf("服务端地址无效：%w", err)
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
	dial := func(ctx context.Context, kind string, port uint16) (net.Conn, error) {
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
