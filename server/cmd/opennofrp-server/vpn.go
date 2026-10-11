package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"opennofrp/pkg/protocol"
	"opennofrp/pkg/tempvpn"
	"opennofrp/server/internal/store"
)

func (s *server) handleVPNConnection(conn net.Conn, raw []byte, sourceIP string) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	var request protocol.VPNHandshake
	fail := func(message string) {
		s.limiter.recordFailure(sourceIP)
		protocol.WriteJSONMessage(conn, protocol.VPNHandshakeResponse{Error: message})
	}
	if json.Unmarshal(raw, &request) != nil || request.ProtocolVersion != protocol.ProtocolVersion || !strings.HasPrefix(request.Token, "onfr_vpn_") || len(request.Token) != 73 {
		fail("临时 VPN 凭据无效或已过期")
		return
	}
	hash := store.VPNTokenHash(request.Token)
	lease, err := s.store.LookupTemporaryVPN(context.Background(), hash)
	if err != nil {
		fail("临时 VPN 凭据无效或已过期")
		return
	}
	target := s.sessionFor(lease.ClientID)
	if target == nil || !target.HasCapability(protocol.CapTemporaryVPN) {
		fail("目标机器离线或 Client 尚不支持临时 VPN")
		return
	}
	if _, busy := s.activeVPN.LoadOrStore(lease.ID, struct{}{}); busy {
		protocol.WriteJSONMessage(conn, protocol.VPNHandshakeResponse{Error: "此临时 VPN 已有连接，请先断开原连接"})
		return
	}
	defer s.activeVPN.Delete(lease.ID)
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := protocol.WriteJSONMessage(conn, protocol.VPNHandshakeResponse{OK: true, VirtualIP: "10.203.0.1", ExpiresAt: lease.ExpiresAt.Unix()}); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	config := yamux.DefaultConfig()
	config.StreamOpenTimeout = 15 * time.Second
	ym, err := yamux.Server(conn, config)
	if err != nil {
		return
	}
	defer ym.Close()
	ctx, cancel := context.WithDeadline(context.Background(), lease.ExpiresAt)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { ym.Close() })
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ym.CloseChan():
				return
			case <-ticker.C:
				_, err := s.store.LookupTemporaryVPN(ctx, hash)
				if err != nil || s.sessionFor(lease.ClientID) == nil {
					cancel()
					return
				}
			}
		}
	}()
	s.limiter.recordSuccess(sourceIP)
	s.logger.Info("temporary VPN connected", "lease_id", lease.ID, "client_id", lease.ClientID, "expires_at", lease.ExpiresAt)
	defer s.logger.Info("temporary VPN disconnected", "lease_id", lease.ID)
	flows := make(chan struct{}, 128)
	for {
		stream, err := ym.AcceptStream()
		if err != nil {
			return
		}
		select {
		case flows <- struct{}{}:
			go func() { defer func() { stream.Close(); <-flows }(); s.serveVPNFlow(ctx, stream, lease.ClientID) }()
		default:
			stream.Close()
		}
	}
}

func (s *server) serveVPNFlow(ctx context.Context, stream net.Conn, clientID string) {
	stream.SetDeadline(time.Now().Add(15 * time.Second))
	var request protocol.VPNDialRequest
	if protocol.ReadJSONMessage(stream, &request) != nil || request.Port == 0 || (request.Network != "tcp" && request.Network != "udp") {
		return
	}
	target := s.sessionFor(clientID)
	if target == nil {
		return
	}
	remote, err := target.OpenVPNStream(request.Network, request.Port)
	if err != nil {
		stream.Write([]byte{protocol.DialAckFailed})
		return
	}
	defer remote.Close()
	if _, err := stream.Write([]byte{protocol.DialAckOK}); err != nil {
		return
	}
	stream.SetDeadline(time.Time{})
	tempvpn.Relay(ctx, stream, remote)
}
