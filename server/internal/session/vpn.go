package session

import (
	"fmt"
	"io"
	"net"
	"time"

	"opennofrp/pkg/protocol"
)

func (s *Session) OpenVPNStream(network string, port uint16) (net.Conn, error) {
	if port == 0 || !s.HasCapability(protocol.CapTemporaryVPN) || s.Yamux == nil {
		return nil, fmt.Errorf("目标客户端不支持临时 VPN")
	}
	transport := protocol.TransportTCP
	if network == "udp" {
		transport = protocol.TransportUDP
	} else if network != "tcp" {
		return nil, fmt.Errorf("unsupported network")
	}
	stream, err := s.Yamux.Open()
	if err != nil {
		return nil, err
	}
	stream.SetDeadline(time.Now().Add(15 * time.Second))
	meta := protocol.StreamMetadata{Transport: transport, ClientAddr: net.IPv4(127, 0, 0, 1), Flags: protocol.FlagTemporaryVPN | protocol.FlagDialAck, VPNPort: port}
	if err := meta.WriteHeader(stream); err != nil {
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
		return nil, fmt.Errorf("127.0.0.1:%d 服务不可用", port)
	}
	stream.SetDeadline(time.Time{})
	return stream, nil
}
