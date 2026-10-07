// Package session 管理一个已连接、已注册的 Client：包括其控制流（上行心跳、
// 下行规则快照）以及 yamux 会话的生命周期。
package session

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"opennofrp/pkg/protocol"
)

// Session 表示一个已连接、已认证的 Client。
type Session struct {
	ID       string // 内部会话 id（随机生成）
	ClientID string // 该会话所属的已注册客户端 id
	Yamux    *yamux.Session
	Logger   *slog.Logger

	mu           sync.Mutex
	lastActivity time.Time
	ctrlStream   net.Conn // 双向控制流：上行心跳，下行快照及确认
}

func New(id, clientID string, ym *yamux.Session, logger *slog.Logger, ctrlStream net.Conn) *Session {
	return &Session{
		ID:           id,
		ClientID:     clientID,
		Yamux:        ym,
		Logger:       logger,
		ctrlStream:   ctrlStream,
		lastActivity: time.Now(),
	}
}

func (s *Session) Touch() {
	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()
}

func (s *Session) IdleFor() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastActivity)
}

// SetControlStream 换入双向控制流（在初始化期间调用一次；若已有旧的控制流，
// 则将其关闭）。
func (s *Session) SetControlStream(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctrlStream != nil && s.ctrlStream != c {
		s.ctrlStream.Close()
	}
	s.ctrlStream = c
}

// PushRulesSnapshot 通过控制流将最新的规则快照转发给该 Client。若控制流已不存在，
// 则不做任何操作；无论如何下一次握手都会重新下发完整快照，因此漏推一次只意味着
// Client 上的规则列表在重新连接前会短暂过时。
func (s *Session) PushRulesSnapshot(rules []protocol.Rule) error {
	s.mu.Lock()
	c := s.ctrlStream
	s.mu.Unlock()
	if c == nil {
		return nil
	}
	return protocol.WriteJSONMessage(c, protocol.RulesSnapshot{
		Type:  protocol.MsgRulesSnapshot,
		Rules: rules,
	})
}

// OpenStreamFor 为一个新接受的公网 TCP 连接向 Client 打开新的 yamux 流，写入
// StreamMetadata 头部（使 Client 知道原始客户端地址以及该连接所属的规则），
// 然后双向转发字节，直到任意一方关闭。
func (s *Session) OpenStreamFor(publicConn net.Conn, ruleID uint32) error {
	stream, err := s.Yamux.Open()
	if err != nil {
		return fmt.Errorf("session: open yamux stream: %w", err)
	}

	ra := publicConn.RemoteAddr()
	tcpAddr, _ := ra.(*net.TCPAddr)
	if tcpAddr == nil {
		stream.Close()
		return fmt.Errorf("session: public conn has non-TCP remote addr")
	}

	meta := protocol.StreamMetadata{
		Transport:  protocol.TransportTCP,
		ClientAddr: tcpAddr.IP,
		ClientPort: uint16(tcpAddr.Port),
		RuleID:     ruleID,
	}
	if err := meta.WriteHeader(stream); err != nil {
		stream.Close()
		return fmt.Errorf("session: write stream metadata: %w", err)
	}

	s.Touch()
	go relay(publicConn, stream, s.Logger)
	return nil
}

// OpenUDPStream 为一个 UDP “流”（由其源地址标识）打开一个 yamux 流。返回的流以帧的
// 形式承载数据报：每个数据报为 2 字节大端序长度 + 负载。Client 在其本地 UDP
// socket 上使用相同的分帧方式，因此数据报在穿越控制连接时能保留边界。
func (s *Session) OpenUDPStream(remoteAddr *net.UDPAddr, ruleID uint32) (net.Conn, error) {
	stream, err := s.Yamux.Open()
	if err != nil {
		return nil, fmt.Errorf("session: open yamux stream (udp): %w", err)
	}
	meta := protocol.StreamMetadata{
		Transport:  protocol.TransportUDP,
		ClientAddr: remoteAddr.IP,
		ClientPort: uint16(remoteAddr.Port),
		RuleID:     ruleID,
	}
	if err := meta.WriteHeader(stream); err != nil {
		stream.Close()
		return nil, fmt.Errorf("session: write stream metadata: %w", err)
	}
	s.Touch()
	return stream, nil
}

func relay(publicConn net.Conn, stream net.Conn, logger *slog.Logger) {
	defer publicConn.Close()
	defer stream.Close()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go cp(publicConn, stream)
	go cp(stream, publicConn)
	<-done
}
