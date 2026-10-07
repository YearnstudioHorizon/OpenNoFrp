// Package protocol 定义了 OpenNoFrp Server（云端、不受信任的网络环境、纯用户态）
// 与 OpenNoFrp Client（本地、受控机器、使用 TPROXY）之间的私有线路协议。
//
// 设计目标：
//   - Server 永远不需要理解目标服务的协议。它只转发原始字节，外加一个描述
//     原始客户端地址的小型元数据帧。
//   - 本协议不是 Proxy Protocol v1/v2，也不需要目标服务理解它。只有
//     OpenNoFrp Client 会解析它。
//   - 每个逻辑上的转发连接（TCP）或 UDP 流都作为控制连接上的一个 yamux 流
//     承载。元数据帧总是新打开的流上发送的第一个内容，位于任何负载字节
//     之前。
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// ProtocolVersion 在线路格式发生不向后兼容的变更时递增。Client 与 Server 会在
// 握手期间交换该值，若不匹配则拒绝继续。
const ProtocolVersion uint8 = 1

// TransportKind 标识被转发的流是 TCP 还是 UDP。
type TransportKind uint8

const (
	TransportTCP TransportKind = 1
	TransportUDP TransportKind = 2
)

func (t TransportKind) String() string {
	switch t {
	case TransportTCP:
		return "tcp"
	case TransportUDP:
		return "udp"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// StreamMetadata 是 Server 向 Client 打开的每个新 yamux 流上发送的第一帧。它告诉
// Client 在连接本地真实服务时透明地重建原始客户端身份所需的全部信息。
//
// Client 使用 RuleID（而不是端口号）来查找该连接属于哪条本地已知的规则。本协议
// 的早期版本为此使用原始的远程端口号，但在规则管理迁移到 Server 的数据库之后
// （参见 docs/03-product-design.md），规则由其数据库行 ID 标识；在 Client 连接
// 进行中规则被编辑（例如面板管理员修改了 remote_port）时，这是唯一保证稳定不变
// 的值。
//
// 线路格式（所有整数均为大端序）：
//
//	byte    0       : ProtocolVersion
//	byte    1       : TransportKind（1=tcp，2=udp）
//	byte    2       : 原始客户端地址族（4 = IPv4，6 = IPv6）
//	bytes   3..19   : 原始客户端 IP，左侧以零填充
//	                  （IPv4 使用 4 字节，IPv6 使用 16 字节）
//	bytes   19..21  : 原始客户端端口（uint16）
//	bytes   21..25  : RuleID（uint32）——标识该连接属于 Client 当前生效的
//	                  规则（来自最近一次 RulesSnapshot）中的哪一条
//	byte    25      : flags（保留，目前必须为 0）
//	bytes   26..28  : 尾部变长区段的长度（uint16），
//	                  目前始终为 0，保留用于未来扩展
//	                  （例如 SNI 提示），而不会破坏固定头部
type StreamMetadata struct {
	Transport  TransportKind
	ClientAddr net.IP
	ClientPort uint16
	RuleID     uint32
}

const fixedHeaderLen = 28

// Encode 将元数据序列化为固定长度的线路头部。
func (m StreamMetadata) Encode() ([]byte, error) {
	buf := make([]byte, fixedHeaderLen)
	buf[0] = ProtocolVersion
	buf[1] = byte(m.Transport)

	ip4 := m.ClientAddr.To4()
	if ip4 != nil {
		buf[2] = 4
		copy(buf[3:7], ip4)
	} else {
		ip6 := m.ClientAddr.To16()
		if ip6 == nil {
			return nil, errors.New("protocol: invalid ClientAddr")
		}
		buf[2] = 6
		copy(buf[3:19], ip6)
	}

	binary.BigEndian.PutUint16(buf[19:21], m.ClientPort)
	binary.BigEndian.PutUint32(buf[21:25], m.RuleID)
	buf[25] = 0                               // flags 保留
	binary.BigEndian.PutUint16(buf[26:28], 0) // 暂无尾部区段

	return buf, nil
}

// WriteHeader 将编码后的元数据帧写入 w。Server 在打开新的 yamux 流之后、转发任何
// 负载字节之前调用此函数。
//
// （有意不命名为 WriteTo：该名称暗示 io.WriterTo 接口签名
// `WriteTo(io.Writer) (int64, error)`，而本函数并非如此——它写入的是一个小的
// 固定长度头部，而不是长度未知的数据流。）
func (m StreamMetadata) WriteHeader(w io.Writer) error {
	buf, err := m.Encode()
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// ReadStreamMetadata 从 r 读取并解码一个元数据帧。Client 在每个新接受的 yamux 流上
// 进行的第一次读取就是调用此函数。
func ReadStreamMetadata(r io.Reader) (StreamMetadata, error) {
	var m StreamMetadata

	header := make([]byte, fixedHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return m, fmt.Errorf("protocol: read header: %w", err)
	}

	version := header[0]
	if version != ProtocolVersion {
		return m, fmt.Errorf("protocol: version mismatch: got %d, want %d", version, ProtocolVersion)
	}

	m.Transport = TransportKind(header[1])
	if m.Transport != TransportTCP && m.Transport != TransportUDP {
		return m, fmt.Errorf("protocol: unknown transport kind %d", header[1])
	}

	switch header[2] {
	case 4:
		m.ClientAddr = net.IP(append([]byte(nil), header[3:7]...))
	case 6:
		m.ClientAddr = net.IP(append([]byte(nil), header[3:19]...))
	default:
		return m, fmt.Errorf("protocol: unknown address family %d", header[2])
	}

	m.ClientPort = binary.BigEndian.Uint16(header[19:21])
	m.RuleID = binary.BigEndian.Uint32(header[21:25])

	trailingLen := binary.BigEndian.Uint16(header[26:28])
	if trailingLen > 0 {
		// 保留供将来使用；读出并丢弃，使尚不理解该扩展的 Client 仍能保持
		// 流的对齐。
		if _, err := io.CopyN(io.Discard, r, int64(trailingLen)); err != nil {
			return m, fmt.Errorf("protocol: discard trailing section: %w", err)
		}
	}

	return m, nil
}

// ClientAddrPort 以类似 net.Addr 的字符串形式返回原始客户端地址，便于记录日志。
func (m StreamMetadata) ClientAddrPort() string {
	return net.JoinHostPort(m.ClientAddr.String(), fmt.Sprint(m.ClientPort))
}
