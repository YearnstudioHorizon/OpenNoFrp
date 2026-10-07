package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// ControlMessageType 用于区分通过 yamux 控制流（stream 0，在连接建立时打开一次）
// 发送的各类 JSON 控制消息。
// 这里使用 JSON（而不是像 StreamMetadata 那样手写的二进制格式）是有意为之：
// 控制消息频率低、数据量小，因此可读性/可扩展性比二进制编码节省的那几个字节
// 更重要。
type ControlMessageType string

const (
	MsgHandshakeRequest  ControlMessageType = "handshake_request"
	MsgHandshakeResponse ControlMessageType = "handshake_response"
	MsgHeartbeat         ControlMessageType = "heartbeat"
	MsgHeartbeatAck      ControlMessageType = "heartbeat_ack"
	MsgRegisterRequest   ControlMessageType = "register_request"
	MsgRegisterResponse  ControlMessageType = "register_response"
	MsgRulesSnapshot     ControlMessageType = "rules_snapshot"
)

// HandshakeRequest 由 Client 在与 Server 建立控制 TCP 连接后、打开 yamux 会话之前
// 立即发送。
//
// 与最初的设计（单一共享 token + 由 Client 指定端口列表）不同，Client 现在使用
// 每个 Client 独立的身份（ClientID/ClientSecret，通过下文的注册流程一次性签发）
// 进行认证，并且不再请求任何端口——为该 Client 转发哪些端口完全由 Server/面板
// 管理员决定，并在握手成功后通过 RulesSnapshot 推送给 Client。正因如此，
// “只有管理员在面板中启用后才开放端口”才得以实现：Client 无权申请任意远程端口。
type HandshakeRequest struct {
	Type            ControlMessageType `json:"type"`
	ProtocolVersion uint8              `json:"protocol_version"`
	ClientID        string             `json:"client_id"`
	ClientSecret    string             `json:"client_secret"`
	ClientVersion   string             `json:"client_version"`
	// Capabilities 列出该 Client 支持的可选能力（见 Cap* 常量）。旧版 Client 不发送
	// 该字段，Server 据此判定其不支持依赖新能力的规则（例如 HTTP 规则需要
	// CapDialAck），并在面板中提示升级，而不是让访问者等待超时。
	Capabilities []string `json:"capabilities,omitempty"`
}

// Client 能力标识。
const (
	// CapDialAck：支持 StreamMetadata FlagDialAck 拨号确认（HTTP/TLS 规则必需）。
	CapDialAck = "dial_ack"
	// CapSNIHint：支持 StreamMetadata 尾部区段中的 SNI 提示（TLS 透传规则）。
	CapSNIHint = "sni_hint"
	// CapProxyProtocol：支持向后端发送 Proxy Protocol v1/v2 头。
	CapProxyProtocol = "proxy_protocol"
	// CapUDPSpoof：支持 UDP 源 IP 伪装拨号。
	CapUDPSpoof = "udp_spoof"
	// CapPortRange：支持端口段规则（RemotePortEnd/LocalPort 偏移映射）。
	CapPortRange = "port_range"
)

// HasCapability 报告能力列表中是否包含 c。
func HasCapability(caps []string, c string) bool {
	for _, x := range caps {
		if x == c {
			return true
		}
	}
	return false
}

// PortBinding 描述 Server 监听（TCP、UDP 或两者）并转发给 Client 的一个端口。
// 保留它是为了与 RulesSnapshot 中每条规则的传输标志保持线上格式兼容。
type PortBinding struct {
	Port uint16 `json:"port"`
	TCP  bool   `json:"tcp"`
	UDP  bool   `json:"udp"`
}

// HandshakeResponse 是 Server 的应答。它不再携带 AcceptedPorts 列表——Client
// 只能通过 Server 随后立即发送的 RulesSnapshot 消息获知其生效的规则集。
type HandshakeResponse struct {
	Type            ControlMessageType `json:"type"`
	OK              bool               `json:"ok"`
	Error           string             `json:"error,omitempty"`
	ProtocolVersion uint8              `json:"protocol_version"`
	ServerVersion   string             `json:"server_version"`
}

// RegisterRequest 由仅持有一次性注册 token（由面板的“添加客户端”流程新生成，
// 嵌入在一行安装命令中）、尚无持久化 ClientID/ClientSecret 凭据对的 Client 发送。
// 这在每个 Client 的生命周期中只发生一次（安装后首次启动）；Client 会将返回的
// 凭据持久化到本地磁盘，此后的每次连接都使用 HandshakeRequest。
type RegisterRequest struct {
	Type            ControlMessageType `json:"type"`
	ProtocolVersion uint8              `json:"protocol_version"`
	RegisterToken   string             `json:"register_token"`
	ClientVersion   string             `json:"client_version"`
	// Hostname 是尽力提供给面板的显示提示（管理员之后可以重命名该 Client）；
	// 仅供参考，绝不会被用于授权决策。
	Hostname string `json:"hostname"`
}

// RegisterResponse 携带新签发的永久凭据。注册 token 只能使用一次：Server 一旦
// 发放了 ClientID/ClientSecret 凭据对就会将其标记为已使用，因此在首次使用后重放
// 截获的注册命令不会获得第二个身份。
type RegisterResponse struct {
	Type         ControlMessageType `json:"type"`
	OK           bool               `json:"ok"`
	Error        string             `json:"error,omitempty"`
	ClientID     string             `json:"client_id"`
	ClientSecret string             `json:"client_secret"`
}

// RuleProtocol 标识转发规则适用的传输协议。
type RuleProtocol string

const (
	RuleProtocolTCP RuleProtocol = "tcp"
	RuleProtocolUDP RuleProtocol = "udp"
	// RuleProtocolBoth 是双协议规则：Server 在同一公网端口上同时开启 TCP 和 UDP
	// 监听。各个流的元数据中仍然携带 TransportTCP 或 TransportUDP，因此 Client
	// 无需对此做特殊处理。
	RuleProtocolBoth RuleProtocol = "tcp+udp"
	// RuleProtocolHTTP 是 HTTP 反向代理规则：Server 在公网端口上解析 HTTP 请求，
	// 按 Host/路径前缀路由到对应规则（多条 HTTP 规则可共享同一端口），支持
	// WebSocket 升级与 SSE 流式响应。对 Client 而言，每个 HTTP 请求连接仍以
	// TransportTCP 流的形式到达，按普通 TCP 规则拨号本地服务即可。
	RuleProtocolHTTP RuleProtocol = "http"
	// RuleProtocolTLS 是 TLS 透传规则：Server 只窥探访问者 ClientHello 中的 SNI，
	// 按域名路由到对应规则（多条 TLS 规则可共享同一端口），不解密流量；证书由
	// 内网后端自己持有。对 Client 而言仍是 TransportTCP 流（带 FlagDialAck 与
	// SNI 提示），按普通 TCP 规则拨号本地服务即可。
	RuleProtocolTLS RuleProtocol = "tls"
)

// Rule 是由 Server 推送给 Client 的一条转发规则。它是由 Server 掌控的、关于
// “该 Client 此刻应当做什么”的权威描述——Client 自身已不再有本地规则配置
// （参见 docs/01-architecture.md 和 docs/03-product-design.md）。
type Rule struct {
	ID               int64        `json:"id"`
	Name             string       `json:"name"`
	Protocol         RuleProtocol `json:"protocol"`
	LocalIP          string       `json:"local_ip"`
	LocalPort        uint16       `json:"local_port"`
	RemotePort       uint16       `json:"remote_port"`
	PreserveSourceIP bool         `json:"preserve_source_ip"`
	// Backends 是除 LocalIP:LocalPort 之外的额外后端（"ip:port"），为空表示单后端。
	// 旧版 Client 会忽略该字段，仅使用 LocalIP:LocalPort。
	Backends []string `json:"backends,omitempty"`
	// LBStrategy 是多后端选择策略：""/"round_robin" = 轮询，"random" = 随机，
	// "failover" = 按顺序优先使用第一个健康后端。所有策略在拨号失败时都会依次
	// 尝试其余后端；Client 会对多后端规则做周期性 TCP 健康检查并跳过不健康后端。
	LBStrategy string `json:"lb_strategy,omitempty"`
	// ProxyProtocol 为 1 或 2 时，Client 在拨通后端后先写入 PROXY 协议 v1/v2 头，
	// 携带访问者真实源地址；0 表示不发送。需要 Client 声明 CapProxyProtocol。
	ProxyProtocol int `json:"proxy_protocol,omitempty"`
	// RemotePortEnd 非 0 时表示端口段规则：公网端口 RemotePort..RemotePortEnd 依次映射到
	// 本地端口 LocalPort..LocalPort+(RemotePortEnd-RemotePort)。每个连接的偏移通过
	// StreamMetadata.PortOffset 告知 Client。需要 Client 声明 CapPortRange。
	RemotePortEnd uint16 `json:"remote_port_end,omitempty"`
}

// RulesSnapshot 由 Server 推送给已连接的 Client：握手成功后立即推送一次，此后在
// Client 保持连接期间，每当面板管理员为该 Client 添加/编辑/启用/禁用/删除规则时
// 都会再次推送。它始终是该 Client 当前所有已启用（ENABLED）规则的完整快照
// （而非增量）——Client 的 rulesync 协调器会将其与自身当前正在运行的转发器进行
// 比对，并精确地启动/停止发生变化的部分。被禁用的规则不会出现在此列表中；
// Client 完全不需要知道它们的存在。
type RulesSnapshot struct {
	Type  ControlMessageType `json:"type"`
	Rules []Rule             `json:"rules"`
}

// HeartbeatMessage 由 Client 定期发送，用于告知 Server 自己仍然存活。Server 收到后
// 会重置该客户端的超时计时器。配套的客户端看门狗设计参见 docs/02（它关注的是
// 本地部署安全，而不是这个线路层面的心跳）。
type HeartbeatMessage struct {
	Type         ControlMessageType `json:"type"`
	SequenceNum  uint64             `json:"seq"`
	UnixTimeNano int64              `json:"unix_time_nano"`
}

type HeartbeatAck struct {
	Type        ControlMessageType `json:"type"`
	SequenceNum uint64             `json:"seq"`
}

// WriteJSONMessage 向 w 写入一条带长度前缀的 JSON 消息。控制流上的所有控制消息
// 都使用这种分帧方式：4 字节大端序长度前缀，后跟相应字节数的 JSON。这样就无需
// 使用可能意外预读到流数据中的 JSON 流式解码器（当控制流与 yamux 多路复用时
// 这一点很重要，不过在当前设计中控制消息位于专用的 stream 0 上，因此这主要是
// 纵深防御）。
func WriteJSONMessage(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("protocol: marshal control message: %w", err)
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("protocol: control message too large (%d bytes)", len(data))
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("protocol: write length prefix: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("protocol: write payload: %w", err)
	}
	return nil
}

// ReadJSONMessage 从 r 读取一条带长度前缀的 JSON 消息，并将其反序列化到 v 中。
func ReadJSONMessage(r io.Reader, v interface{}) error {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return fmt.Errorf("protocol: read length prefix: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf)
	if n > 1<<20 {
		return fmt.Errorf("protocol: control message too large (%d bytes)", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("protocol: read payload: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("protocol: unmarshal control message: %w", err)
	}
	return nil
}

// PeekMessageType 仅读取原始 JSON 消息中足以确定其 Type 字段的部分，而不会从
// 底层 reader 中永久消费该消息。
// 这是为通用分发循环提供的便捷辅助函数；大多数调用方在静态上就知道接下来应收到
// 哪种消息类型，可以直接调用 ReadJSONMessage。
type typeOnly struct {
	Type ControlMessageType `json:"type"`
}

func PeekType(data []byte) (ControlMessageType, error) {
	var t typeOnly
	if err := json.Unmarshal(data, &t); err != nil {
		return "", err
	}
	return t.Type, nil
}
