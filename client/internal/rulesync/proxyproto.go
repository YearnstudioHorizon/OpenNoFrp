package rulesync

// Proxy Protocol（HAProxy PROXY 协议 v1/v2）：规则开启后，Client 在拨通本地后端之后、
// 转发任何数据之前，先向后端写入一个 PROXY 头，携带访问者的真实源地址
// （StreamMetadata.ClientAddr/ClientPort）。适用于无法使用源地址伪装（TPROXY）的
// 场景，后端（nginx、HAProxy、Traefik 等）需相应开启 proxy_protocol 支持。
// 目标地址使用 Client 实际拨号的后端地址。

import (
	"encoding/binary"
	"fmt"
	"net"

	"opennofrp/pkg/protocol"
)

// proxyV2Signature 是 PROXY 协议 v2 的固定 12 字节签名。
var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// buildProxyHeader 构造 PROXY 协议头。version 为 1 或 2；src/dst 为空时 v1 输出
// "PROXY UNKNOWN"，v2 输出 LOCAL 命令。
func buildProxyHeader(version int, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) ([]byte, error) {
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("proxy protocol: unsupported version %d", version)
	}
	valid := srcIP != nil && dstIP != nil && !srcIP.IsUnspecified()
	src4, dst4 := srcIP.To4(), dstIP.To4()
	both4 := src4 != nil && dst4 != nil

	if version == 1 {
		if !valid {
			return []byte("PROXY UNKNOWN\r\n"), nil
		}
		if both4 {
			return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", src4, dst4, srcPort, dstPort)), nil
		}
		return []byte(fmt.Sprintf("PROXY TCP6 %s %s %d %d\r\n", ipv6Text(srcIP), ipv6Text(dstIP), srcPort, dstPort)), nil
	}

	hdr := append([]byte(nil), proxyV2Signature...)
	if !valid {
		// 版本 2 + LOCAL 命令，无地址信息。
		return append(hdr, 0x20, 0x00, 0x00, 0x00), nil
	}
	var fam byte
	var addrs []byte
	if both4 {
		fam = 0x11 // AF_INET + STREAM
		addrs = append(append([]byte{}, src4...), dst4...)
	} else {
		fam = 0x21 // AF_INET6 + STREAM
		addrs = append(append([]byte{}, srcIP.To16()...), dstIP.To16()...)
	}
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports[0:2], srcPort)
	binary.BigEndian.PutUint16(ports[2:4], dstPort)
	addrs = append(addrs, ports...)
	hdr = append(hdr, 0x21, fam) // 版本 2 + PROXY 命令
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(addrs)))
	hdr = append(hdr, lenBuf...)
	return append(hdr, addrs...), nil
}

// ipv6Text 以 IPv6 文本形式输出地址；IPv4 地址输出为 ::ffff:a.b.c.d。
func ipv6Text(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return "::ffff:" + v4.String()
	}
	return ip.String()
}

// writeProxyHeader 在规则开启 Proxy Protocol 时向 upstream 写入 PROXY 头。
func writeProxyHeader(rule protocol.Rule, meta protocol.StreamMetadata, upstream net.Conn) error {
	if rule.ProxyProtocol == 0 {
		return nil
	}
	var dstIP net.IP
	var dstPort uint16
	if ta, ok := upstream.RemoteAddr().(*net.TCPAddr); ok {
		dstIP, dstPort = ta.IP, uint16(ta.Port)
	} else {
		dstIP, dstPort = net.ParseIP(rule.LocalIP), rule.LocalPort
	}
	hdr, err := buildProxyHeader(rule.ProxyProtocol, meta.ClientAddr, meta.ClientPort, dstIP, dstPort)
	if err != nil {
		return err
	}
	_, err = upstream.Write(hdr)
	return err
}

// relayUpstream 在拨通后端后先写入 PROXY 头（若开启），再双向中继。
func (r *Reconciler) relayUpstream(rule protocol.Rule, meta protocol.StreamMetadata, stream, upstream net.Conn) {
	if err := writeProxyHeader(rule, meta, upstream); err != nil {
		r.Logger.Warn("failed to write proxy protocol header, dropping", "rule", rule.Name, "error", err)
		return
	}
	relay(stream, upstream)
}
