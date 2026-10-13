package network

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Diagnostics record packet headers and byte counts, never application payloads.
type packetTrace struct {
	log   func(string, ...any)
	count atomic.Uint32
}

func newPacketTrace(log func(string, ...any)) *packetTrace {
	return &packetTrace{log: log}
}

func (t *packetTrace) packet(direction string, data []byte) {
	if t.log == nil {
		return
	}
	n := t.count.Add(1)
	if n > 128 {
		return
	}
	if n == 128 {
		t.log("包头诊断达到 128 条上限，后续仍记录连接与转发状态")
	}
	if len(data) < 20 || data[0]>>4 != 4 {
		return
	}
	i := int(data[0]&15) * 4
	if i < 20 || i > len(data) {
		return
	}
	src := netip.AddrFrom4([4]byte{data[12], data[13], data[14], data[15]})
	dst := netip.AddrFrom4([4]byte{data[16], data[17], data[18], data[19]})
	if data[9] != 6 || len(data)-i < 20 {
		t.log("%s %s -> %s protocol=%d bytes=%d", direction, src, dst, data[9], len(data))
		return
	}
	b := data[i:]
	t.log("%s TCP %s:%d -> %s:%d flags=0x%02x seq=%d ack=%d bytes=%d", direction, src, binary.BigEndian.Uint16(b[:2]), dst, binary.BigEndian.Uint16(b[2:4]), b[13], binary.BigEndian.Uint32(b[4:8]), binary.BigEndian.Uint32(b[8:12]), len(data))
}

type diagnosticConn struct {
	net.Conn
	log                   func(string, ...any)
	flow                  string
	readOnce, writeOnce   sync.Once
	readBytes, writeBytes atomic.Int64
}

func (c *diagnosticConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.readBytes.Add(int64(n))
		c.readOnce.Do(func() { c.log("TCP 收到本机数据：%s，%d 字节", c.flow, n) })
	}
	return n, err
}

func (c *diagnosticConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.writeBytes.Add(int64(n))
		c.writeOnce.Do(func() { c.log("TCP 收到目标响应：%s，%d 字节", c.flow, n) })
	}
	return n, err
}

func (c *diagnosticConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}
