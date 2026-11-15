//go:build linux

package rulesync

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildProxyHeaderV1(t *testing.T) {
	cases := []struct {
		src, dst net.IP
		want     string
	}{
		{net.ParseIP("1.2.3.4"), net.ParseIP("127.0.0.1"), "PROXY TCP4 1.2.3.4 127.0.0.1 5555 80\r\n"},
		{net.ParseIP("2001:db8::1"), net.ParseIP("::1"), "PROXY TCP6 2001:db8::1 ::1 5555 80\r\n"},
		{net.ParseIP("1.2.3.4"), net.ParseIP("::1"), "PROXY TCP6 ::ffff:1.2.3.4 ::1 5555 80\r\n"},
		{net.IPv4zero, net.ParseIP("127.0.0.1"), "PROXY UNKNOWN\r\n"},
		{nil, net.ParseIP("127.0.0.1"), "PROXY UNKNOWN\r\n"},
	}
	for _, c := range cases {
		got, err := buildProxyHeader(1, c.src, 5555, c.dst, 80)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Errorf("v1(%v,%v) = %q want %q", c.src, c.dst, got, c.want)
		}
	}
	if _, err := buildProxyHeader(3, nil, 0, nil, 0); err == nil {
		t.Errorf("unsupported version should fail")
	}
}

func TestBuildProxyHeaderV2(t *testing.T) {
	got, err := buildProxyHeader(2, net.ParseIP("1.2.3.4"), 5555, net.ParseIP("10.0.0.1"), 80)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:12], proxyV2Signature) || got[12] != 0x21 || got[13] != 0x11 {
		t.Fatalf("bad v2 prefix: % x", got[:14])
	}
	if n := binary.BigEndian.Uint16(got[14:16]); n != 12 || len(got) != 16+12 {
		t.Fatalf("bad v2 length %d (total %d)", n, len(got))
	}
	if !bytes.Equal(got[16:20], []byte{1, 2, 3, 4}) || !bytes.Equal(got[20:24], []byte{10, 0, 0, 1}) ||
		binary.BigEndian.Uint16(got[24:26]) != 5555 || binary.BigEndian.Uint16(got[26:28]) != 80 {
		t.Errorf("bad v2 address block: % x", got[16:])
	}
	got6, _ := buildProxyHeader(2, net.ParseIP("2001:db8::1"), 1, net.ParseIP("::1"), 2)
	if got6[13] != 0x21 || binary.BigEndian.Uint16(got6[14:16]) != 36 || len(got6) != 16+36 {
		t.Errorf("bad v2 ipv6 header: % x", got6[:16])
	}
	local, _ := buildProxyHeader(2, nil, 0, nil, 0)
	if len(local) != 16 || local[12] != 0x20 {
		t.Errorf("bad v2 LOCAL header: % x", local)
	}
}
