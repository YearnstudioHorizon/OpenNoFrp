// Package protocol defines the private wire protocol between OpenNoFrp
// Server (cloud, untrusted network environment, pure userspace) and
// OpenNoFrp Client (local, controlled machine, uses TPROXY).
//
// Design goals:
//   - Server never needs to understand anything about the target service's
//     protocol. It only forwards raw bytes plus a small metadata frame that
//     describes the original client's address.
//   - This protocol is NOT Proxy Protocol v1/v2 and does not need the target
//     service to understand it. Only the OpenNoFrp Client parses it.
//   - Every logical forwarded connection (TCP) or UDP flow is carried as one
//     yamux stream over the control connection. The metadata frame is always
//     the first thing sent on a freshly opened stream, before any payload
//     bytes.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// ProtocolVersion is bumped whenever the wire format changes in a
// backwards-incompatible way. Client and Server exchange this during the
// handshake and refuse to proceed on mismatch.
const ProtocolVersion uint8 = 1

// TransportKind identifies whether the forwarded flow is TCP or UDP.
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

// StreamMetadata is the first frame sent on every new yamux stream opened by
// the Server towards the Client. It tells the Client everything it needs to
// transparently re-create the original client's identity when connecting to
// the local real service.
//
// RuleID (not a port number) is what the Client uses to look up which
// locally-known rule this connection belongs to. Earlier revisions of this
// protocol used the raw remote port number for this purpose, but once rule
// management moved into the Server's database (see docs/03-product-design.md)
// rules are identified by their database row ID, which is the only value
// guaranteed stable across a rule being edited (e.g. remote_port changed by
// the panel operator) while a Client is mid-connection.
//
// Wire format (all integers big-endian):
//
//	byte    0       : ProtocolVersion
//	byte    1       : TransportKind (1=tcp, 2=udp)
//	byte    2       : original client address family (4 = IPv4, 6 = IPv6)
//	bytes   3..19   : original client IP, left-padded with zeros
//	                  (4 bytes used for IPv4, 16 bytes for IPv6)
//	bytes   19..21  : original client port (uint16)
//	bytes   21..25  : RuleID (uint32) -- identifies which of the Client's
//	                  currently-active rules (from the last RulesSnapshot)
//	                  this connection belongs to
//	byte    25      : flags (reserved, must be 0 for now)
//	bytes   26..28  : length of trailing variable-length section (uint16),
//	                  currently always 0, reserved for future extensions
//	                  (e.g. SNI hints) without breaking the fixed header
type StreamMetadata struct {
	Transport  TransportKind
	ClientAddr net.IP
	ClientPort uint16
	RuleID     uint32
}

const fixedHeaderLen = 28

// Encode serializes the metadata into the fixed-size wire header.
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
	buf[25] = 0                                // flags reserved
	binary.BigEndian.PutUint16(buf[26:28], 0) // no trailing section yet

	return buf, nil
}

// WriteHeader writes the encoded metadata frame to w. This is the function
// the Server calls right after opening a new yamux stream, before relaying
// any payload bytes.
//
// (Deliberately not named WriteTo: that name implies the io.WriterTo
// interface signature `WriteTo(io.Writer) (int64, error)`, which this is
// not -- this writes a small fixed-size header, not a stream of unknown
// length.)
func (m StreamMetadata) WriteHeader(w io.Writer) error {
	buf, err := m.Encode()
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// ReadStreamMetadata reads and decodes one metadata frame from r. This is
// the function the Client calls as the very first read on every newly
// accepted yamux stream.
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
		// Reserved for future use; drain and discard so the stream stays
		// aligned for the Client that doesn't understand the extension yet.
		if _, err := io.CopyN(io.Discard, r, int64(trailingLen)); err != nil {
			return m, fmt.Errorf("protocol: discard trailing section: %w", err)
		}
	}

	return m, nil
}

// ClientAddrPort returns the original client's address as a net.Addr-ish
// string, convenient for logging.
func (m StreamMetadata) ClientAddrPort() string {
	return net.JoinHostPort(m.ClientAddr.String(), fmt.Sprint(m.ClientPort))
}
