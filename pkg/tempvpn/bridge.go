// Package tempvpn implements private loopback access over authenticated streams.
package tempvpn

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"opennofrp/pkg/protocol"
)

func Relay(ctx context.Context, a, b net.Conn) {
	closeBoth := func() { a.SetDeadline(time.Now()); b.SetDeadline(time.Now()); a.Close(); b.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		if _, err := io.Copy(dst, src); err != nil {
			closeBoth()
			done <- struct{}{}
			return
		}
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

func ReadDatagram(r io.Reader, buf []byte) (int, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n > len(buf) {
		return 0, fmt.Errorf("UDP packet too large")
	}
	_, err := io.ReadFull(r, buf[:n])
	return n, err
}
func WriteDatagram(w io.Writer, data []byte) error {
	if len(data) > 65507 {
		return fmt.Errorf("UDP packet too large")
	}
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(data)))
	if n, err := w.Write(h[:]); err != nil {
		return err
	} else if n != len(h) {
		return io.ErrShortWrite
	}
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

// ServeLoopback never accepts a host supplied by the visitor: the destination
// is fixed to 127.0.0.1, with only the TCP/UDP port selected by the stream.
func ServeLoopback(ctx context.Context, meta protocol.StreamMetadata, stream net.Conn) {
	if meta.VPNPort == 0 || !meta.HasFlag(protocol.FlagTemporaryVPN) || meta.RuleID != 0 {
		return
	}
	network := "tcp"
	if meta.Transport == protocol.TransportUDP {
		network = "udp"
	} else if meta.Transport != protocol.TransportTCP {
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(meta.VPNPort))))
	if err != nil {
		stream.Write([]byte{protocol.DialAckFailed})
		return
	}
	defer conn.Close()
	if _, err := stream.Write([]byte{protocol.DialAckOK}); err != nil {
		return
	}
	if network == "tcp" {
		Relay(ctx, stream, conn)
		return
	}
	RelayDatagrams(ctx, conn, stream)
}

// RelayDatagrams adapts a connected UDP endpoint to the framed stream format.
func RelayDatagrams(ctx context.Context, udpConn, stream net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	closeBoth := func() {
		cancel()
		udpConn.SetDeadline(time.Now())
		stream.SetDeadline(time.Now())
		udpConn.Close()
		stream.Close()
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	done := make(chan struct{}, 2)
	go func() {
		defer func() { closeBoth(); done <- struct{}{} }()
		buf := make([]byte, 65507)
		for {
			udpConn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			if ctx.Err() != nil {
				return
			}
			n, err := udpConn.Read(buf)
			if err != nil {
				return
			}
			if err := WriteDatagram(stream, buf[:n]); err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { closeBoth(); done <- struct{}{} }()
		buf := make([]byte, 65507)
		for {
			stream.SetReadDeadline(time.Now().Add(2 * time.Minute))
			if ctx.Err() != nil {
				return
			}
			n, err := ReadDatagram(stream, buf)
			if err != nil {
				return
			}
			if _, err := udpConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	<-done
	<-done
}
