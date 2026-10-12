// Package netrelay relays TCP connections and yamux streams with half-close support.
package netrelay

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// CloseWrite sends EOF without discarding data still arriving in the reverse direction.
func CloseWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	// In yamux, Close sends FIN while leaving the receive side available.
	if stream, ok := c.(*yamux.Stream); ok {
		return stream.Close()
	}
	return errors.New("connection does not support half-close")
}

// Relay forwards both directions. An error cancels both copies; EOF only closes
// the corresponding write side so the peer can finish its response.
func Relay(a, b net.Conn) error {
	defer a.Close()
	defer b.Close()
	stop := func() {
		// yamux Close alone is a half-close; deadlines also wake blocked readers.
		_ = a.SetDeadline(time.Now())
		_ = b.SetDeadline(time.Now())
		_ = a.Close()
		_ = b.Close()
	}
	done := make(chan error, 2)
	copyDirection := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			err = CloseWrite(dst)
		}
		if err != nil {
			stop()
		}
		done <- err
	}
	go copyDirection(a, b)
	go copyDirection(b, a)
	first, second := <-done, <-done
	if first != nil {
		return first
	}
	return second
}
