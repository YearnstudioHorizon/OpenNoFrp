package tempvpn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func TestTempVPNBridgeHTTP(t *testing.T) {
	// 1. Local backend HTTP server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/large" {
			// Write a large body (e.g. 500KB)
			data := bytes.Repeat([]byte("1234567890ABCDEF"), 32*1024)
			w.Write(data)
			return
		}
		fmt.Fprintf(w, "path: %s", r.URL.Path)
	}))
	defer backend.Close()

	backendAddr := backend.Listener.Addr().String()
	_, portStr, err := net.SplitHostPort(backendAddr)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Client <-> Server yamux session
	csA, csB := net.Pipe()
	defer csA.Close()
	defer csB.Close()

	yamuxServerCfg := yamux.DefaultConfig()
	yamuxServerCfg.LogOutput = io.Discard
	yamuxClientCfg := yamux.DefaultConfig()
	yamuxClientCfg.LogOutput = io.Discard

	srvSess, err := yamux.Server(csA, yamuxServerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srvSess.Close()

	cliSess, err := yamux.Client(csB, yamuxClientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cliSess.Close()

	// 3. Visitor VPN <-> Server yamux session
	vsA, vsB := net.Pipe()
	defer vsA.Close()
	defer vsB.Close()

	vpnSrvSess, err := yamux.Server(vsA, yamuxServerCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer vpnSrvSess.Close()

	vpnCliSess, err := yamux.Client(vsB, yamuxClientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer vpnCliSess.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Server-side accept loop from VPN visitor
	go func() {
		for {
			vpnStream, err := vpnSrvSess.AcceptStream()
			if err != nil {
				return
			}
			go func(vStream net.Conn) {
				defer vStream.Close()
				// Server opens stream to client
				cStream, err := srvSess.OpenStream()
				if err != nil {
					return
				}
				defer cStream.Close()
				Relay(ctx, vStream, cStream)
			}(vpnStream)
		}
	}()

	// Client-side accept loop from Server
	go func() {
		for {
			cStream, err := cliSess.AcceptStream()
			if err != nil {
				return
			}
			go func(stream net.Conn) {
				defer stream.Close()
				// Client dials backend
				targetConn, err := net.Dial("tcp", "127.0.0.1:"+portStr)
				if err != nil {
					return
				}
				defer targetConn.Close()
				Relay(ctx, stream, targetConn)
			}(cStream)
		}
	}()

	// Visitor opens stream and connects
	runRequest := func(path string) ([]byte, error) {
		vpnStream, err := vpnCliSess.OpenStream()
		if err != nil {
			return nil, err
		}
		defer vpnStream.Close()

		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n", path)
		if _, err := vpnStream.Write([]byte(req)); err != nil {
			return nil, err
		}

		vpnStream.SetDeadline(time.Now().Add(5 * time.Second))
		return io.ReadAll(vpnStream)
	}

	res1, err := runRequest("/hello")
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	if !bytes.Contains(res1, []byte("path: /hello")) {
		t.Fatalf("unexpected res1: %s", string(res1))
	}

	// Test with http.Client through a custom dialer (simulating how applications connect)
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return vpnCliSess.OpenStream()
			},
		},
		Timeout: 5 * time.Second,
	}

	for i := 0; i < 5; i++ {
		resp, err := httpClient.Get("http://local/hello")
		if err != nil {
			t.Fatalf("httpClient request %d failed: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("httpClient read body %d failed: %v", i, err)
		}
		if !bytes.Contains(body, []byte("path: /hello")) {
			t.Fatalf("unexpected body %d: %s", i, string(body))
		}
	}
}

func TestTempVPNBridgeUDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Local echo UDP server
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := append([]byte("echo:"), buf[:n]...)
			backend.WriteToUDP(resp, addr)
		}
	}()

	backendPort := backend.LocalAddr().(*net.UDPAddr).Port

	// 2. Client side dials backend via UDP and relays datagrams with stream
	streamA, streamB := net.Pipe()
	defer streamA.Close()
	defer streamB.Close()

	clientUDP, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: backendPort})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	go RelayDatagrams(ctx, clientUDP, streamA)

	// 3. Visitor side writes datagrams to streamB and reads them back
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("udp-packet-%d", i)
		if err := WriteDatagram(streamB, []byte(msg)); err != nil {
			t.Fatalf("packet %d write error: %v", i, err)
		}
		buf := make([]byte, 1024)
		n, err := ReadDatagram(streamB, buf)
		if err != nil {
			t.Fatalf("packet %d read error: %v", i, err)
		}
		expected := fmt.Sprintf("echo:udp-packet-%d", i)
		if string(buf[:n]) != expected {
			t.Fatalf("packet %d: got %q, want %q", i, string(buf[:n]), expected)
		}
	}
}
