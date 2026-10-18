//go:build linux

package controlconn

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"opennofrp/pkg/protocol"
	"opennofrp/pkg/updater"
)

func TestRemoteUpdateResultAndRestart(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		result       updater.Result
		err          error
		restart      bool
	}{
		{"already latest", "up_to_date", updater.Result{Version: "v0.4.1"}, nil, false},
		{"download failed", "failed", updater.Result{}, errors.New("download failed"), false},
		{"installed", "restarting", updater.Result{Version: "v0.4.2", Updated: true}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			serverConn.SetDeadline(time.Now().Add(2 * time.Second))
			var restarts atomic.Int32
			restarted := make(chan struct{}, 1)
			client := &Client{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Update: func(context.Context) (updater.Result, error) { return tc.result, tc.err }, Restart: func() error { restarts.Add(1); restarted <- struct{}{}; return nil }}
			ack := make(chan string, 1)
			client.startUpdate(context.Background(), clientConn, "request-1", ack)
			var result protocol.ClientUpdateResult
			if err := protocol.ReadJSONMessage(serverConn, &result); err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.status || result.RequestID != "request-1" || result.Version != tc.result.Version {
				t.Fatalf("unexpected response: %+v", result)
			}
			if tc.restart {
				if restarts.Load() != 0 {
					t.Fatal("restart before acknowledgement")
				}
				ack <- "request-1"
				select {
				case <-restarted:
				case <-time.After(time.Second):
					t.Fatal("no restart after acknowledgement")
				}
			} else if restarts.Load() != 0 {
				t.Fatal("unnecessary restart")
			}
		})
	}
}

func TestRemoteUpdatePreservesHeartbeatAndRuleFlow(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	serverConn.SetDeadline(time.Now().Add(2 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocked := make(chan struct{})
	started := make(chan struct{})
	rules := make(chan struct{}, 1)
	restart := make(chan struct{}, 1)
	client := &Client{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Update: func(context.Context) (updater.Result, error) {
		close(started)
		<-blocked
		return updater.Result{Updated: true, Version: "v0.4.2"}, nil
	}, Restart: func() error { restart <- struct{}{}; return nil }, OnRules: func([]protocol.Rule) { rules <- struct{}{} }}
	go client.rulesLoop(ctx, clientConn)
	if err := protocol.WriteJSONMessage(serverConn, protocol.ClientUpdateRequest{Type: protocol.MsgClientUpdate, RequestID: "first"}); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := protocol.WriteJSONMessage(serverConn, protocol.RulesSnapshot{Type: protocol.MsgRulesSnapshot}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rules:
	case <-time.After(time.Second):
		t.Fatal("update blocked rules stream")
	}
	go func() { _ = client.writeControl(clientConn, protocol.HeartbeatMessage{Type: protocol.MsgHeartbeat}) }()
	var heartbeat protocol.HeartbeatMessage
	if err := protocol.ReadJSONMessage(serverConn, &heartbeat); err != nil || heartbeat.Type != protocol.MsgHeartbeat {
		t.Fatal("update blocked heartbeat", err)
	}
	if err := protocol.WriteJSONMessage(serverConn, protocol.ClientUpdateRequest{Type: protocol.MsgClientUpdate, RequestID: "duplicate"}); err != nil {
		t.Fatal(err)
	}
	var duplicate protocol.ClientUpdateResult
	if err := protocol.ReadJSONMessage(serverConn, &duplicate); err != nil {
		t.Fatal(err)
	}
	if duplicate.Status != "failed" || duplicate.RequestID != "duplicate" {
		t.Fatal("concurrent update accepted")
	}
	close(blocked)
	var result protocol.ClientUpdateResult
	if err := protocol.ReadJSONMessage(serverConn, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "restarting" {
		t.Fatal("wrong update status")
	}
	if err := protocol.WriteJSONMessage(serverConn, protocol.ClientUpdateRequest{Type: protocol.MsgClientUpdateAck, RequestID: "first"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-restart:
	case <-time.After(time.Second):
		t.Fatal("restart ack not processed")
	}
}

func TestRestartFailureIsReported(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	b.SetDeadline(time.Now().Add(2 * time.Second))
	c := &Client{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Update: func(context.Context) (updater.Result, error) {
		return updater.Result{Updated: true, Version: "v0.4.2"}, nil
	}, Restart: func() error { return errors.New("exec failed") }}
	ack := make(chan string, 1)
	ack <- "id"
	c.startUpdate(context.Background(), a, "id", ack)
	var result protocol.ClientUpdateResult
	if err := protocol.ReadJSONMessage(b, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "restarting" {
		t.Fatal("missing installation response")
	}
	if err := protocol.ReadJSONMessage(b, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || result.Version != "v0.4.2" || result.Error == "" {
		t.Fatal("missing restart failure")
	}
}
