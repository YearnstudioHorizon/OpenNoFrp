package session

import (
	"context"
	"net"
	"testing"
	"time"

	"opennofrp/pkg/protocol"
)

func TestRequestUpdateCorrelationAndConcurrency(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	b.SetDeadline(time.Now().Add(2 * time.Second))
	s := New("session", "client", nil, nil, a)
	s.Capabilities = []string{protocol.CapSelfUpdate}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		result, err := s.RequestUpdate(ctx)
		if err == nil && (result.Version != "v0.4.2" || result.Status != "restarting") {
			t.Error("incorrect result")
		}
		done <- err
	}()
	var request protocol.ClientUpdateRequest
	if err := protocol.ReadJSONMessage(b, &request); err != nil {
		t.Fatal(err)
	}
	if request.Type != protocol.MsgClientUpdate || request.RequestID == "" {
		t.Fatal("bad command")
	}
	if _, err := s.RequestUpdate(ctx); err == nil {
		t.Fatal("parallel update allowed")
	}
	s.ReceiveUpdateResult(protocol.ClientUpdateResult{RequestID: "wrong", Status: "up_to_date"})
	select {
	case <-done:
		t.Fatal("accepted unrelated result")
	default:
	}
	s.ReceiveUpdateResult(protocol.ClientUpdateResult{RequestID: request.RequestID, Status: "restarting", Version: "v0.4.2"})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s.ReceiveUpdateResult(protocol.ClientUpdateResult{RequestID: request.RequestID, Status: "failed", Error: "restart failed"})
	if s.UpdateRestartError(request.RequestID) != "restart failed" {
		t.Fatal("late restart error lost")
	}
}

func TestUpdateRequiresCapabilityAndTimesOut(t *testing.T) {
	s := New("session", "client", nil, nil, nil)
	if _, err := s.RequestUpdate(context.Background()); err == nil {
		t.Fatal("legacy capability bypass")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s.SetControlStream(a)
	s.Capabilities = []string{protocol.CapSelfUpdate}
	go func() { var request protocol.ClientUpdateRequest; protocol.ReadJSONMessage(b, &request) }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.RequestUpdate(ctx); err == nil {
		t.Fatal("missing timeout")
	}
	s.mu.Lock()
	busy := s.updateResult != nil
	s.mu.Unlock()
	if busy {
		t.Fatal("timeout left update lock set")
	}
}
