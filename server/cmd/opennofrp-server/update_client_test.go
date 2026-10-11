package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"opennofrp/pkg/protocol"
	"opennofrp/server/internal/session"
)

func TestClientUpdateChecksReconnectedVersion(t *testing.T) {
	for _, tc := range []struct {
		name, status, newVersion string
		success                  bool
	}{
		{"latest", "up_to_date", "", true},
		{"reconnected", "restarting", "v0.4.2", true},
		{"wrong version", "restarting", "v0.4.1", false},
		{"restart failed", "failed", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			old := session.New("old", "client", nil, nil, a)
			old.Capabilities = []string{protocol.CapSelfUpdate}
			s := &server{sessions: map[string]*session.Session{"client": old}}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				message, err := s.updateClient(ctx, "client")
				if err == nil && message == "" {
					t.Error("missing success notice")
				}
				done <- err
			}()
			var request protocol.ClientUpdateRequest
			if err := protocol.ReadJSONMessage(b, &request); err != nil {
				t.Fatal(err)
			}
			if _, err := s.updateClient(ctx, "client"); err == nil {
				t.Fatal("duplicate task accepted")
			}
			if tc.newVersion != "" {
				s.mu.Lock()
				s.sessions["client"] = &session.Session{ID: "new", ClientID: "client", ClientVersion: tc.newVersion}
				s.mu.Unlock()
			}
			old.ReceiveUpdateResult(protocol.ClientUpdateResult{RequestID: request.RequestID, Status: tc.status, Version: "v0.4.2", Error: "exec failed"})
			err := <-done
			if (err == nil) != tc.success {
				t.Fatalf("unexpected result: %v", err)
			}
			if tc.name == "wrong version" && !strings.Contains(err.Error(), "尚未确认重新连接") {
				t.Fatal("incorrect success on wrong version")
			}
		})
	}
}
