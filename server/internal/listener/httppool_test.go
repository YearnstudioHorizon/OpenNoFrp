package listener

import (
	"net"
	"strings"
	"testing"

	"opennofrp/server/internal/session"
)

func TestBackendPoolKey(t *testing.T) {
	s1 := &session.Session{ID: "s1"}
	s2 := &session.Session{ID: "s2"}
	a := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1000}
	aOtherPort := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 2000}
	b := &net.TCPAddr{IP: net.ParseIP("5.6.7.8"), Port: 1000}

	k := backendPoolKey(1, a, s1)
	if !strings.HasSuffix(k, ".opennofrp") || strings.ContainsAny(k, ":/[]") {
		t.Errorf("pool key is not a plain host name: %q", k)
	}
	if backendPoolKey(1, aOtherPort, s1) != k {
		t.Errorf("same visitor IP with different source port should share the pool")
	}
	for name, other := range map[string]string{
		"different rule":    backendPoolKey(2, a, s1),
		"different visitor": backendPoolKey(1, b, s1),
		"different session": backendPoolKey(1, a, s2),
		"nil remote":        backendPoolKey(1, nil, s1),
	} {
		if other == k {
			t.Errorf("%s must not share the pool key", name)
		}
	}
	if backendPoolKey(1, nil, nil) == "" {
		t.Errorf("pool key must never be empty")
	}
}
