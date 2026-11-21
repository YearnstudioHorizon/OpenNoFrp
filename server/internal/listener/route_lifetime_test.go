package listener

import (
	"net"
	"testing"
)

func TestHTTPSharedPortRetiresOnlyRemovedRoute(t *testing.T) {
	l := new(httpListener)
	l.setRoutes([]httpRoute{{RuleID: 1, ClientID: "first"}, {RuleID: 2, ClientID: "second"}})
	first, second := l.routes[0].lifetime, l.routes[1].lifetime
	toRevoke, peer := net.Pipe()
	defer peer.Close()
	released := make(chan struct{})
	if _, err := first.track(toRevoke, func() { close(released) }); err != nil {
		t.Fatal(err)
	}
	l.setRoutes([]httpRoute{{RuleID: 2, ClientID: "second"}})
	select {
	case <-released:
	default:
		t.Fatal("revoked route retained an active backend")
	}
	if first.ctx.Err() == nil || second.ctx.Err() != nil || l.routes[0].lifetime != second {
		t.Fatal("reconciliation canceled the wrong route")
	}
	l.setRoutes(nil)
}
