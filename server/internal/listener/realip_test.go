package listener

import (
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func mkReq(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "http://a.test/", nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func mustNets(t *testing.T, s string) []*net.IPNet {
	t.Helper()
	n, bad := ParseTrustedProxies(s)
	if len(bad) > 0 {
		t.Fatalf("bad trusted proxies: %v", bad)
	}
	return n
}

func TestParseIPSources(t *testing.T) {
	if got := ParseIPSources("X-Real-IP, bogus, x-real-ip;cf-connecting-ip"); !reflect.DeepEqual(got, []string{"x-real-ip", "cf-connecting-ip"}) {
		t.Errorf("ParseIPSources = %v", got)
	}
	if got := ParseIPSources(""); !reflect.DeepEqual(got, []string{"remote_addr"}) {
		t.Errorf("ParseIPSources empty = %v", got)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	nets, bad := ParseTrustedProxies("1.2.3.4, 10.0.0.0/8, nope, ::1")
	if len(nets) != 3 || !reflect.DeepEqual(bad, []string{"nope"}) {
		t.Fatalf("nets=%v bad=%v", nets, bad)
	}
	if !ipInNets(net.ParseIP("1.2.3.4"), nets) || ipInNets(net.ParseIP("1.2.3.5"), nets) || !ipInNets(net.ParseIP("10.9.8.7"), nets) {
		t.Errorf("ipInNets mismatch")
	}
}

func TestExtractClientIP(t *testing.T) {
	cases := []struct {
		name       string
		route      httpRoute
		remote     string
		headers    map[string]string
		want       string
		fromHeader bool
	}{
		{"default remote", httpRoute{}, "10.0.0.1:1", map[string]string{"X-Forwarded-For": "2.2.2.2"}, "10.0.0.1", false},
		{"priority cf first", httpRoute{IPSources: []string{"cf-connecting-ip", "x-forwarded-for"}}, "10.0.0.1:1",
			map[string]string{"CF-Connecting-IP": "1.1.1.1", "X-Forwarded-For": "2.2.2.2, 3.3.3.3"}, "1.1.1.1", true},
		{"fallback to xff leftmost", httpRoute{IPSources: []string{"cf-connecting-ip", "x-forwarded-for"}}, "10.0.0.1:1",
			map[string]string{"X-Forwarded-For": "2.2.2.2, 3.3.3.3"}, "2.2.2.2", true},
		{"remote_addr before headers", httpRoute{IPSources: []string{"remote_addr", "x-real-ip"}}, "10.0.0.1:1",
			map[string]string{"X-Real-IP": "4.4.4.4"}, "10.0.0.1", false},
		{"invalid header falls through", httpRoute{IPSources: []string{"x-real-ip", "true-client-ip"}}, "10.0.0.1:1",
			map[string]string{"X-Real-IP": "garbage", "True-Client-IP": "6.6.6.6"}, "6.6.6.6", true},
		{"untrusted peer ignored", httpRoute{IPSources: []string{"x-forwarded-for"}, TrustedProxies: mustNets(t, "10.0.0.0/8")}, "192.168.1.1:1",
			map[string]string{"X-Forwarded-For": "5.5.5.5"}, "192.168.1.1", false},
		{"trusted chain right-to-left", httpRoute{IPSources: []string{"x-forwarded-for"}, TrustedProxies: mustNets(t, "10.0.0.0/8")}, "10.0.0.1:1",
			map[string]string{"X-Forwarded-For": "9.9.9.9, 5.5.5.5, 10.0.0.2"}, "5.5.5.5", true},
		{"forwarded ipv6", httpRoute{IPSources: []string{"forwarded"}}, "10.0.0.1:1",
			map[string]string{"Forwarded": `for="[2001:db8::1]:4711";proto=http`}, "2001:db8::1", true},
	}
	for _, c := range cases {
		ip, fh := extractClientIP(mkReq(c.remote, c.headers), c.route)
		if ip == nil || !ip.Equal(net.ParseIP(c.want)) || fh != c.fromHeader {
			t.Errorf("%s: got %v,%v want %s,%v", c.name, ip, fh, c.want, c.fromHeader)
		}
	}
}

func TestRewriteForwardHeaders(t *testing.T) {
	// untrusted: spoofed headers stripped, real IP = peer
	route := httpRoute{IPSources: []string{"cf-connecting-ip"}, TrustedProxies: mustNets(t, "10.0.0.0/8")}
	in := mkReq("192.168.1.1:1", map[string]string{"CF-Connecting-IP": "6.6.6.6", "X-Forwarded-For": "6.6.6.6"})
	out := in.Header.Clone()
	real, _ := extractClientIP(in, route)
	rewriteForwardHeaders(in, out, route, real)
	if out.Get("CF-Connecting-IP") != "" || out.Get("X-Real-IP") != "192.168.1.1" || out.Get("X-Forwarded-For") != "192.168.1.1" {
		t.Errorf("untrusted rewrite: %v", out)
	}
	if out.Get("Forwarded") != `for=192.168.1.1;host="a.test";proto=http` || out.Get("X-Forwarded-Host") != "a.test" {
		t.Errorf("forwarded headers: %v", out)
	}

	// trusted: chain preserved + peer appended, CF header kept
	in = mkReq("10.0.0.1:1", map[string]string{"CF-Connecting-IP": "1.1.1.1", "X-Forwarded-For": "1.1.1.1", "X-Forwarded-Proto": "https"})
	out = in.Header.Clone()
	real, _ = extractClientIP(in, route)
	rewriteForwardHeaders(in, out, route, real)
	if out.Get("X-Real-IP") != "1.1.1.1" || out.Get("X-Forwarded-For") != "1.1.1.1, 10.0.0.1" || out.Get("CF-Connecting-IP") != "1.1.1.1" || out.Get("X-Forwarded-Proto") != "https" {
		t.Errorf("trusted rewrite: %v", out)
	}
}
