package envcheck

import (
	"net"
	"strings"
	"testing"
)

func TestLocalDockerTarget(t *testing.T) {
	addresses := []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)}}
	for _, tc := range []struct {
		ip   string
		want bool
	}{{"127.0.0.1", true}, {"::1", true}, {"192.0.2.10", true}, {"::ffff:192.0.2.10", true}, {"192.0.2.11", false}} {
		if got := isLocalDockerTarget(net.ParseIP(tc.ip), addresses); got != tc.want {
			t.Fatalf("%s: %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestPublishedPortFromInspect(t *testing.T) {
	const fixture = `[
	{"Id":"a","Name":"/web","State":{"Running":true,"Pid":42},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2"}},"Ports":{
	"9000/tcp":[{"HostIp":"192.0.2.10","HostPort":"8000"}],
	"9001/tcp":[{"HostIp":"192.0.2.10","HostPort":"8001"}],
	"9002/tcp":[{"HostIp":"192.0.2.10","HostPort":"8002"}],
	"53/udp":[{"HostIp":"0.0.0.0","HostPort":"8053"}],
	"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"},{"HostIp":"::","HostPort":"8080"}]} }},
	{"Id":"b","Name":"/other","State":{"Running":true,"Pid":43},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.3"}},"Ports":{"81/tcp":[{"HostIp":"192.0.2.11","HostPort":"8001"}]}}}
	]`
	for _, tc := range []struct {
		name, ip, proto, id string
		port, want          uint16
		wantErr             bool
	}{
		{"range first", "192.0.2.10", "tcp", "a", 8000, 9000, false},
		{"range middle", "192.0.2.10", "tcp", "a", 8001, 9001, false},
		{"range last", "192.0.2.10", "tcp", "a", 8002, 9002, false},
		{"different host IP", "192.0.2.11", "tcp", "b", 8001, 81, false},
		{"unmatched IP", "192.0.2.12", "tcp", "", 8001, 0, false},
		{"UDP wildcard", "127.0.0.1", "udp", "a", 8053, 53, false},
		{"wrong protocol", "127.0.0.1", "tcp", "", 8053, 0, false},
		{"dual stack duplicate", "127.0.0.1", "tcp", "a", 8080, 80, false},
		{"unspecified IP", "0.0.0.0", "tcp", "", 8080, 0, true},
		{"ambiguous without IP", "", "tcp", "", 8001, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ips []string
			if tc.ip != "" {
				ips = []string{tc.ip}
			}
			info, found, err := publishedPortFromInspect([]byte(fixture), tc.port, tc.proto, ips...)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v", err)
			}
			if tc.wantErr {
				return
			}
			if found != (tc.id != "") || info.ContainerID != tc.id || info.TargetPort != tc.want {
				t.Fatalf("unexpected result: %+v, found %v", info, found)
			}
			if found && (info.TargetIP == "" || info.TargetIP == "127.0.0.1" || info.PID == 0) {
				t.Fatalf("missing container backend: %+v", info)
			}
		})
	}
	t.Run("malformed JSON", func(t *testing.T) {
		if _, _, err := publishedPortFromInspect([]byte("invalid"), 8001, "tcp"); err == nil {
			t.Fatal("expected decode error")
		}
	})
	t.Run("multiple networks", func(t *testing.T) {
		data := strings.Replace(fixture, `"bridge":{"IPAddress":"172.17.0.2"}`, `"bridge":{"IPAddress":"172.17.0.2"},"other":{"IPAddress":"172.18.0.2"}`, 1)
		if _, _, err := publishedPortFromInspect([]byte(data), 8001, "tcp", "192.0.2.10"); err == nil {
			t.Fatal("expected ambiguous backend error")
		}
	})
}
