package tempvpn

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeHosts accepts only plain hostnames; addresses and hosts-file syntax
// are never accepted as aliases. Empty input leaves the hosts file untouched.
func NormalizeHosts(names []string) ([]string, error) {
	if len(names) > 8 {
		return nil, fmt.Errorf("HOST 别名最多 8 个")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || len(name) > 253 || net.ParseIP(name) != nil || name == "localhost" || name == "localhost.localdomain" || strings.HasSuffix(name, ".localhost") || name == "ip6-localhost" || name == "ip6-loopback" {
			return nil, fmt.Errorf("无效的 HOST 别名：%q", name)
		}
		hasLetter := false
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, fmt.Errorf("无效的 HOST 别名：%q", name)
			}
			for _, c := range label {
				if c >= 'a' && c <= 'z' {
					hasLetter = true
				}
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return nil, fmt.Errorf("无效的 HOST 别名：%q", name)
				}
			}
		}
		// Numeric-only names can be interpreted as abbreviated IP addresses
		// by applications, bypassing the hosts mapping.
		if !hasLetter {
			return nil, fmt.Errorf("HOST 别名必须包含字母：%q", name)
		}
		if !seen[name] {
			out = append(out, name)
			seen[name] = true
		}
	}
	return out, nil
}
