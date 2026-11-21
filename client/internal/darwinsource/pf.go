//go:build darwin

package darwinsource

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

const pfctl = "/sbin/pfctl"

type packetFilter struct {
	iface  string
	anchor string
	tag    string
	token  string

	mu      sync.Mutex
	closed  bool
	targets map[netip.Addr]netip.Addr
}

func setupPacketFilter(ctx context.Context, device tun.Device) (*packetFilter, error) {
	name, err := device.Name()
	if err != nil {
		return nil, err
	}
	if err := attachIP(name); err != nil {
		return nil, err
	}

	// The default macOS ruleset already evaluates these anchors. Never reload
	// the main ruleset, which can contain rules installed by the OS or other apps.
	for _, check := range []struct{ section, rule string }{
		{"rules", `anchor "com.apple/*"`},
		{"nat", `rdr-anchor "com.apple/*"`},
	} {
		out, err := runPF(ctx, "", "-s", check.section)
		if err != nil {
			return nil, err
		}
		if !strings.Contains(out, check.rule) {
			return nil, fmt.Errorf("PF main %s rules do not include %s", check.section, check.rule)
		}
	}
	pf := &packetFilter{
		iface: name, anchor: "com.apple/opennofrp-" + name, tag: "opennofrp-" + name,
		targets: make(map[netip.Addr]netip.Addr),
	}
	out, err := runPF(ctx, "", "-E")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		key, token, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == "Token" {
			pf.token = strings.TrimSpace(token)
			break
		}
	}
	if _, err := strconv.ParseUint(pf.token, 10, 64); err != nil {
		return nil, fmt.Errorf("could not read PF enable token from %q", out)
	}
	return pf, nil
}

func (p *packetFilter) destination(ctx context.Context, target netip.Addr) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return netip.Addr{}, net.ErrClosed
	}
	if dst, ok := p.targets[target]; ok {
		return dst, nil
	}
	// A loopback destination is rejected by XNU before PF can see it on
	// utun. Use a synthetic link-local destination, then redirect in PF.
	// These addresses exist only inside this utun and have no host routes.
	index := len(p.targets) + 256
	if index >= 0xff00 {
		return netip.Addr{}, errors.New("too many source IP targets")
	}
	dst := netip.AddrFrom4([4]byte{169, 254, byte(index >> 8), byte(index)})
	p.targets[target] = dst
	if _, err := runPF(ctx, p.rules(), "-a", p.anchor, "-f", "-"); err != nil {
		delete(p.targets, target)
		return netip.Addr{}, err
	}
	return dst, nil
}

func (p *packetFilter) rules() string {
	var rules strings.Builder
	targets := make([]netip.Addr, 0, len(p.targets))
	for target := range p.targets {
		targets = append(targets, target)
	}
	slices.SortFunc(targets, netip.Addr.Compare)
	for _, target := range targets {
		fmt.Fprintf(&rules, "rdr on %s inet proto { tcp udp } from any to %s tag %s -> %s\n", p.iface, p.targets[target], p.tag, target)
	}
	fmt.Fprintf(&rules, "pass in quick on %[1]s reply-to %[1]s inet proto { tcp udp } all tagged %[2]s keep state (floating)\n", p.iface, p.tag)
	return rules.String()
}

func (p *packetFilter) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, flushErr := runPF(ctx, "", "-a", p.anchor, "-f", "-")
	_, refErr := runPF(ctx, "", "-X", p.token)
	return errors.Join(flushErr, refErr)
}

func runPF(ctx context.Context, rules string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, pfctl, args...)
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pfctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func attachIP(name string) error {
	// XNU's SIOCPROTOATTACH attaches IPv4 without assigning an address or
	// adding host routes. Both supported architectures use a 32-byte ifreq.
	const attach = 0xc0206950 // _IOWR('i', 80, struct ifreq)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var ifreq [32]byte
	copy(ifreq[:unix.IFNAMSIZ], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), attach, uintptr(unsafe.Pointer(&ifreq[0])))
	if errno != 0 && errno != unix.EEXIST {
		return fmt.Errorf("attach IPv4 to %s: %w", name, errno)
	}
	return nil
}
