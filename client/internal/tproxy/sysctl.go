package tproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sysctlPath maps a dotted sysctl name (e.g. "net.ipv4.conf.lo.rp_filter")
// to its /proc/sys file path.
func sysctlPath(name string) string {
	return "/proc/sys/" + strings.ReplaceAll(name, ".", "/")
}

// readSysctl returns the current value of a sysctl.
func readSysctl(name string) (string, error) {
	data, err := os.ReadFile(sysctlPath(name))
	if err != nil {
		return "", fmt.Errorf("tproxy: read sysctl %s: %w", name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// writeSysctl sets a sysctl value. Requires root.
func writeSysctl(name, value string) error {
	path := sysctlPath(name)
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("tproxy: write sysctl %s=%s: %w", name, value, err)
	}
	return nil
}

// SysctlSetting is one (name, desired value) pair the tproxy manager needs.
type SysctlSetting struct {
	Name  string
	Value string
}

// requiredSysctls returns the full list of sysctls that must be set to the
// given value for TPROXY + spoofed-source-IP connects to work, for the given
// network interface name (the interface that will receive inbound traffic
// for the proxied port, e.g. "eth0").
//
// Rationale for each one (see docs/01-architecture.md section 6.1 for the
// full debugging history that led to this list):
//   - route_localnet=1 on lo: without this, the kernel refuses to route
//     packets whose destination is 127.0.0.0/8 through non-loopback paths
//     during the TPROXY-redirected local delivery, and more importantly
//     allows 127.0.0.1 to be treated as a valid connect() target even
//     though the source address is spoofed to an external-looking IP.
//   - accept_local=1 on lo: permits accepting packets whose source address
//     claims to be from a "martian" range when arriving on lo, which is
//     exactly what happens when our spoofed-source upstream connection's
//     SYN packet loops back through lo.
//   - rp_filter=0 and accept_local=1 under "all", not just on lo and the
//     ingress interface: this was discovered the hard way during real
//     end-to-end testing (not just the earlier sandbox probing) -- Linux's
//     reverse-path-filtering and martian-source-acceptance checks apply the
//     STRICTER (in rp_filter's case, the max; for accept_local, effectively
//     requiring both the specific interface's value AND "all"'s value to
//     permit it) of the per-interface and "all" settings. Setting only
//     net.ipv4.conf.lo.accept_local=1 without also setting
//     net.ipv4.conf.all.accept_local=1 silently leaves the real inbound
//     path's CONNMARK --save-mark unable to actually tag the conntrack
//     entry (the rule's packet counter still increments -- TPROXY is a
//     terminating target and by the time CONNMARK runs, the connection
//     tracking entry classification has already been finalized as
//     "invalid source, mark not settable" under the stricter policy).
//     Always set both "all" and the specific interface for every one of
//     these three sysctls.
func requiredSysctls(ingressIface string) []SysctlSetting {
	settings := []SysctlSetting{
		{"net.ipv4.conf.lo.route_localnet", "1"},
		{"net.ipv4.conf.lo.accept_local", "1"},
		{"net.ipv4.conf.lo.rp_filter", "0"},
		{"net.ipv4.conf.all.route_localnet", "1"},
		{"net.ipv4.conf.all.accept_local", "1"},
		{"net.ipv4.conf.all.rp_filter", "0"},
	}
	if ingressIface != "" && ingressIface != "lo" {
		settings = append(settings,
			SysctlSetting{fmt.Sprintf("net.ipv4.conf.%s.route_localnet", ingressIface), "1"},
			SysctlSetting{fmt.Sprintf("net.ipv4.conf.%s.accept_local", ingressIface), "1"},
			SysctlSetting{fmt.Sprintf("net.ipv4.conf.%s.rp_filter", ingressIface), "0"},
		)
	}
	return settings
}

// SysctlSnapshot captures the pre-existing value of every sysctl we are
// about to change, so the uninstaller / rollback path can restore the
// system to exactly how it was found, rather than guessing at defaults.
// This is persisted to disk (see Manager.snapshotPath) so it survives
// across Client restarts between install and uninstall.
type SysctlSnapshot map[string]string

// CaptureSysctlSnapshot reads the current value of every sysctl that
// ApplySysctls is about to touch, without modifying anything.
func CaptureSysctlSnapshot(ingressIface string) (SysctlSnapshot, error) {
	snap := make(SysctlSnapshot)
	for _, s := range requiredSysctls(ingressIface) {
		if _, already := snap[s.Name]; already {
			continue
		}
		val, err := readSysctl(s.Name)
		if err != nil {
			return nil, err
		}
		snap[s.Name] = val
	}
	return snap, nil
}

// ApplySysctls sets every required sysctl to the value TPROXY needs.
// Call CaptureSysctlSnapshot first if you need to be able to restore later.
func ApplySysctls(ingressIface string) error {
	for _, s := range requiredSysctls(ingressIface) {
		if err := writeSysctl(s.Name, s.Value); err != nil {
			return err
		}
	}
	return nil
}

// RestoreSysctls writes back every value captured in snap.
func RestoreSysctls(snap SysctlSnapshot) error {
	var firstErr error
	for name, value := range snap {
		if err := writeSysctl(name, value); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// DefaultIngressInterface attempts to guess the network interface that
// carries inbound internet traffic, by inspecting the default route. This
// is used as a sensible default for the install script; users can override
// it in the config if their setup is unusual (e.g. multiple WAN interfaces).
func DefaultIngressInterface() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("tproxy: read /proc/net/route: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		iface, destination := fields[0], fields[1]
		if destination == "00000000" { // default route destination is 0.0.0.0
			return iface, nil
		}
	}
	return "", fmt.Errorf("tproxy: could not determine default route interface")
}

// snapshotFilePath returns where the sysctl snapshot for a given state
// directory is stored on disk.
func snapshotFilePath(stateDir string) string {
	return filepath.Join(stateDir, "sysctl-snapshot.json")
}
