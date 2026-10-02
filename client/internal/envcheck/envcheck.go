// Package envcheck probes the local Linux environment for everything the
// TPROXY-based source-IP-preservation feature needs, and reports a clear,
// actionable result instead of letting the feature fail mysteriously at
// runtime.
//
// Every check here corresponds to a concrete failure mode we hit while
// validating the design in an isolated KVM sandbox (see
// docs/01-architecture.md section 6). We encode those lessons as checks so
// that a user running "opennofrp-client envcheck" gets told in advance
// exactly what's missing, rather than discovering it through a silently
// hanging connection.
package envcheck

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Severity classifies how serious a failed check is.
type Severity int

const (
	// SeverityFatal means preserve_source_ip cannot work at all until this
	// is fixed.
	SeverityFatal Severity = iota
	// SeverityWarning means the feature may work but with caveats (e.g. a
	// sysctl needs to be set and the installer will try to set it
	// automatically; if that fails, warn but keep going).
	SeverityWarning
	// SeverityInfo is purely informational.
	SeverityInfo
)

func (s Severity) String() string {
	switch s {
	case SeverityFatal:
		return "FATAL"
	case SeverityWarning:
		return "WARN"
	default:
		return "INFO"
	}
}

// CheckResult is one probe's outcome.
type CheckResult struct {
	Name     string
	Severity Severity
	Passed   bool
	Detail   string
	FixHint  string
}

// Report aggregates all checks run against the host.
type Report struct {
	Results []CheckResult
}

// OK returns true if no FATAL check failed.
func (r Report) OK() bool {
	for _, res := range r.Results {
		if !res.Passed && res.Severity == SeverityFatal {
			return false
		}
	}
	return true
}

func (r Report) add(res CheckResult) Report {
	r.Results = append(r.Results, res)
	return r
}

// RunAll executes every environment check and returns the aggregated report.
// This does not modify the system in any way -- it is purely read-only
// probing, safe to run repeatedly and safe to run before the user has
// decided to proceed with installation.
func RunAll() Report {
	var r Report
	r = r.add(checkRunningAsRoot())
	r = r.add(checkKernelModule("xt_TPROXY", true))
	r = r.add(checkKernelModule("xt_connmark", true))
	r = r.add(checkKernelModule("nf_conntrack", true))
	r = r.add(checkIptablesLegacyAvailable())
	r = r.add(checkIptablesLegacyActive())
	r = r.add(checkConntrackToolAvailable())
	return r
}

func checkRunningAsRoot() CheckResult {
	uid := os.Geteuid()
	if uid == 0 {
		return CheckResult{
			Name: "running as root", Severity: SeverityFatal, Passed: true,
			Detail: "effective UID is 0",
		}
	}
	return CheckResult{
		Name: "running as root", Severity: SeverityFatal, Passed: false,
		Detail: fmt.Sprintf("effective UID is %d, not 0", uid),
		FixHint: "TPROXY and IP_TRANSPARENT require root (or at minimum " +
			"CAP_NET_ADMIN + CAP_NET_RAW). Re-run with sudo, or grant those " +
			"capabilities to the binary: setcap cap_net_admin,cap_net_raw+ep <binary>",
	}
}

// checkKernelModule verifies a kernel module is loaded, by checking
// /proc/modules. It does NOT attempt to modprobe it -- that is a mutating
// action left to the install script (with the user's explicit consent),
// envcheck is read-only by design.
func checkKernelModule(name string, fatal bool) CheckResult {
	sev := SeverityWarning
	if fatal {
		sev = SeverityFatal
	}

	f, err := os.Open("/proc/modules")
	if err != nil {
		return CheckResult{
			Name: fmt.Sprintf("kernel module %s loaded", name), Severity: sev, Passed: false,
			Detail:  fmt.Sprintf("could not read /proc/modules: %v", err),
			FixHint: fmt.Sprintf("modprobe %s", name),
		}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && fields[0] == name {
			return CheckResult{
				Name: fmt.Sprintf("kernel module %s loaded", name), Severity: sev, Passed: true,
				Detail: scanner.Text(),
			}
		}
	}

	// Some of these modules can be built-in (not shown in /proc/modules) if
	// the kernel was compiled with them as "=y" rather than "=m". Treat
	// "not found in /proc/modules" as a soft signal and let the actual
	// iptables rule application be the final arbiter; but still surface it
	// so the user isn't surprised.
	return CheckResult{
		Name: fmt.Sprintf("kernel module %s loaded", name), Severity: sev, Passed: false,
		Detail: fmt.Sprintf("%s not found in /proc/modules (may be built-in, or may need modprobe)", name),
		FixHint: fmt.Sprintf("modprobe %s", name),
	}
}

// checkIptablesLegacyAvailable verifies the iptables-legacy binary exists.
//
// Why this matters: our sandbox testing found that nftables' native
// "type route hook output" + ct-mark rewriting has an unresolved kernel/
// nftables-version interaction bug that silently breaks TPROXY interception
// itself. The classic iptables-legacy TPROXY + CONNMARK save/restore pattern
// does not have this problem and is what OpenNoFrp's tproxy helper uses.
// See docs/01-architecture.md section 6.1.
func checkIptablesLegacyAvailable() CheckResult {
	path, err := exec.LookPath("iptables-legacy")
	if err != nil {
		// Fall back: on some distros "iptables" itself IS the legacy
		// binary (no nft wrapper installed at all), which is also fine.
		if plainPath, err2 := exec.LookPath("iptables"); err2 == nil {
			if !isNftWrapper(plainPath) {
				return CheckResult{
					Name: "iptables-legacy available", Severity: SeverityFatal, Passed: true,
					Detail: fmt.Sprintf("using %s (not an nft wrapper)", plainPath),
				}
			}
		}
		return CheckResult{
			Name: "iptables-legacy available", Severity: SeverityFatal, Passed: false,
			Detail:  "iptables-legacy binary not found",
			FixHint: "apt-get install iptables  (provides both iptables-legacy and iptables-nft)",
		}
	}
	return CheckResult{
		Name: "iptables-legacy available", Severity: SeverityFatal, Passed: true,
		Detail: path,
	}
}

// checkIptablesLegacyActive checks whether the "iptables" alternative
// currently points at the legacy backend or the nft backend. This is
// informational -- opennofrp's tproxy helper always invokes
// "iptables-legacy" explicitly regardless of the system-wide alternative, so
// a mismatch here is not fatal, but it IS worth warning about because mixing
// iptables-nft (used by e.g. Docker) and iptables-legacy (used by us) rules
// on the same machine means "iptables -L" won't show our rules and vice
// versa, which is a common source of confusion during troubleshooting.
func checkIptablesLegacyActive() CheckResult {
	out, err := exec.Command("update-alternatives", "--display", "iptables").CombinedOutput()
	if err != nil {
		return CheckResult{
			Name: "iptables alternative", Severity: SeverityInfo, Passed: true,
			Detail: "update-alternatives not available or no iptables alternative registered (likely fine on non-Debian systems)",
		}
	}
	text := string(out)
	active := "unknown"
	if strings.Contains(text, "currently points to /usr/sbin/iptables-legacy") ||
		strings.Contains(text, "指向 /usr/sbin/iptables-legacy") {
		active = "legacy"
	} else if strings.Contains(text, "currently points to /usr/sbin/iptables-nft") ||
		strings.Contains(text, "指向 /usr/sbin/iptables-nft") {
		active = "nft"
	}
	return CheckResult{
		Name: "iptables alternative", Severity: SeverityInfo, Passed: true,
		Detail: fmt.Sprintf("system-wide default: %s (opennofrp always calls iptables-legacy explicitly, this is informational only)", active),
	}
}

func checkConntrackToolAvailable() CheckResult {
	path, err := exec.LookPath("conntrack")
	if err != nil {
		return CheckResult{
			Name: "conntrack tool available", Severity: SeverityWarning, Passed: false,
			Detail:  "conntrack binary not found (only needed for diagnostics, not required at runtime)",
			FixHint: "apt-get install conntrack",
		}
	}
	return CheckResult{
		Name: "conntrack tool available", Severity: SeverityInfo, Passed: true,
		Detail: path,
	}
}

func isNftWrapper(path string) bool {
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "nf_tables")
}

// Print writes a human-readable report to stdout/stderr, suitable for the
// "opennofrp-client envcheck" CLI subcommand.
func (r Report) Print() {
	for _, res := range r.Results {
		mark := "✓"
		if !res.Passed {
			mark = "✗"
		}
		fmt.Printf("[%s] %s %s\n", res.Severity, mark, res.Name)
		if res.Detail != "" {
			fmt.Printf("      %s\n", res.Detail)
		}
		if !res.Passed && res.FixHint != "" {
			fmt.Printf("      fix: %s\n", res.FixHint)
		}
	}
	if r.OK() {
		fmt.Println("\nAll fatal checks passed. preserve_source_ip should work.")
	} else {
		fmt.Println("\nOne or more FATAL checks failed. preserve_source_ip will not work until these are fixed.")
	}
}

// parseUint16 is a small helper used by other envcheck files.
func parseUint16(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}
