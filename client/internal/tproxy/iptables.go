// Package tproxy implements the local transparent-proxy machinery that lets
// OpenNoFrp Client deliver connections to a completely unmodified local
// service while making that service see the real, original client IP via a
// normal accept()/recvfrom() call.
//
// This package is the direct codification of the sandbox-validated design
// in docs/01-architecture.md section 6. Every rule and sysctl here exists
// because a specific alternative was tried and found broken during that
// validation; see the comments for the "why", not just the "what".
//
// IMPORTANT: all mutating functions in this package use `iptables-legacy`
// explicitly, never the bare `iptables` command and never `nft`. This is
// deliberate: nftables' native TPROXY+route-hook approach has an unresolved
// kernel/nftables-version bug (observed on Debian 12 / kernel 6.1.0) where
// marking SYN-ACK reply packets via a "type route hook output" chain
// silently breaks the original inbound TPROXY interception. iptables-legacy's
// classic CONNMARK save/restore pattern does not have this problem.
package tproxy

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const iptablesBin = "iptables-legacy"

// RuleSpec describes one TPROXY deployment for a single local service port.
type RuleSpec struct {
	// PublicPort is the port the Client should intercept inbound traffic on
	// (this corresponds to the metadata's TargetPort -- i.e. the port the
	// *local service* actually listens on, since TPROXY operates entirely
	// within this one machine; the Server-side public port is irrelevant
	// here).
	PublicPort uint16
	// IngressIface is the network interface inbound traffic arrives on
	// (e.g. "eth0"). TPROXY only intercepts traffic on this interface, so
	// that locally-originated traffic (e.g. the proxy's own outbound
	// connections) is never accidentally re-intercepted.
	IngressIface string
	// ListenPort is the port our own proxy process listens on to receive
	// TPROXY-redirected connections. Must be unique per RuleSpec and must
	// not collide with any real service.
	ListenPort uint16
	// FWMark is the firewall mark used to tag TPROXY'd packets for policy
	// routing. Must be unique per RuleSpec (or can be shared if using a
	// single shared policy-routing table for all rules -- see Manager).
	FWMark uint32
}

func (r RuleSpec) comment() string {
	return fmt.Sprintf("opennofrp-port-%d", r.PublicPort)
}

// runIptables runs iptables-legacy with the given arguments and returns a
// descriptive error on failure, including stderr output.
func runIptables(args ...string) error {
	cmd := exec.Command(iptablesBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tproxy: %s %s: %w: %s", iptablesBin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ruleExists checks whether a rule matching the given arguments (minus the
// leading "-t <table> -A/-D <chain>") already exists, using iptables'
// built-in -C (check) action. This is what makes all Add* functions in this
// file idempotent: safe to call on every Client startup without
// accumulating duplicate rules across restarts.
func ruleExists(table, chain string, ruleArgs ...string) bool {
	args := append([]string{"-t", table, "-C", chain}, ruleArgs...)
	cmd := exec.Command(iptablesBin, args...)
	return cmd.Run() == nil
}

func fwmarkSpec(mark uint32) string {
	return fmt.Sprintf("0x%x/0x%x", mark, mark)
}

// AddTproxyRule installs the mangle-table rules for one local service port:
//
//  1. PREROUTING: TPROXY redirect matching inbound traffic on the ingress
//     interface destined for PublicPort, to our ListenPort on 127.0.0.1,
//     tagging the packet with FWMark.
//  2. PREROUTING: CONNMARK --save-mark for the same match, so the mark
//     survives into conntrack and can be restored on the reply path.
//  3. OUTPUT: CONNMARK --restore-mark for packets with source port
//     PublicPort (i.e. the reply direction from the local service back to
//     our proxy), so the reply's policy routing decision also uses FWMark
//     and gets delivered back to our proxy via the local routing table
//     rather than leaking out a physical/bridge interface.
//
// This exact three-rule pattern (TPROXY + save in PREROUTING, restore in
// OUTPUT, matched by sport/dport respectively) is the one sequence that was
// validated end-to-end against a real unmodified TCP service in the sandbox.
// Do not "simplify" it by dropping the CONNMARK pair -- without it the
// handshake's reply packet has no mark, falls through to the main routing
// table, and the proxy's connect() call hangs until timeout.
func AddTproxyRule(spec RuleSpec) error {
	port := strconv.Itoa(int(spec.PublicPort))
	listenPort := strconv.Itoa(int(spec.ListenPort))
	mark := fwmarkSpec(spec.FWMark)
	comment := spec.comment()

	tproxyArgs := []string{
		"-i", spec.IngressIface,
		"-p", "tcp",
		"--dport", port,
		"-m", "comment", "--comment", comment,
		"-j", "TPROXY",
		"--on-port", listenPort,
		"--on-ip", "127.0.0.1",
		"--tproxy-mark", mark,
	}
	if !ruleExists("mangle", "PREROUTING", tproxyArgs...) {
		if err := runIptables(append([]string{"-t", "mangle", "-A", "PREROUTING"}, tproxyArgs...)...); err != nil {
			return err
		}
	}

	saveArgs := []string{
		"-p", "tcp",
		"--dport", port,
		"-m", "comment", "--comment", comment,
		"-j", "CONNMARK", "--save-mark",
	}
	if !ruleExists("mangle", "PREROUTING", saveArgs...) {
		if err := runIptables(append([]string{"-t", "mangle", "-A", "PREROUTING"}, saveArgs...)...); err != nil {
			return err
		}
	}

	restoreArgs := []string{
		"-p", "tcp",
		"--sport", port,
		"-m", "comment", "--comment", comment,
		"-j", "CONNMARK", "--restore-mark",
	}
	if !ruleExists("mangle", "OUTPUT", restoreArgs...) {
		if err := runIptables(append([]string{"-t", "mangle", "-A", "OUTPUT"}, restoreArgs...)...); err != nil {
			return err
		}
	}

	return nil
}

// RemoveTproxyRule deletes every rule AddTproxyRule might have created for
// this spec. Deletion is also idempotent (safe to call even if some or all
// rules are already gone) and uses -D with the exact same argument lists
// used for -C/-A, so it only ever removes rules this package itself added
// (never a blanket flush of the mangle table).
func RemoveTproxyRule(spec RuleSpec) error {
	port := strconv.Itoa(int(spec.PublicPort))
	listenPort := strconv.Itoa(int(spec.ListenPort))
	mark := fwmarkSpec(spec.FWMark)
	comment := spec.comment()

	var firstErr error
	tryDelete := func(table, chain string, args ...string) {
		if !ruleExists(table, chain, args...) {
			return // already gone
		}
		full := append([]string{"-t", table, "-D", chain}, args...)
		if err := runIptables(full...); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	tryDelete("mangle", "PREROUTING",
		"-i", spec.IngressIface, "-p", "tcp", "--dport", port,
		"-m", "comment", "--comment", comment,
		"-j", "TPROXY", "--on-port", listenPort, "--on-ip", "127.0.0.1", "--tproxy-mark", mark)

	tryDelete("mangle", "PREROUTING",
		"-p", "tcp", "--dport", port,
		"-m", "comment", "--comment", comment,
		"-j", "CONNMARK", "--save-mark")

	tryDelete("mangle", "OUTPUT",
		"-p", "tcp", "--sport", port,
		"-m", "comment", "--comment", comment,
		"-j", "CONNMARK", "--restore-mark")

	return firstErr
}

// connmarkComment tags the direct-dial CONNMARK rules this package adds for
// the reply path (see EnsureConnmarkReplyRules). Distinct from the
// "opennofrp-port-" tag used by AddTproxyRule so ListOpenNoFrpRules and the
// uninstaller can distinguish the two rule families.
const connmarkComment = "opennofrp-connmark"

// EnsureConnmarkReplyRules installs the mangle OUTPUT pair required by the
// direct spoofed-dial path (the Client receives the original client address
// in the yamux stream metadata and dials the local service itself with
// IP_TRANSPARENT + SO_MARK, so there is no inbound TPROXY interception to
// hang the PREROUTING half of AddTproxyRule off):
//
//  1. OUTPUT: CONNMARK --save-mark for our outbound packets (they carry
//     fwmark via SO_MARK), so the connection's mark lands in conntrack.
//  2. OUTPUT: CONNMARK --restore-mark for the reply direction (the local
//     service's SYN-ACK/ACK/data packets carry no mark of their own), so
//     the fwmark policy rule (table 100, "local default dev lo") delivers
//     them back to the spoofed socket instead of routing them out the
//     default gateway -- without this the handshake's reply packet leaks
//     out a physical interface and connect() hangs until timeout.
//
// Masks are limited to the fwmark's own bits so this never clobbers
// unrelated marks on other locally-generated connections. This exact pair
// (plus the policy route and sysctls) was validated end-to-end on the
// target production client host: a spoofed connect() to a local HTTP
// service completed and the service accepted with the spoofed source IP.
// Idempotent: safe to call on every setup path without accumulating
// duplicate rules.
func EnsureConnmarkReplyRules(fwmark uint32) error {
	mask := fmt.Sprintf("0x%x", fwmark)
	markSpec := fwmarkSpec(fwmark)
	zeroSpec := fmt.Sprintf("0x%x/0x%x", 0, fwmark)

	saveArgs := []string{
		"-p", "tcp",
		"-m", "mark", "--mark", markSpec,
		"-m", "comment", "--comment", connmarkComment,
		"-j", "CONNMARK", "--save-mark",
		"--nfmask", mask, "--ctmask", mask,
	}
	if !ruleExists("mangle", "OUTPUT", saveArgs...) {
		if err := runIptables(append([]string{"-t", "mangle", "-A", "OUTPUT"}, saveArgs...)...); err != nil {
			return err
		}
	}

	restoreArgs := []string{
		"-p", "tcp",
		"-m", "mark", "--mark", zeroSpec,
		"-m", "comment", "--comment", connmarkComment,
		"-j", "CONNMARK", "--restore-mark",
		"--nfmask", mask, "--ctmask", mask,
	}
	if !ruleExists("mangle", "OUTPUT", restoreArgs...) {
		if err := runIptables(append([]string{"-t", "mangle", "-A", "OUTPUT"}, restoreArgs...)...); err != nil {
			return err
		}
	}

	return nil
}

// RemoveConnmarkReplyRules deletes exactly what EnsureConnmarkReplyRules
// added for this fwmark. Idempotent and safe when iptables-legacy or the
// rules are absent (used by the uninstaller path, which must not fail just
// because the Client never got far enough to install them).
func RemoveConnmarkReplyRules(fwmark uint32) error {
	mask := fmt.Sprintf("0x%x", fwmark)
	markSpec := fwmarkSpec(fwmark)
	zeroSpec := fmt.Sprintf("0x%x/0x%x", 0, fwmark)

	var firstErr error
	tryDelete := func(args ...string) {
		if !ruleExists("mangle", "OUTPUT", args...) {
			return
		}
		full := append([]string{"-t", "mangle", "-D", "OUTPUT"}, args...)
		if err := runIptables(full...); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	tryDelete("-p", "tcp",
		"-m", "mark", "--mark", markSpec,
		"-m", "comment", "--comment", connmarkComment,
		"-j", "CONNMARK", "--save-mark",
		"--nfmask", mask, "--ctmask", mask)

	tryDelete("-p", "tcp",
		"-m", "mark", "--mark", zeroSpec,
		"-m", "comment", "--comment", connmarkComment,
		"-j", "CONNMARK", "--restore-mark",
		"--nfmask", mask, "--ctmask", mask)

	return firstErr
}

// ListOpenNoFrpRules returns the raw iptables-legacy mangle table listing,
// filtered to only lines containing our comment tag prefix. Used by the
// uninstaller to verify a clean removal, and by diagnostics tooling.
func ListOpenNoFrpRules() (string, error) {
	out, err := exec.Command(iptablesBin, "-t", "mangle", "-L", "-n", "-v").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tproxy: list mangle rules: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var kept []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "opennofrp-port-") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n"), nil
}
