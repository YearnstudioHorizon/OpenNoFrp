package tproxy

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// DefaultRouteTable is the policy-routing table ID OpenNoFrp uses. 100 is
// outside the range typically used by other software (which tends to use
// very low numbers for well-known tables or very high numbers close to
// 253-255 for system-reserved tables), but this is still configurable in
// case of a real conflict on a given host.
const DefaultRouteTable = 100

// DefaultFWMark is the fwmark every spoofed-source connection carries via
// SO_MARK, and the mark the CONNMARK save/restore pair and the fwmark
// policy rule are keyed on. Shared across all rules deliberately: a single
// "any packet with this mark is deliverable locally via table 100" class
// keeps the routing setup to one ip rule + one table regardless of how many
// preserve_source_ip rules are active.
const DefaultFWMark = 0x1

// EnsurePolicyRoute sets up the `ip rule` + `ip route` combination that lets
// packets tagged with fwmark be delivered locally via the loopback device,
// which is what allows our proxy's spoofed-source-IP connect() calls to
// successfully complete their TCP handshake (the reply packet, carrying the
// restored mark, needs this same rule to find its way back to the proxy
// rather than being routed out a physical interface).
//
// This is idempotent: safe to call on every Client startup.
func EnsurePolicyRoute(table int, fwmark uint32) error {
	if err := ensureIPRule(table, fwmark); err != nil {
		return err
	}
	if err := ensureLocalDefaultRoute(table); err != nil {
		return err
	}
	return nil
}

// RemovePolicyRoute tears down exactly what EnsurePolicyRoute added, and
// only that -- it does not touch the main routing table, any other `ip rule`
// entries, or any other policy routing table.
func RemovePolicyRoute(table int, fwmark uint32) error {
	var firstErr error
	if err := deleteLocalDefaultRoute(table); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := deleteIPRule(table, fwmark); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func ipRuleArgsFor(table int, fwmark uint32) []string {
	return []string{"rule", "add", "fwmark", fmt.Sprintf("0x%x", fwmark), "lookup", strconv.Itoa(table)}
}

func ensureIPRule(table int, fwmark uint32) error {
	if ipRuleExists(table, fwmark) {
		return nil
	}
	args := ipRuleArgsFor(table, fwmark)
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tproxy: ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func deleteIPRule(table int, fwmark uint32) error {
	if !ipRuleExists(table, fwmark) {
		return nil
	}
	args := []string{"rule", "del", "fwmark", fmt.Sprintf("0x%x", fwmark), "lookup", strconv.Itoa(table)}
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tproxy: ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ipRuleExists(table int, fwmark uint32) bool {
	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return false
	}
	// Example line: "32765:	from all fwmark 0x1 lookup 100"
	needle1 := fmt.Sprintf("fwmark 0x%x", fwmark)
	needle2 := fmt.Sprintf("lookup %d", table)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, needle1) && strings.Contains(line, needle2) {
			return true
		}
	}
	return false
}

func ensureLocalDefaultRoute(table int) error {
	if localDefaultRouteExists(table) {
		return nil
	}
	args := []string{"route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(table)}
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tproxy: ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func deleteLocalDefaultRoute(table int) error {
	if !localDefaultRouteExists(table) {
		return nil
	}
	args := []string{"route", "flush", "table", strconv.Itoa(table)}
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tproxy: ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func localDefaultRouteExists(table int) bool {
	out, err := exec.Command("ip", "route", "list", "table", strconv.Itoa(table)).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "local default dev lo") ||
		strings.Contains(string(out), "local 0.0.0.0/0 dev lo")
}
