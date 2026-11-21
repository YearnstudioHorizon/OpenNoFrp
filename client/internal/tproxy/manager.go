//go:build linux

package tproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// State is the write-ahead rollback record for one network namespace.
type State struct {
	Boot     string
	Table    int
	Mark     uint32
	Route    bool
	Rule     bool
	Firewall []firewallRule
	Sysctls  []sysctlChange
}

type sysctlChange struct {
	Name, Before, After string
}

type firewallRule struct {
	Table, Chain string
	Args         []string
}

type Manager struct {
	StateDir string
}

func (m Manager) statePath() string { return filepath.Join(m.StateDir, "network-journal.json") }

func bootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return string(data), err
}

func (m Manager) saveState(st *State) error {
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(m.StateDir, ".network-journal-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = errors.Join(json.NewEncoder(f).Encode(st), f.Sync(), f.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), m.statePath()); err != nil {
		return err
	}
	dir, err := os.Open(m.StateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (m Manager) SetupRuntime(ingress string, table int, mark uint32) (err error) {
	if _, err := os.Lstat(m.statePath()); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("tproxy: recover existing network journal before changing settings: %s", m.statePath())
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	st := &State{Boot: boot, Table: table, Mark: mark}
	defer func() {
		if err != nil {
			err = errors.Join(err, m.Teardown())
		}
	}()
	if err := checkRoutingAvailable(table, mark); err != nil {
		return err
	}

	// Block loopback traffic arriving from physical interfaces before relaxing
	// any sysctl. Filter INPUT and FORWARD also cover destinations after DNAT.
	for _, rule := range loopbackGuards() {
		if err := m.addFirewall(st, rule); err != nil {
			return err
		}
	}
	for _, setting := range requiredSysctls(ingress) {
		old, err := readSysctl(setting.Name)
		if err != nil {
			return err
		}
		if old == setting.Value {
			continue
		}
		st.Sysctls = append(st.Sysctls, sysctlChange{setting.Name, old, setting.Value})
		if err := m.saveState(st); err != nil {
			return err
		}
		if err := writeSysctl(setting.Name, setting.Value); err != nil {
			return err
		}
	}

	st.Route = true
	if err := m.saveState(st); err != nil {
		return err
	}
	if _, err := runIP(routeArgs("add", table)...); err != nil {
		return err
	}
	st.Rule = true
	if err := m.saveState(st); err != nil {
		return err
	}
	if _, err := runIP(policyArgs("add", table, mark)...); err != nil {
		return err
	}
	for _, args := range connmarkReplyRules(mark) {
		if err := m.addFirewall(st, firewallRule{"mangle", "OUTPUT", args}); err != nil {
			return err
		}
	}
	return nil
}

func loopbackGuards() []firewallRule {
	rules := []firewallRule{}
	for _, entry := range []struct{ table, chain, address string }{
		{"raw", "PREROUTING", "-s"}, {"raw", "PREROUTING", "-d"},
		{"filter", "INPUT", "-d"}, {"filter", "FORWARD", "-d"},
	} {
		rules = append(rules, firewallRule{entry.table, entry.chain,
			[]string{"!", "-i", "lo", entry.address, "127.0.0.0/8", "-m", "comment",
				"--comment", "opennofrp-loopback-guard", "-j", "DROP"}})
	}
	return rules
}

func (r firewallRule) args(action string) []string {
	return append([]string{"-w", "3", "-t", r.Table, action, r.Chain}, r.Args...)
}

func (m Manager) addFirewall(st *State, rule firewallRule) error {
	if ruleExists(rule.Table, rule.Chain, rule.Args...) {
		// A pre-existing rule is someone else's and is never recorded for removal.
		return nil
	}
	st.Firewall = append(st.Firewall, rule)
	if err := m.saveState(st); err != nil {
		return err
	}
	return runIptables(rule.args("-I")...)
}

func (m Manager) Teardown() error {
	data, err := os.ReadFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	boot, err := bootID()
	if err != nil {
		return err
	}
	if st.Boot != boot {
		return os.Remove(m.statePath())
	}

	var cleanup error
	if st.Rule {
		cleanup = errors.Join(cleanup, removeOwnedRule(st.Table, st.Mark))
	}
	if st.Route {
		cleanup = errors.Join(cleanup, removeOwnedRoute(st.Table))
	}
	var restore error
	for _, change := range st.Sysctls {
		current, err := readSysctl(change.Name)
		if errors.Is(err, os.ErrNotExist) {
			continue // the interface no longer exists
		}
		if err == nil && current == change.After {
			err = writeSysctl(change.Name, change.Before)
		}
		restore = errors.Join(restore, err)
	}
	for i := len(st.Firewall) - 1; i >= 0; i-- {
		r := st.Firewall[i]
		// Keep the ingress guards if we could not restore the original isolation.
		if restore != nil && r.Table != "mangle" {
			continue
		}
		cleanup = errors.Join(cleanup, deleteRecordedFirewallRule(r))
	}
	if err := errors.Join(cleanup, restore); err != nil {
		return err
	}
	return os.Remove(m.statePath())
}

func deleteRecordedFirewallRule(r firewallRule) error {
	err := runIptables(r.args("-D")...)
	if err == nil {
		return nil
	}
	// Listing the chain distinguishes an already-absent rule from a missing
	// iptables binary, an inaccessible table, or an xtables lock failure.
	if listErr := runIptables("-w", "3", "-t", r.Table, "-S", r.Chain); listErr != nil {
		return errors.Join(err, listErr)
	}
	if ruleExists(r.Table, r.Chain, r.Args...) {
		return err
	}
	return nil
}

// Policy routing commands carry an explicit protocol and priority so teardown
// can remove only the entries owned by this client.
const routeProtocol = "241"
const rulePriority = "12141"

func routeArgs(action string, table int) []string {
	return []string{"-4", "route", action, "local", "0.0.0.0/0", "dev", "lo",
		"table", strconv.Itoa(table), "proto", routeProtocol}
}

func policyArgs(action string, table int, mark uint32) []string {
	return []string{"-4", "rule", action, "pref", rulePriority, "fwmark", fwmarkSpec(mark),
		"table", strconv.Itoa(table), "protocol", routeProtocol}
}
