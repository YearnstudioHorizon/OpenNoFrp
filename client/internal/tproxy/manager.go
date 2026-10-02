package tproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// State is the on-disk record of everything OpenNoFrp has changed on this
// machine's network stack. It is written after every successful Setup call
// and read by Teardown, so that uninstallation is based on "what did we
// actually do" rather than "what do we currently think we should undo" --
// this matters if the Client config changes between install and uninstall
// (e.g. a proxy rule was added or removed), ensuring we only ever remove
// exactly what we added.
type State struct {
	IngressIface   string          `json:"ingress_iface"`
	RouteTable     int             `json:"route_table"`
	FWMark         uint32          `json:"fwmark"`
	Rules          []RuleSpec      `json:"rules"`
	SysctlSnapshot SysctlSnapshot  `json:"sysctl_snapshot"`
}

// Manager coordinates the TPROXY rule set, policy routing, and sysctls for
// all proxy rules that have preserve_source_ip enabled.
type Manager struct {
	StateDir string // e.g. /var/lib/opennofrp
}

func (m Manager) statePath() string {
	return filepath.Join(m.StateDir, "tproxy-state.json")
}

// LoadState reads the persisted state, if any. Returns (nil, nil) if no
// state file exists yet (fresh install, nothing to tear down).
func (m Manager) LoadState() (*State, error) {
	data, err := os.ReadFile(m.statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("tproxy: read state: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("tproxy: parse state: %w", err)
	}
	return &st, nil
}

func (m Manager) saveState(st State) error {
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		return fmt.Errorf("tproxy: create state dir: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("tproxy: marshal state: %w", err)
	}
	tmp := m.statePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("tproxy: write state: %w", err)
	}
	return os.Rename(tmp, m.statePath())
}

// Setup applies TPROXY rules, policy routing, and sysctls for the given set
// of rules. It is idempotent and safe to call on every Client startup --
// each underlying primitive (iptables rules, ip rule/route, sysctls) only
// changes the system if the desired state isn't already in place.
//
// baseFWMark is the starting fwmark value; each RuleSpec gets baseFWMark + i
// to keep marks distinct is NOT done here -- the caller (forwarder package)
// is expected to assign distinct FWMark values per RuleSpec already, since
// a single shared policy-routing table keyed by "any nonzero mark -> local"
// works fine and keeps things simpler. See NewSharedFWMarkRules.
func (m Manager) Setup(ingressIface string, routeTable int, sharedFWMark uint32, rules []RuleSpec) error {
	existing, err := m.LoadState()
	if err != nil {
		return err
	}

	var snapshot SysctlSnapshot
	if existing != nil && existing.SysctlSnapshot != nil {
		// Reuse the original pre-install snapshot across repeated Setup
		// calls (e.g. Client restarts), so we never overwrite the
		// "true original" values with values WE set on a previous run.
		snapshot = existing.SysctlSnapshot
	} else {
		snapshot, err = CaptureSysctlSnapshot(ingressIface)
		if err != nil {
			return fmt.Errorf("tproxy: capture sysctl snapshot: %w", err)
		}
	}

	if err := ApplySysctls(ingressIface); err != nil {
		return fmt.Errorf("tproxy: apply sysctls: %w", err)
	}

	if err := EnsurePolicyRoute(routeTable, sharedFWMark); err != nil {
		return fmt.Errorf("tproxy: ensure policy route: %w", err)
	}

	for _, r := range rules {
		if err := AddTproxyRule(r); err != nil {
			return fmt.Errorf("tproxy: add rule for port %d: %w", r.PublicPort, err)
		}
	}

	st := State{
		IngressIface:   ingressIface,
		RouteTable:     routeTable,
		FWMark:         sharedFWMark,
		Rules:          rules,
		SysctlSnapshot: snapshot,
	}
	return m.saveState(st)
}

// Teardown removes everything recorded in the persisted state: iptables
// rules, the policy route, and restores sysctls to their pre-install
// values. This is what the uninstall script calls. If no state file exists
// (nothing was ever set up, or it was already torn down), this is a no-op.
func (m Manager) Teardown() error {
	st, err := m.LoadState()
	if err != nil {
		return err
	}

	// The rulesync setup path installs the OUTPUT CONNMARK pair directly
	// (without writing a state file), so remove it unconditionally, keyed
	// on the constants it uses -- idempotent when the rules are absent.
	connmarkFWMark := uint32(DefaultFWMark)
	if st != nil {
		connmarkFWMark = st.FWMark
	}
	if err := RemoveConnmarkReplyRules(connmarkFWMark); err != nil {
		return err
	}

	if st == nil {
		return nil // nothing else to do
	}

	var firstErr error
	for _, r := range st.Rules {
		if err := RemoveTproxyRule(r); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if err := RemovePolicyRoute(st.RouteTable, st.FWMark); err != nil && firstErr == nil {
		firstErr = err
	}

	if st.SysctlSnapshot != nil {
		if err := RestoreSysctls(st.SysctlSnapshot); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		if err := os.Remove(m.statePath()); err != nil && !os.IsNotExist(err) {
			firstErr = err
		}
	}

	return firstErr
}
