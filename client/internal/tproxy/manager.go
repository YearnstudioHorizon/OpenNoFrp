package tproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// State 是 OpenNoFrp 对本机网络栈所做全部改动的磁盘记录。每次 Setup 调用
// 成功后都会写入它，并由 Teardown 读取，使卸载依据的是“我们实际做了什么”，
// 而不是“我们当前认为应该撤销什么”——当 Client 配置在安装与卸载之间发生
// 变化（例如增加或删除了一条代理规则）时，这一点很重要，可确保我们只移除
// 自己添加过的内容，不多也不少。
type State struct {
	IngressIface   string         `json:"ingress_iface"`
	RouteTable     int            `json:"route_table"`
	FWMark         uint32         `json:"fwmark"`
	Rules          []RuleSpec     `json:"rules"`
	SysctlSnapshot SysctlSnapshot `json:"sysctl_snapshot"`
}

// Manager 为所有启用了 preserve_source_ip 的代理规则统一协调 TPROXY 规则集、
// 策略路由和 sysctls。
type Manager struct {
	StateDir string // 例如 /var/lib/opennofrp
}

func (m Manager) statePath() string {
	return filepath.Join(m.StateDir, "tproxy-state.json")
}

// LoadState 读取已持久化的状态（如果有）。若状态文件尚不存在（全新安装，
// 没有需要拆除的内容），则返回 (nil, nil)。
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

// Setup 为给定的规则集合应用 TPROXY 规则、策略路由和 sysctls。它是幂等的，
// 可以在每次 Client 启动时安全调用——每个底层原语（iptables 规则、
// ip rule/route、sysctls）只有在期望状态尚未就绪时才会修改系统。
//
// baseFWMark 是起始 fwmark 值；为保持标记互不相同而给每个 RuleSpec 分配
// baseFWMark + i 的做法【不在】此处进行——调用方（forwarder 包）应已为每个
// RuleSpec 分配了不同的 FWMark 值，因为单张以“任意非零标记 -> 本地”为键的
// 共享策略路由表就能正常工作，且更简单。参见 NewSharedFWMarkRules。
func (m Manager) Setup(ingressIface string, routeTable int, sharedFWMark uint32, rules []RuleSpec) error {
	existing, err := m.LoadState()
	if err != nil {
		return err
	}

	var snapshot SysctlSnapshot
	if existing != nil && existing.SysctlSnapshot != nil {
		// 在多次 Setup 调用（例如 Client 重启）之间复用安装前的原始快照，
		// 以免用【我们】在上一次运行中设置的值覆盖“真正的原始”值。
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

// Teardown 移除持久化状态中记录的所有内容：iptables 规则、策略路由，并将
// sysctls 恢复为安装前的值。卸载脚本调用的就是它。若状态文件不存在（从未
// 进行过配置，或已被拆除），则不执行任何操作。
func (m Manager) Teardown() error {
	st, err := m.LoadState()
	if err != nil {
		return err
	}

	// rulesync 的配置路径会直接安装 OUTPUT CONNMARK 规则对（不写入状态文件），
	// 因此这里根据它所使用的常量无条件移除——规则不存在时也是幂等的。
	connmarkFWMark := uint32(DefaultFWMark)
	if st != nil {
		connmarkFWMark = st.FWMark
	}
	if err := RemoveConnmarkReplyRules(connmarkFWMark); err != nil {
		return err
	}

	if st == nil {
		return nil // 没有其他需要处理的内容
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
