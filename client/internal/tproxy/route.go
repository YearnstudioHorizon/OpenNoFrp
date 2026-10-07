package tproxy

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// DefaultRouteTable 是 OpenNoFrp 使用的策略路由表 ID。100 不在其他软件通常
// 使用的范围内（它们往往为知名路由表使用很小的编号，或为系统保留表使用接近
// 253-255 的很大编号），但为防在某台主机上确实发生冲突，该值仍可配置。
const DefaultRouteTable = 100

// DefaultFWMark 是每个伪造源地址连接通过 SO_MARK 携带的 fwmark，也是
// CONNMARK save/restore 规则对和 fwmark 策略规则所依据的标记。它有意在所有
// 规则间共享：单一的“带有此标记的任何数据包都可经 table 100 本地投递”类别，
// 使得无论启用了多少条 preserve_source_ip 规则，路由配置都只需一条 ip rule
// 加一张路由表。
const DefaultFWMark = 0x1

// EnsurePolicyRoute 配置 `ip rule` + `ip route` 组合，使带有 fwmark 标记的
// 数据包经由回环设备本地投递；正是这一点让我们代理中伪造源 IP 的 connect()
// 调用能够成功完成 TCP 握手（携带已恢复标记的回包需要这条规则才能找到返回
// 代理的路径，而不是被路由到物理网卡上发出去）。
//
// 该函数是幂等的：可以在每次 Client 启动时安全调用。
func EnsurePolicyRoute(table int, fwmark uint32) error {
	if err := ensureIPRule(table, fwmark); err != nil {
		return err
	}
	if err := ensureLocalDefaultRoute(table); err != nil {
		return err
	}
	return nil
}

// RemovePolicyRoute 精确拆除 EnsurePolicyRoute 所添加的内容，且仅限于此——
// 它不会触及主路由表、任何其他 `ip rule` 条目或任何其他策略路由表。
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
	// 示例行："32765:	from all fwmark 0x1 lookup 100"
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
