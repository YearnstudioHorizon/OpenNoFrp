package tproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sysctlPath 将点分隔的 sysctl 名称（例如 "net.ipv4.conf.lo.rp_filter"）
// 映射为对应的 /proc/sys 文件路径。
func sysctlPath(name string) string {
	return "/proc/sys/" + strings.ReplaceAll(name, ".", "/")
}

// readSysctl 返回某个 sysctl 的当前值。
func readSysctl(name string) (string, error) {
	data, err := os.ReadFile(sysctlPath(name))
	if err != nil {
		return "", fmt.Errorf("tproxy: read sysctl %s: %w", name, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// writeSysctl 设置某个 sysctl 的值。需要 root 权限。
func writeSysctl(name, value string) error {
	path := sysctlPath(name)
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("tproxy: write sysctl %s=%s: %w", name, value, err)
	}
	return nil
}

// SysctlSetting 是 tproxy manager 所需的一组（名称，期望值）对。
type SysctlSetting struct {
	Name  string
	Value string
}

// requiredSysctls 针对给定的网络接口名称（即将接收被代理端口入站流量的
// 接口，例如 "eth0"），返回为使 TPROXY + 伪造源 IP 的 connect 正常工作
// 而必须设置为指定值的完整 sysctl 列表。
//
// 每一项的理由（形成这份列表的完整调试历程参见 docs/01-architecture.md
// 第 6.1 节）：
//   - lo 上的 route_localnet=1：没有它，内核在 TPROXY 重定向后的本地交付
//     过程中会拒绝通过非回环路径路由目标为 127.0.0.0/8 的数据包；更重要的
//     是，它使 127.0.0.1 即使在源地址被伪造为看似外部的 IP 时，也能被视为
//     合法的 connect() 目标。
//   - lo 上的 accept_local=1：允许接受到达 lo 时源地址声称来自 "martian"
//     范围的数据包，而这正是我们伪造源地址的上游连接的 SYN 包经 lo 回环时
//     发生的情况。
//   - 在 "all" 下（而不仅仅是在 lo 和入站接口上）设置 rp_filter=0 和
//     accept_local=1：这是在真实的端到端测试中（而不仅仅是早期的沙箱探测
//     中）吃了苦头才发现的——Linux 的反向路径过滤和 martian 源地址接受检查
//     会采用各接口设置与 "all" 设置中更严格的那个（对 rp_filter 而言取
//     最大值；对 accept_local 而言，实际上要求特定接口的值与 "all" 的值
//     都允许才行）。只设置 net.ipv4.conf.lo.accept_local=1 而不同时设置
//     net.ipv4.conf.all.accept_local=1，会悄无声息地导致真实入站路径上的
//     CONNMARK --save-mark 实际上无法给 conntrack 条目打标记（该规则的数据包
//     计数器仍会递增——TPROXY 是终结型目标，等到 CONNMARK 运行时，连接跟踪
//     条目的分类已经在更严格的策略下被最终确定为“源地址无效，无法设置
//     标记”）。对这三个 sysctl 中的每一个，始终同时设置 "all" 和特定接口。
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

// SysctlSnapshot 记录我们即将修改的每个 sysctl 原有的值，使卸载/回滚路径
// 能够把系统精确恢复到最初的状态，而不是去猜测默认值。它会被持久化到磁盘
// （参见 Manager.snapshotPath），因此即使 Client 在安装与卸载之间重启也能
// 保留下来。
type SysctlSnapshot map[string]string

// CaptureSysctlSnapshot 读取 ApplySysctls 即将修改的每个 sysctl 的当前值，
// 不做任何修改。
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

// ApplySysctls 将每个所需的 sysctl 设置为 TPROXY 需要的值。
// 如果之后需要能够恢复，请先调用 CaptureSysctlSnapshot。
func ApplySysctls(ingressIface string) error {
	for _, s := range requiredSysctls(ingressIface) {
		if err := writeSysctl(s.Name, s.Value); err != nil {
			return err
		}
	}
	return nil
}

// RestoreSysctls 写回 snap 中记录的每个值。
func RestoreSysctls(snap SysctlSnapshot) error {
	var firstErr error
	for name, value := range snap {
		if err := writeSysctl(name, value); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// DefaultIngressInterface 通过检查默认路由，尝试推测承载入站互联网流量的
// 网络接口。它被用作安装脚本的合理默认值；如果用户的环境比较特殊（例如有
// 多个 WAN 接口），可以在配置中覆盖它。
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
		if destination == "00000000" { // 默认路由的目标地址为 0.0.0.0
			return iface, nil
		}
	}
	return "", fmt.Errorf("tproxy: could not determine default route interface")
}

// snapshotFilePath 返回给定状态目录对应的 sysctl 快照在磁盘上的存储路径。
func snapshotFilePath(stateDir string) string {
	return filepath.Join(stateDir, "sysctl-snapshot.json")
}
