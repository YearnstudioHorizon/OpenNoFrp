// Package envcheck 探测本地 Linux 环境是否满足基于 TPROXY 的源 IP 保留功能
// 所需的全部条件，并给出清晰、可操作的结果，而不是让该功能在运行时莫名其妙地
// 失败。
//
// 这里的每一项检查都对应我们在隔离的 KVM 沙箱中验证该设计时遇到过的一种具体
// 故障模式（参见 docs/01-architecture.md 第 6 节）。我们把这些经验编码为检查项，
// 这样运行 "opennofrp-client envcheck" 的用户就能提前确切得知缺少什么，而不是
// 通过一个悄无声息挂起的连接才发现问题。
package envcheck

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Severity 表示某项检查失败的严重程度。
type Severity int

const (
	// SeverityFatal 表示在修复此问题之前，preserve_source_ip 完全无法工作。
	SeverityFatal Severity = iota
	// SeverityWarning 表示该功能可能可以工作，但有附加条件（例如需要设置某个
	// sysctl，安装程序会尝试自动设置；若设置失败，则发出警告但继续执行）。
	SeverityWarning
	// SeverityInfo 仅用于提供信息。
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

// CheckResult 是单项探测的结果。
type CheckResult struct {
	Name     string
	Severity Severity
	Passed   bool
	Detail   string
	FixHint  string
}

// Report 汇总针对本机运行的所有检查。
type Report struct {
	Results []CheckResult
}

// OK 在没有任何 FATAL 级检查失败时返回 true。
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

// RunAll 执行所有环境检查并返回汇总报告。
// 它不会以任何方式修改系统——纯粹是只读探测，可以安全地重复运行，也可以在
// 用户决定继续安装之前安全运行。
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

// checkKernelModule 通过检查 /proc/modules 来确认某个内核模块已加载。它不会
// 尝试对其执行 modprobe——那是一个会修改系统的操作，留给安装脚本（在用户明确
// 同意的情况下）完成；envcheck 在设计上是只读的。
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

	// 如果内核编译时将其中某些模块配置为 "=y" 而非 "=m"，它们可能是内置的
	// （不会出现在 /proc/modules 中）。因此把“未在 /proc/modules 中找到”视为
	// 一个软信号，以实际应用 iptables 规则的结果作为最终裁定；但仍然将其展示
	// 出来，以免用户感到意外。
	return CheckResult{
		Name: fmt.Sprintf("kernel module %s loaded", name), Severity: sev, Passed: false,
		Detail:  fmt.Sprintf("%s not found in /proc/modules (may be built-in, or may need modprobe)", name),
		FixHint: fmt.Sprintf("modprobe %s", name),
	}
}

// checkIptablesLegacyAvailable 确认 iptables-legacy 可执行文件存在。
//
// 为什么这很重要：我们的沙箱测试发现，nftables 原生的
// "type route hook output" + ct-mark 重写存在一个尚未解决的内核/nftables 版本
// 交互 bug，会悄无声息地破坏 TPROXY 拦截本身。经典的 iptables-legacy TPROXY +
// CONNMARK save/restore 模式没有这个问题，这也是 OpenNoFrp 的 tproxy helper
// 所采用的方式。参见 docs/01-architecture.md 第 6.1 节。
func checkIptablesLegacyAvailable() CheckResult {
	path, err := exec.LookPath("iptables-legacy")
	if err != nil {
		// 回退：在某些发行版上，"iptables" 本身就是 legacy 可执行文件
		// （根本没有安装 nft 包装器），这种情况同样可行。
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

// checkIptablesLegacyActive 检查 "iptables" alternative 当前指向 legacy 后端
// 还是 nft 后端。此项仅供参考——无论系统级 alternative 如何设置，opennofrp 的
// tproxy helper 总是显式调用 "iptables-legacy"，因此这里不一致并不致命；但确实
// 值得提醒，因为在同一台机器上混用 iptables-nft（例如 Docker 使用）和
// iptables-legacy（我们使用）的规则，意味着 "iptables -L" 不会显示我们的规则，
// 反之亦然，这是排查问题时常见的困惑来源。
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

// Print 将人类可读的报告写到 stdout/stderr，适用于
// "opennofrp-client envcheck" CLI 子命令。
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

// parseUint16 是供 envcheck 其他文件使用的小型辅助函数。
func parseUint16(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}
