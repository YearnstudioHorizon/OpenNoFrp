// Package tproxy 实现本地透明代理机制，使 OpenNoFrp Client 能够把连接交付给
// 完全未经修改的本地服务，同时让该服务通过普通的 accept()/recvfrom() 调用
// 看到真实的原始客户端 IP。
//
// 本包是 docs/01-architecture.md 第 6 节中经沙箱验证的设计的直接代码化实现。
// 这里的每条规则和每个 sysctl 之所以存在，都是因为在那次验证中尝试过某种
// 替代方案并发现它行不通；请通过注释了解“为什么”，而不仅仅是“是什么”。
//
// IMPORTANT: 本包中所有会修改系统状态的函数都显式使用 `iptables-legacy`，
// 从不使用裸 `iptables` 命令，也从不使用 `nft`。这是有意为之：nftables 原生的
// TPROXY+route-hook 方案存在一个尚未解决的内核/nftables 版本 bug（在
// Debian 12 / kernel 6.1.0 上观察到）：通过 "type route hook output" 链给
// SYN-ACK 回复包打标记，会悄无声息地破坏原有的入站 TPROXY 拦截。
// iptables-legacy 经典的 CONNMARK save/restore 模式不存在这个问题。
package tproxy

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const iptablesBin = "iptables-legacy"

// RuleSpec 描述针对单个本地服务端口的一次 TPROXY 部署。
type RuleSpec struct {
	// PublicPort 是 Client 拦截入站流量的端口
	// （对应元数据中的 TargetPort——即*本地服务*实际监听的端口，因为 TPROXY
	// 完全在本机内部运作；Server 端的公网端口在这里无关紧要）。
	PublicPort uint16
	// IngressIface 是入站流量到达的网络接口（例如 "eth0"）。TPROXY 只拦截
	// 该接口上的流量，从而确保本机发起的流量（例如代理自身的出站连接）
	// 永远不会被意外地再次拦截。
	IngressIface string
	// ListenPort 是我们自己的代理进程用来接收经 TPROXY 重定向的连接的监听端口。
	// 每个 RuleSpec 必须唯一，且不得与任何真实服务冲突。
	ListenPort uint16
	// FWMark 是用于给经 TPROXY 处理的数据包打标记、以便进行策略路由的防火墙
	// 标记。每个 RuleSpec 必须唯一（若所有规则共用同一张策略路由表，也可以
	// 共享——参见 Manager）。
	FWMark uint32
}

func (r RuleSpec) comment() string {
	return fmt.Sprintf("opennofrp-port-%d", r.PublicPort)
}

// runIptables 使用给定参数运行 iptables-legacy，失败时返回包含 stderr
// 输出的描述性错误。
func runIptables(args ...string) error {
	cmd := exec.Command(iptablesBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tproxy: %s %s: %w: %s", iptablesBin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ruleExists 使用 iptables 内置的 -C（检查）操作，判断与给定参数（不含开头的
// "-t <table> -A/-D <chain>"）匹配的规则是否已存在。正是这一点使本文件中
// 所有 Add* 函数具备幂等性：每次 Client 启动时调用都是安全的，不会在多次
// 重启之间累积重复规则。
func ruleExists(table, chain string, ruleArgs ...string) bool {
	args := append([]string{"-t", table, "-C", chain}, ruleArgs...)
	cmd := exec.Command(iptablesBin, args...)
	return cmd.Run() == nil
}

func fwmarkSpec(mark uint32) string {
	return fmt.Sprintf("0x%x/0x%x", mark, mark)
}

// AddTproxyRule 为一个本地服务端口安装 mangle 表规则：
//
//  1. PREROUTING：匹配入站接口上目标为 PublicPort 的入站流量，执行 TPROXY
//     重定向到 127.0.0.1 上我们的 ListenPort，并给数据包打上 FWMark。
//  2. PREROUTING：对相同的匹配条件执行 CONNMARK --save-mark，使标记保存到
//     conntrack 中，以便在回复路径上恢复。
//  3. OUTPUT：对源端口为 PublicPort 的数据包（即从本地服务返回我们代理的
//     回复方向）执行 CONNMARK --restore-mark，使回复的策略路由决策同样使用
//     FWMark，并经由本地路由表交付回我们的代理，而不是从物理/网桥接口
//     泄漏出去。
//
// 这一确切的三规则模式（PREROUTING 中 TPROXY + save，OUTPUT 中 restore，
// 分别按 sport/dport 匹配）是在沙箱中针对真实的未修改 TCP 服务端到端验证
// 通过的唯一序列。不要通过去掉 CONNMARK 这对规则来“简化”它——没有它们，
// 握手的回复包就没有标记，会落入主路由表，导致代理的 connect() 调用一直
// 挂起直到超时。
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

// RemoveTproxyRule 删除 AddTproxyRule 可能为该 spec 创建的所有规则。删除操作
// 同样是幂等的（即使部分或全部规则已不存在，调用也是安全的），并使用与
// -C/-A 完全相同的参数列表执行 -D，因此只会删除本包自己添加的规则
// （绝不会整体清空 mangle 表）。
func RemoveTproxyRule(spec RuleSpec) error {
	port := strconv.Itoa(int(spec.PublicPort))
	listenPort := strconv.Itoa(int(spec.ListenPort))
	mark := fwmarkSpec(spec.FWMark)
	comment := spec.comment()

	var firstErr error
	tryDelete := func(table, chain string, args ...string) {
		if !ruleExists(table, chain, args...) {
			return // 已不存在
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

// connmarkComment 用于标记本包为回复路径添加的直连拨号 CONNMARK 规则
// （参见 EnsureConnmarkReplyRules）。它与 AddTproxyRule 使用的
// "opennofrp-port-" 标签不同，以便 ListOpenNoFrpRules 和卸载程序能够区分
// 这两类规则。
const connmarkComment = "opennofrp-connmark"

// EnsureConnmarkReplyRules 安装直连伪造源地址拨号路径所需的 mangle OUTPUT
// 规则对（Client 从 yamux 流元数据中获取原始客户端地址，并自行使用
// IP_TRANSPARENT + SO_MARK 拨号连接本地服务，因此不存在可以挂接
// AddTproxyRule 中 PREROUTING 那一半规则的入站 TPROXY 拦截）：
//
//  1. OUTPUT：对我们的出站数据包（它们通过 SO_MARK 携带 fwmark）执行
//     CONNMARK --save-mark，使连接的标记写入 conntrack。
//  2. OUTPUT：对回复方向（本地服务的 SYN-ACK/ACK/数据包本身不带任何标记）
//     执行 CONNMARK --restore-mark，使 fwmark 策略规则（table 100，
//     "local default dev lo"）将它们交付回伪造源地址的 socket，而不是经由
//     默认网关路由出去——没有这一步，握手的回复包会从物理接口泄漏出去，
//     connect() 会一直挂起直到超时。
//
// 掩码仅限于 fwmark 自身的位，因此绝不会覆盖其他本机发起的连接上的无关
// 标记。这一确切的规则对（加上策略路由和 sysctl）已在目标生产客户端主机上
// 端到端验证通过：对本地 HTTP 服务的伪造源地址 connect() 成功完成，且该服务
// 以伪造的源 IP 接受了连接。
// 幂等：在每条设置路径上调用都是安全的，不会累积重复规则。
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

// RemoveConnmarkReplyRules 精确删除 EnsureConnmarkReplyRules 为该 fwmark
// 添加的规则。它是幂等的，在 iptables-legacy 或这些规则不存在时也是安全的
// （供卸载程序路径使用，该路径不能仅仅因为 Client 从未运行到安装这些规则的
// 阶段就失败）。
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

// ListOpenNoFrpRules 返回 iptables-legacy mangle 表的原始列表输出，并过滤为
// 仅包含我们注释标签前缀的行。供卸载程序验证是否已干净移除，也供诊断工具
// 使用。
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
