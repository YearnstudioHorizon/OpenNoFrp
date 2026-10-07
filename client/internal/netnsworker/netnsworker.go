// Package netnsworker 让 OpenNoFrp Client 在目标容器的网络命名空间内部（而非
// Client 自身所在的宿主机网络命名空间）运行基于 TPROXY 的源 IP 保留转发逻辑。
//
// 为什么需要它：以默认 bridge 网络模式（标准的 "docker run -p"）运行的 Docker
// 容器，会对所有进入 docker0 的流量应用 MASQUERADE，这会在数据包到达容器之前
// 覆盖宿主机侧 TPROXY 转发器所做的任何源 IP 伪造。大量沙箱测试（参见
// docs/01-architecture.md 第 6 节）表明，从容器命名空间外部无法让伪造的源 IP
// 穿过该 MASQUERADE 边界而得以保留。
//
// 在同一沙箱中验证过的解决方案：不去对抗 MASQUERADE 边界，而是在目标容器自身的
// 网络命名空间内部运行 TPROXY 代理进程，并以该命名空间自己的回环地址
// （127.0.0.1）作为上游目标——这正是已被证明对普通宿主机进程可行的拓扑。在容器的
// netns 内部，“本地服务”和“代理”都位于同一个命名空间中，因此完全不会涉及
// bridge 的 NAT 机制；Docker 的 -p 端口映射、iptables DNAT/MASQUERADE 规则以及
// 容器本身都不会被触碰或重新配置。
//
// 使其生效的前提条件（参见 tproxy 包中的 dialer.go）：
//   - TPROXY mangle 规则（TPROXY + CONNMARK save/restore）必须在目标 netns
//     内部应用，并匹配该命名空间自身的入口接口（对容器而言通常是 "eth0"）
//   - 上游 connect() 所用的 socket 必须带有与这些规则所用 fwmark 相匹配的
//     SO_MARK（这是通过真实的端到端 Go 测试发现的修复；最初的 netns sidecar
//     实验因缺少它而失败，当时被错误地归因于某种 netns 特有的内核限制）
//   - 相关的 sysctl（route_localnet、accept_local、rp_filter）必须在该命名空间
//     内部，对 "lo"、容器的入口接口以及 "all" 进行设置
package netnsworker

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// ContainerNetns 通过 PID 标识目标容器的网络命名空间（即从宿主机 PID 命名空间
// 看到的容器 init 进程 PID——也就是 `docker inspect --format '{{.State.Pid}}'`
// 返回的值）。
type ContainerNetns struct {
	PID int
}

// nsPath 返回该容器的 /proc/<pid>/ns/net 路径。
func (c ContainerNetns) nsPath() string {
	return fmt.Sprintf("/proc/%d/ns/net", c.PID)
}

// RunInNamespace 将调用方 goroutine 所在 OS 线程的网络命名空间切换到目标容器的
// 命名空间后执行 fn，并在返回前切换回来。
//
// 关键的 Go 运行时细节：setns(2) 只影响调用它的 OS 线程，而非整个进程，而 Go
// 调度器可能在任意抢占点把 goroutine 迁移到其他 OS 线程上。本函数使用
// runtime.LockOSThread() 在 fn 的整个执行期间把当前 goroutine 固定在一个 OS
// 线程上，并且关键在于返回前从不调用 runtime.UnlockOSThread()——该线程被有意
// 保持锁定并随后丢弃（Go 运行时会终止该 OS 线程，而不会再将其复用于其他
// goroutine，这正是标准库针对这种情况所记录的模式：
// https://pkg.go.dev/runtime#LockOSThread）。这保证了任何其他无关的 goroutine
// 都不会意外地运行在一个处于容器网络命名空间内的线程上。
//
// fn 应当同步完成其所有对命名空间敏感的工作（例如创建一个 TPROXY 监听器并运行
// 其完整的 accept 循环），因为本函数只会在 fn 返回之后才返回。
//
// 通过真实端到端测试发现的重要注意事项：这只能保证在调用 fn 的同一个 goroutine
// 上运行的代码处于正确的命名空间。如果 fn 自己又派生了其他 goroutine（例如对每个
// 已接受的连接执行 "go handleConn(...)"，这是一种完全普通、在其他场景下也正确的
// Go 模式），这些新 goroutine 并不会自动被固定到已 setns() 的线程上——Go 调度器
// 可以自由地在任何 OS 线程上运行它们，包括仍处于宿主机根命名空间中的线程。任何
// 创建新的命名空间敏感资源的系统调用（最重要的是通过 net.Dial / unix.Socket 调用
// 的 socket(2)），只有在调用方 goroutine 已在其自己专用且锁定的 OS 线程上独立调用
// 过 Enter（见下文）时，才能保证落在目标命名空间中。具体模式参见 netnsworker-poc
// 的 runForwarder：accept 循环本身可以运行在由 RunInNamespace 固定的线程上，但
// 每一个按连接处理的 goroutine 都必须为自己再次调用 Enter。
func (c ContainerNetns) RunInNamespace(fn func() error) error {
	hostNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("netnsworker: open host netns: %w", err)
	}
	defer hostNS.Close()

	targetNS, err := os.Open(c.nsPath())
	if err != nil {
		return fmt.Errorf("netnsworker: open target netns %s: %w", c.nsPath(), err)
	}
	defer targetNS.Close()

	// 专用 goroutine，在其整个生命周期内永久固定在一个专用 OS 线程上——关于为何
	// 这种特定组合（新 goroutine + LockOSThread + 永不解锁）在这里是安全的模式，
	// 参见上面的文档注释。
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// 有意不调用 runtime.UnlockOSThread()：一旦该 goroutine 返回，Go 会
		// 终止这个 OS 线程，而不会把其他 goroutine 调度到一个已经 setns() 进入
		// 容器命名空间的线程上。

		if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("netnsworker: setns into container: %w", err)
			return
		}

		fnErr := fn()

		// 尽力而为：在该线程被销毁前切换回来。由于无论如何该线程都会被丢弃，
		// 这并非严格必要，但作为一种低成本的纵深防御，以防 fn 的 defer 调用中
		// 的某些清理代码（执行到这里时已经运行完毕）以某种方式期望仍处于正常的
		// 命名空间——它不会，但这样可以避免一个停留在错误命名空间中的线程留下
		// *进程可见*的副作用超过必要的时间。
		_ = unix.Setns(int(hostNS.Fd()), unix.CLONE_NEWNET)

		errCh <- fnErr
	}()

	return <-errCh
}

// Enter 将调用方 goroutine 固定到一个新的专用 OS 线程上，并通过 setns() 让该
// 线程进入此容器的网络命名空间。与 RunInNamespace 不同，它不会运行回调后返回——
// 它就地修改当前 goroutine 的线程亲和性后返回，此后调用方 goroutine（且仅限该
// goroutine，只要它一直运行在这个已被永久占用的线程上）就可以安全地创建命名空间
// 敏感的资源（socket 等），这些资源会正确地归属于目标命名空间。
//
// 每一个需要在目标命名空间内创建 socket 的独立调度的 goroutine（即每一个
// "go func(){...}()"）都必须在开头调用它——RunInNamespace 的命名空间归属不会
// 传递给子 goroutine。它所防止的具体故障模式参见包文档以及
// netnsworker-poc/main.go。
func (c ContainerNetns) Enter() error {
	runtime.LockOSThread()
	// 有意永不解锁，原因与 RunInNamespace 相同。

	targetNS, err := os.Open(c.nsPath())
	if err != nil {
		return fmt.Errorf("netnsworker: open target netns %s: %w", c.nsPath(), err)
	}
	defer targetNS.Close()

	if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("netnsworker: setns into container: %w", err)
	}
	return nil
}

// IngressInterface 返回目标命名空间内主要的非回环接口名称（对于标准的 Docker
// bridge 网络容器通常是 "eth0"）。由于它检查的是当前命名空间的接口，必须在
// RunInNamespace 的 fn 中调用。
func IngressInterface() (string, error) {
	ifaces, err := netInterfacesExcludingLoopback()
	if err != nil {
		return "", err
	}
	if len(ifaces) == 0 {
		return "", fmt.Errorf("netnsworker: no non-loopback interface found in this namespace")
	}
	// 容器的 netns 通常恰好只有一个非回环接口（它的 veth pair 一端，按惯例命名为
	// eth0）。如果碰巧有多个（不常见的自定义网络配置），我们取第一个，并在实际中
	// 若取错时允许调用方通过配置覆盖。
	return ifaces[0], nil
}
