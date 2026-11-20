//go:build linux

// Linux 平台的源 IP 保留实现：依据对本地目标端口归属者的实时探测，选择在
// 宿主机 netns 或 Docker 容器 netns 中执行 TPROXY 式伪造源地址拨号。
package rulesync

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"path/filepath"

	"opennofrp/client/internal/envcheck"
	"opennofrp/client/internal/netnsworker"
	"opennofrp/client/internal/tproxy"
	"opennofrp/pkg/protocol"
)

// sharedFWMark 是所有伪造源地址连接所使用的 fwmark。它必须与安装宿主机/容器
// 策略路由以及 OUTPUT CONNMARK save/restore 规则对时所用的值一致
// （即取值相同的 tproxy.DefaultFWMark）。
const sharedFWMark = tproxy.DefaultFWMark

// sourceIPSupported 报告本平台是否支持保留访问者源 IP。
func sourceIPSupported() bool { return true }

// dialPreservingSource 在开启 preserve_source_ip 的规则上执行伪造源地址拨号。
// 返回 (nil, nil) 表示应回退为普通转发；返回错误表示该连接应被丢弃。
func (r *Reconciler) dialPreservingSource(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata, target string) (net.Conn, error) {
	// 每个连接都重新执行 DetectPortOwner 很重要，因为 Docker 容器重启后
	// 其 PID 会改变（/proc/<pid>/ns/net 也随之不同），否则过期的 PID
	// 会悄无声息地进入已失效的命名空间。
	owner, err := envcheck.DetectPortOwner(rule.LocalPort, rule.LocalIP)
	if err != nil {
		r.Logger.Warn("cannot determine port owner, falling back to plain forwarding",
			"rule", rule.Name, "port", rule.LocalPort, "error", err)
		return nil, nil
	}

	switch owner.Kind {
	case envcheck.OwnerHostProcess, envcheck.OwnerDockerHostNetwork:
		if err := r.ensureHostTPROXYReady(); err != nil {
			r.Logger.Warn("host TPROXY environment setup failed, falling back to plain forwarding", "error", err)
			return nil, nil
		}
		dialer := tproxy.SpoofedDialer{FWMark: sharedFWMark}
		return dialer.DialSpoofed(ctx, meta.ClientAddr, net.ParseIP(rule.LocalIP), rule.LocalPort)

	case envcheck.OwnerDockerBridgeNetwork:
		cns := netnsworker.ContainerNetns{PID: owner.PID}
		if err := r.ensureNetnsReady(cns); err != nil {
			r.Logger.Warn("container netns setup failed, falling back to plain forwarding",
				"rule", rule.Name, "container_pid", owner.PID, "error", err)
			return nil, nil
		}

		// bridge 网络容器：整个伪造源地址的连接必须在该容器的网络命名空间
		// 【内部】创建——宿主机上的任何 iptables/TPROXY 都无法在 Docker 的
		// bridge MASQUERADE 之后保留下来，参见 docs/01-architecture.md 第 6.5 节。
		// 该 goroutine 必须在调用 socket() 之前以 runtime.LockOSThread 的方式
		// Enter() 此 netns。
		containerIP := net.ParseIP("127.0.0.1")
		if owner.TargetIP != "" {
			containerIP = net.ParseIP(owner.TargetIP)
		}
		containerPort := rule.LocalPort
		if owner.TargetPort != 0 {
			containerPort = owner.TargetPort
		}
		upstreamCh := make(chan net.Conn, 1)
		errCh := make(chan error, 1)
		go func() {
			if err := cns.Enter(); err != nil {
				errCh <- fmt.Errorf("enter container netns: %w", err)
				return
			}
			dialer := tproxy.SpoofedDialer{FWMark: sharedFWMark}
			upstream, err := dialer.DialSpoofed(ctx, meta.ClientAddr, containerIP, containerPort)
			if err != nil {
				errCh <- err
				return
			}
			upstreamCh <- upstream
		}()
		select {
		case err := <-errCh:
			r.Logger.Warn("container-netns spoofed dial failed, dropping", "rule", rule.Name, "error", err)
			return nil, err
		case upstream := <-upstreamCh:
			return upstream, nil
		}

	default:
		r.Logger.Warn("unknown port owner kind, falling back to plain forwarding", "rule", rule.Name, "kind", owner.Kind.String())
		return nil, nil
	}
}

// ensureHostTPROXYReady 应用伪造源地址拨号所需的宿主机级 sysctls、策略路由
// 以及 OUTPUT CONNMARK save/restore 规则对，每个进程只执行一次。这里不需要
// 入站 TPROXY mangle 规则：yamux 流已携带原始客户端地址，因此 Client 直接使用
// SO_MARK/IP_TRANSPARENT 拨号——但回包方向仍需要 CONNMARK 恢复，否则服务的
// SYN-ACK 会经默认网关路由出去，导致握手超时（参见 tproxy.EnsureConnmarkReplyRules）。
func (r *Reconciler) ensureHostTPROXYReady() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return net.ErrClosed
	}
	if r.hostSetupDone {
		return nil
	}
	iface, err := tproxy.DefaultIngressInterface()
	if err != nil {
		return fmt.Errorf("detect ingress interface: %w", err)
	}
	if err := (tproxy.Manager{StateDir: r.StateDir}).SetupRuntime(iface, tproxy.DefaultRouteTable, sharedFWMark); err != nil {
		return err
	}
	r.hostSetupDone = true
	r.Logger.Info("host TPROXY environment prepared (sysctls + policy route + CONNMARK)", "iface", iface)
	return nil
}

// ensureNetnsReady 在容器的 netns 内应用 sysctls + 策略路由，每个容器 PID
// 只执行一次。通过 RunInNamespace 执行，确保写入落在容器自身的 eth0/lo/all 条目上。
func (r *Reconciler) ensureNetnsReady(cns netnsworker.ContainerNetns) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return net.ErrClosed
	}

	source, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", cns.PID))
	if err != nil {
		return err
	}
	defer source.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &stat); err != nil {
		return err
	}
	id := fmt.Sprintf("%d-%d", stat.Dev, stat.Ino)
	if r.preparedNetns[id] {
		return nil
	}

	dir := filepath.Join(r.StateDir, "namespaces", id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "netns")
	anchor, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	anchor.Close()
	// The bind mount keeps the exact namespace recoverable after a PID change
	// and after an unexpected client exit.
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", source.Fd()), path, "", unix.MS_BIND, ""); err != nil {
		return errors.Join(err, os.Remove(path))
	}
	mgr := tproxy.Manager{StateDir: dir}
	if err := netnsworker.RunPath(path, func() error {
		iface, err := netnsworker.IngressInterface()
		if err != nil {
			return err
		}
		return mgr.SetupRuntime(iface, tproxy.DefaultRouteTable, sharedFWMark)
	}); err != nil {
		return errors.Join(err, teardownNamespace(dir))
	}
	r.preparedNetns[id] = true
	r.Logger.Info("container network namespace prepared", "pid", cns.PID)
	return nil
}

func teardownNamespace(dir string) error {
	path := filepath.Join(dir, "netns")
	var fs unix.Statfs_t
	err := unix.Statfs(path, &fs)
	if err == nil && fs.Type == unix.NSFS_MAGIC {
		mgr := tproxy.Manager{StateDir: dir}
		if err := netnsworker.RunPath(path, mgr.Teardown); err != nil {
			return err
		}
		if err := unix.Unmount(path, 0); err != nil {
			return err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// A plain anchor file after reboot has no kernel state left to restore.
	return os.RemoveAll(dir)
}

func TeardownNetwork(stateDir string) error {
	cleanup := (tproxy.Manager{StateDir: stateDir}).Teardown()
	root := filepath.Join(stateDir, "namespaces")
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return cleanup
	}
	if err != nil {
		return errors.Join(cleanup, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			cleanup = errors.Join(cleanup, teardownNamespace(filepath.Join(root, entry.Name())))
		}
	}
	return cleanup
}

func (r *Reconciler) TeardownNetwork() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopping = true
	return TeardownNetwork(r.StateDir)
}
