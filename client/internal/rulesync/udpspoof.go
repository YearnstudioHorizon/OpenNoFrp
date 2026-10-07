package rulesync

// UDP 源 IP 保留：按本地端口归属者选择在宿主机 netns 或容器 netns 内以访问者的
// 真实 (IP, 端口) 为源地址拨号本地 UDP 服务。任何一步失败都返回错误，由 serveUDP
// 回退为普通转发。

import (
	"context"
	"fmt"
	"net"

	"opennofrp/client/internal/envcheck"
	"opennofrp/client/internal/netnsworker"
	"opennofrp/client/internal/tproxy"
	"opennofrp/pkg/protocol"
)

func (r *Reconciler) dialSpoofedUDP(ctx context.Context, rule protocol.Rule, meta protocol.StreamMetadata) (net.Conn, error) {
	targetIP := net.ParseIP(rule.LocalIP)
	if targetIP == nil {
		return nil, fmt.Errorf("bad local ip %q", rule.LocalIP)
	}
	if (targetIP.To4() != nil) != (meta.ClientAddr.To4() != nil) {
		return nil, fmt.Errorf("visitor address %s and backend %s are different address families", meta.ClientAddr, targetIP)
	}
	dialer := tproxy.SpoofedDialer{FWMark: sharedFWMark}

	// 端口归属探测失败时（例如只探测到 TCP 监听），按宿主机进程处理。
	owner, err := envcheck.DetectPortOwner(rule.LocalPort)
	if err == nil && owner.Kind == envcheck.OwnerDockerBridgeNetwork {
		cns := netnsworker.ContainerNetns{PID: owner.PID}
		if err := r.ensureNetnsReady(cns); err != nil {
			return nil, fmt.Errorf("container netns setup: %w", err)
		}
		type result struct {
			c   net.Conn
			err error
		}
		ch := make(chan result, 1)
		go func() {
			if err := cns.Enter(); err != nil {
				ch <- result{nil, fmt.Errorf("enter container netns: %w", err)}
				return
			}
			c, err := dialer.DialSpoofedUDP(ctx, meta.ClientAddr, meta.ClientPort, net.ParseIP("127.0.0.1"), rule.LocalPort)
			ch <- result{c, err}
		}()
		res := <-ch
		return res.c, res.err
	}

	if err := r.ensureHostTPROXYReady(); err != nil {
		return nil, fmt.Errorf("host TPROXY setup: %w", err)
	}
	return dialer.DialSpoofedUDP(ctx, meta.ClientAddr, meta.ClientPort, targetIP, rule.LocalPort)
}
