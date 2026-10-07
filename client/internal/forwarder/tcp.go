// Package forwarder 实现运行在 Client 上的数据面逻辑：对每条启用了
// preserve_source_ip 的代理规则，它监听经 TPROXY 重定向而来的连接，并为每个
// 连接以伪造的源 IP（与原始远端客户端一致）拨号到真实的本地服务。
//
// 对于未启用 preserve_source_ip 的规则，则回退为普通反向代理（正常拨号到本地
// 服务；本地服务看到的源地址将是 Client 自身的回环/本地地址，与原版 frp 相同）。
package forwarder

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"opennofrp/client/internal/tproxy"
)

// TCPRule 是一条 TCP 代理规则的运行时配置。
type TCPRule struct {
	Name             string
	LocalIP          net.IP
	LocalPort        uint16
	PreserveSourceIP bool

	// 仅在 PreserveSourceIP 为 true 时使用：
	IngressIface string
	ListenPort   uint16 // 我们的 TPROXY 监听器绑定的端口
}

// TCPForwarder 持有一条 PreserveSourceIP=true 的 TCPRule 的监听器。
// 它必须在对应的 tproxy.RuleSpec 已通过 tproxy.Manager.Setup 应用之后再启动，
// 否则入站连接根本不会到达 ListenPort。
type TCPForwarder struct {
	Rule   TCPRule
	Logger *slog.Logger
	Dialer tproxy.SpoofedDialer

	listener net.Listener
}

// Start 开始在 127.0.0.1:ListenPort 上监听经 TPROXY 重定向的连接。监听 socket
// 本身需要设置 IP_TRANSPARENT（通过在监听 socket 上设置 SO_IP_TRANSPARENT），
// 这样 accept() 才能返回本地地址为*原始*目的地址的连接（这是整个设计所依赖的
// TPROXY 语义 —— 参见 docs/01-architecture.md）。
func (f *TCPForwarder) Start(ctx context.Context) error {
	lc := net.ListenConfig{
		Control: controlSetTransparent,
	}
	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%d", f.Rule.ListenPort))
	if err != nil {
		return fmt.Errorf("forwarder: listen on TPROXY port %d: %w", f.Rule.ListenPort, err)
	}
	f.listener = ln

	go f.acceptLoop(ctx)
	return nil
}

func (f *TCPForwarder) Close() error {
	if f.listener != nil {
		return f.listener.Close()
	}
	return nil
}

func (f *TCPForwarder) acceptLoop(ctx context.Context) {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			f.Logger.Error("tproxy accept failed", "rule", f.Rule.Name, "error", err)
			continue
		}
		go f.handleConn(ctx, conn)
	}
}

// handleConn 会针对每个经 TPROXY 重定向的入站连接被调用。按照 TPROXY 语义：
// conn.RemoteAddr() 是原始远端客户端的真实地址（这正是 TPROXY 相对于普通
// REDIRECT/DNAT 的意义所在），而 conn.LocalAddr() —— 通过 getsockname() ——
// 是该连接的原始目的地址（即客户端以为自己所连接的对外公开地址）。这里其实
// 并不需要 LocalAddr，因为我们已经从规则配置中得知目标本地服务的地址，但把它
// 记录到日志中有助于诊断。
func (f *TCPForwarder) handleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	remoteAddr, ok := clientConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		f.Logger.Error("tproxy conn has non-TCP remote addr", "rule", f.Rule.Name)
		return
	}

	f.Logger.Debug("accepted tproxy connection",
		"rule", f.Rule.Name,
		"original_client", remoteAddr.String(),
		"original_dst", clientConn.LocalAddr().String(),
	)

	upstream, err := f.Dialer.DialSpoofed(ctx, remoteAddr.IP, f.Rule.LocalIP, f.Rule.LocalPort)
	if err != nil {
		f.Logger.Warn("failed to dial local service with spoofed source IP",
			"rule", f.Rule.Name,
			"local_target", fmt.Sprintf("%s:%d", f.Rule.LocalIP, f.Rule.LocalPort),
			"error", err,
		)
		return
	}
	defer upstream.Close()

	relay(clientConn, upstream)
}

// relay 在两个连接之间双向传输字节，直到任一端关闭或出错。
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}

// DialPlain 在不做任何源 IP 伪造的情况下连接本地服务。用于 PreserveSourceIP=false
// 的规则，或作为 OpenNoFrp 在 TPROXY 无法生效的 Docker bridge 网络目标上的回退
// 行为（参见 docs/01-architecture.md 第 6.2 节）—— 本地服务看到的连接源地址将是
// Client 进程自身的地址，与原版 frp 的行为一致。
func DialPlain(ctx context.Context, localIP net.IP, localPort uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", localIP, localPort))
}
