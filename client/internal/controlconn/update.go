package controlconn

import (
	"context"
	"net"
	"time"

	"opennofrp/pkg/protocol"
)

func (c *Client) writeControl(conn net.Conn, message any) error {
	c.controlWriteMu.Lock()
	defer c.controlWriteMu.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(protocol.ControlWriteTimeout)); err != nil {
		return err
	}
	defer conn.SetWriteDeadline(time.Time{})
	return protocol.WriteJSONMessage(conn, message)
}

func (c *Client) startUpdate(ctx context.Context, conn net.Conn, requestID string, ack <-chan string) {
	if c.Update == nil || c.Restart == nil {
		_ = c.writeControl(conn, protocol.ClientUpdateResult{Type: protocol.MsgClientUpdateResult, RequestID: requestID, Status: "failed", Error: "客户端未启用远程更新"})
		return
	}
	if !c.updating.CompareAndSwap(false, true) {
		_ = c.writeControl(conn, protocol.ClientUpdateResult{Type: protocol.MsgClientUpdateResult, RequestID: requestID, Status: "failed", Error: "客户端已有更新任务"})
		return
	}
	go func() {
		defer c.updating.Store(false)
		updateCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
		defer cancel()
		result, err := c.Update(updateCtx)
		message := protocol.ClientUpdateResult{Type: protocol.MsgClientUpdateResult, RequestID: requestID, Status: "up_to_date", Version: result.Version}
		if err != nil {
			message.Status = "failed"
			message.Error = err.Error()
		} else if result.Updated {
			message.Status = "restarting"
		}
		if sendErr := c.writeControl(conn, message); sendErr != nil {
			c.Logger.Warn("failed to report client update", "error", sendErr)
		}
		if err != nil || !result.Updated {
			return
		}
		// Wait for the server to receive the result before replacing the process.
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
	wait:
		for {
			select {
			case id := <-ack:
				if id == requestID {
					break wait
				}
			case <-timer.C:
				break wait
			case <-ctx.Done():
				break wait
			}
		}
		if err := c.Restart(); err != nil {
			c.Logger.Error("client updated but restart failed", "error", err)
			_ = c.writeControl(conn, protocol.ClientUpdateResult{Type: protocol.MsgClientUpdateResult, RequestID: requestID, Status: "failed", Version: result.Version, Error: "已安装新版本，但进程重启失败：" + err.Error()})
		}
	}()
}
