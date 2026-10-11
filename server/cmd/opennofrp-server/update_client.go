package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *server) updateClient(ctx context.Context, id string) (string, error) {
	if _, busy := s.clientUpdates.LoadOrStore(id, struct{}{}); busy {
		return "", fmt.Errorf("这台机器已有更新任务，请稍后再试")
	}
	defer s.clientUpdates.Delete(id)
	sess := s.sessionFor(id)
	if sess == nil {
		return "", fmt.Errorf("客户端当前离线，请等待重新连接")
	}
	result, err := sess.RequestUpdate(ctx)
	if err != nil {
		return "", fmt.Errorf("发送或等待更新指令失败：%w", err)
	}
	switch result.Status {
	case "failed":
		return "", fmt.Errorf("客户端更新失败：%s", result.Error)
	case "up_to_date":
		return "当前 Client 已是最新版本（" + result.Version + "）", nil
	case "restarting":
		if result.Version == "" {
			return "", fmt.Errorf("客户端没有返回目标版本，无法确认升级结果")
		}
	default:
		return "", fmt.Errorf("客户端返回未知的更新状态")
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if restartErr := sess.UpdateRestartError(result.RequestID); restartErr != "" {
			return "", fmt.Errorf("%s", restartErr)
		}
		current := s.sessionFor(id)
		if current != nil && current.ID != sess.ID && strings.TrimPrefix(current.ClientVersion, "v") == strings.TrimPrefix(result.Version, "v") {
			return "Client 已更新至 " + current.ClientVersion + "，重启并重新连接成功", nil
		}
		select {
		case <-ticker.C:
		case <-waitCtx.Done():
			return "", fmt.Errorf("新版本 %s 已安装，但尚未确认重新连接；请检查客户端状态和日志", result.Version)
		}
	}
}
