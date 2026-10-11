//go:build linux

package network

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

func OpenDevice() (tun.Device, func(), error) {
	if routes, err := exec.Command("ip", "route", "show", "exact", "10.203.0.1/32").CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("需要 iproute2 和网络管理权限：%s", routes)
	} else if strings.TrimSpace(string(routes)) != "" {
		return nil, nil, fmt.Errorf("10.203.0.1 已有专用路由，请先处理地址冲突")
	}
	device, err := tun.CreateTUN("onfrvpn%d", 1280)
	if err != nil {
		return nil, nil, fmt.Errorf("创建 TUN 失败（需要 root 或 CAP_NET_ADMIN）：%w", err)
	}
	name, err := device.Name()
	if err != nil {
		device.Close()
		return nil, nil, err
	}
	cleanup := func() { device.Close() }
	for _, args := range [][]string{{"address", "add", "10.203.0.2/32", "dev", name}, {"link", "set", "dev", name, "up"}, {"route", "add", "10.203.0.1/32", "dev", name, "src", "10.203.0.2"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("设置 VPN 接口失败：%s (%w)", output, err)
		}
	}
	return device, cleanup, nil
}
