//go:build windows && amd64

package network

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

//go:embed assets/wintun-amd64.dll
var wintunDLL []byte

func loadDriver() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(executable), "wintun.dll")
	existing, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		file, err := os.CreateTemp(filepath.Dir(path), ".wintun-*.dll")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		if _, err := file.Write(wintunDLL); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(file.Name(), path); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if !bytes.Equal(existing, wintunDLL) {
		return fmt.Errorf("程序目录已有不同版本的 wintun.dll，请将接入程序放到独立目录")
	}
	_, err = windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	return err
}

func OpenDevice() (tun.Device, func(), error) {
	if err := loadDriver(); err != nil {
		return nil, nil, fmt.Errorf("加载内置 Wintun 驱动失败：%w", err)
	}
	routes, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; Get-NetRoute -AddressFamily IPv4 | Where-Object DestinationPrefix -EQ '10.203.0.1/32' | Select-Object -ExpandProperty InterfaceIndex").CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("检查路由失败：%s", routes)
	}
	if strings.TrimSpace(string(routes)) != "" {
		return nil, nil, fmt.Errorf("10.203.0.1 已有专用路由，请先处理地址冲突")
	}
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return nil, nil, err
	}
	name := "OpenNoFrp-" + hex.EncodeToString(random)
	device, err := tun.CreateTUN(name, 1280)
	if err != nil {
		return nil, nil, fmt.Errorf("创建 VPN 网卡失败，请以管理员身份运行：%w", err)
	}
	cleanup := func() {
		exec.Command("netsh", "interface", "ipv4", "delete", "route", "10.203.0.1/32", name, "store=active").Run()
		device.Close()
	}
	commands := [][]string{{"interface", "ipv4", "set", "address", "name=" + name, "source=static", "address=10.203.0.2", "mask=255.255.255.255", "gateway=none", "store=active"}, {"interface", "ipv4", "add", "route", "10.203.0.1/32", name, "nexthop=0.0.0.0", "store=active"}, {"interface", "ipv4", "set", "subinterface", name, "mtu=1280", "store=active"}}
	for _, args := range commands {
		if output, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("设置 VPN 网卡失败：%s (%w)", output, err)
		}
	}
	return device, cleanup, nil
}
