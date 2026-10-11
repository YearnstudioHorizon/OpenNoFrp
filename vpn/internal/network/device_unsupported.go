//go:build !linux && (!windows || !amd64)

package network

import (
	"fmt"
	"golang.zx2c4.com/wireguard/tun"
)

func OpenDevice() (tun.Device, func(), error) {
	return nil, nil, fmt.Errorf("临时 VPN 目前支持 Linux AMD64/ARM64 和 Windows AMD64")
}
