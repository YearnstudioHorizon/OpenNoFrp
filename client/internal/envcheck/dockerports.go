//go:build linux

package envcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type dockerContainer struct {
	ID    string `json:"Id"`
	Name  string
	State struct {
		PID     int `json:"Pid"`
		Running bool
	}
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string
		}
		Networks map[string]struct{ IPAddress string }
	}
}

// Inspect returns individual bindings even when docker ps collapses port ranges.
func inspectPublishedPort(port uint16, transport string, localIP ...string) (PortOwnerInfo, bool, error) {
	// Wildcard publications belong to this host, not arbitrary LAN backends
	// that happen to use the same port.
	if len(localIP) > 0 {
		target := net.ParseIP(localIP[0])
		if target == nil || target.IsUnspecified() {
			return PortOwnerInfo{}, false, fmt.Errorf("Docker target must be a concrete IP: %q", localIP[0])
		}
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			return PortOwnerInfo{}, false, fmt.Errorf("list local interface addresses: %w", err)
		}
		if !isLocalDockerTarget(target, addresses) {
			return PortOwnerInfo{}, false, nil
		}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return PortOwnerInfo{}, false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ids, err := exec.CommandContext(ctx, "docker", "ps", "-q", "--no-trunc").Output()
	if err != nil {
		return PortOwnerInfo{}, false, fmt.Errorf("docker list containers: %w", err)
	}
	args := append([]string{"inspect", "--type", "container"}, strings.Fields(string(ids))...)
	if len(args) == 3 {
		return PortOwnerInfo{}, false, nil
	}
	data, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		return PortOwnerInfo{}, false, fmt.Errorf("docker inspect containers: %w", err)
	}
	return publishedPortFromInspect(data, port, transport, localIP...)
}

func isLocalDockerTarget(target net.IP, addresses []net.Addr) bool {
	if target.IsLoopback() {
		return true
	}
	for _, address := range addresses {
		if local, ok := address.(*net.IPNet); ok && local.IP.Equal(target) {
			return true
		}
	}
	return false
}

func publishedPortFromInspect(data []byte, port uint16, transport string, localIP ...string) (PortOwnerInfo, bool, error) {
	var containers []dockerContainer
	if err := json.Unmarshal(data, &containers); err != nil {
		return PortOwnerInfo{}, false, fmt.Errorf("decode Docker inspect: %w", err)
	}
	var target net.IP
	if len(localIP) > 0 {
		target = net.ParseIP(localIP[0])
		if target == nil || target.IsUnspecified() {
			return PortOwnerInfo{}, false, fmt.Errorf("Docker target must be a concrete IP: %q", localIP[0])
		}
	}
	var selected PortOwnerInfo
	for _, c := range containers {
		if !c.State.Running || c.State.PID <= 0 {
			continue
		}
		for key, bindings := range c.NetworkSettings.Ports {
			parts := strings.Split(key, "/")
			if len(parts) != 2 || parts[1] != transport {
				continue
			}
			internal, err := strconv.ParseUint(parts[0], 10, 16)
			if err != nil || internal == 0 {
				continue
			}
			for _, b := range bindings {
				if b.HostPort != strconv.Itoa(int(port)) {
					continue
				}
				bound := net.ParseIP(b.HostIP)
				if target != nil && b.HostIP != "" && (bound == nil || (!bound.Equal(target) && !(bound.IsUnspecified() && (bound.To4() != nil) == (target.To4() != nil)))) {
					continue
				}
				// Current container TPROXY setup supports IPv4 only.
				address := ""
				for _, network := range c.NetworkSettings.Networks {
					ip := net.ParseIP(network.IPAddress)
					if ip == nil || ip.To4() == nil || ip.IsUnspecified() {
						continue
					}
					if address != "" && address != ip.String() {
						return PortOwnerInfo{}, false, fmt.Errorf("container %s has multiple IPv4 backend addresses", c.ID)
					}
					address = ip.String()
				}
				if address == "" {
					return PortOwnerInfo{}, false, fmt.Errorf("container %s has no IPv4 backend address", c.ID)
				}
				info := PortOwnerInfo{Kind: OwnerDockerBridgeNetwork, PID: c.State.PID, ContainerID: c.ID, ContainerName: strings.TrimPrefix(c.Name, "/"), TargetPort: uint16(internal), TargetIP: address}
				if selected.ContainerID != "" && (selected.ContainerID != info.ContainerID || selected.TargetPort != info.TargetPort) {
					return PortOwnerInfo{}, false, fmt.Errorf("ambiguous Docker mapping for %s port %d", transport, port)
				}
				selected = info
			}
		}
	}
	return selected, selected.ContainerID != "", nil
}
