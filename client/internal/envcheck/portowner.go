package envcheck

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// PortOwnerKind 对本地端口上实际监听的对象进行分类，这决定了哪种 TPROXY 部署
// 策略（如果有的话）可行。每种情况背后的完整理由参见 docs/01-architecture.md
// 第 6 节。
type PortOwnerKind int

const (
	// OwnerUnknown 表示无法确定所有者（端口尚未监听，或 /proc 访问被拒绝）。
	OwnerUnknown PortOwnerKind = iota
	// OwnerHostProcess 是直接运行在宿主机网络命名空间中的普通进程。标准的
	// TPROXY + CONNMARK 无需任何特殊处理即可工作——这是经过充分验证的基准情况。
	OwnerHostProcess
	// OwnerDockerHostNetwork 是以 --network host 方式运行的 Docker 容器。从
	// TPROXY 的角度看，它与 OwnerHostProcess 没有区别（同一网络命名空间），
	// 完全受支持。
	OwnerDockerHostNetwork
	// OwnerDockerBridgeNetwork 是使用默认 bridge 网络（或自定义 bridge）并带有
	// -p 端口映射的 Docker 容器。仅在宿主机上做纯内核级 TPROXY，无法让伪造的
	// 源 IP 穿过 Docker 的 bridge MASQUERADE（参见旧设计中 docs/01 第 6.2 节）——
	// 但在容器自身的网络命名空间内部建立整个伪造源地址的连接是可行的（docs/01
	// 第 6.5 节），因此与旧设计不同，这种 OwnerKind 现在通过客户端的
	// container-netns spoofed-dial 策略被视为受支持。
	OwnerDockerBridgeNetwork
)

func (k PortOwnerKind) String() string {
	switch k {
	case OwnerHostProcess:
		return "host-process"
	case OwnerDockerHostNetwork:
		return "docker-host-network"
	case OwnerDockerBridgeNetwork:
		return "docker-bridge-network"
	default:
		return "unknown"
	}
}

// PortOwnerInfo 是检查某个本地端口归属的结果。
type PortOwnerInfo struct {
	Kind          PortOwnerKind
	PID           int
	ProcessName   string
	ContainerID   string // 仅在端口归属 Docker 时设置
	ContainerName string // 仅在端口归属 Docker 时设置，需要 `docker` CLI
}

// CanPreserveSourceIP 根据经过验证的沙箱测试，报告 OpenNoFrp 的 TPROXY 机制
// 对该端口所有者是否预期可行。
func (info PortOwnerInfo) CanPreserveSourceIP() (bool, string) {
	switch info.Kind {
	case OwnerHostProcess, OwnerDockerHostNetwork:
		return true, ""
	case OwnerDockerBridgeNetwork:
		// v1：通过 netns-worker 策略支持（客户端 setns() 进入容器的网络命名
		// 空间，并在其中以伪造的源地址拨号连接服务）。参见
		// client/internal/rulesync 以及 docs/01-architecture.md 第 6.5 节。
		return true, ""
	default:
		return false, "could not determine what is listening on this port; " +
			"is the local service actually running?"
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return "<unknown>"
}

// DetectPortOwner 检查 /proc，找出在给定 IP 的给定 TCP 端口上监听的进程（如果
// 有），然后对其分类。
//
// 该函数完全只读：它解析 /proc/net/tcp[6] 和 /proc/<pid>/cgroup，并可选地调用
// `docker inspect`（同样只读）来解析便于阅读的容器名称。它从不修改任何内容。
func DetectPortOwner(port uint16) (PortOwnerInfo, error) {
	pid, err := findListeningPID(port)
	if err != nil {
		return PortOwnerInfo{Kind: OwnerUnknown}, err
	}
	if pid == 0 {
		return PortOwnerInfo{Kind: OwnerUnknown}, fmt.Errorf("no process found listening on port %d", port)
	}

	info := PortOwnerInfo{PID: pid}
	info.ProcessName = processName(pid)

	containerID, inHostNetns := dockerCgroupInfo(pid)
	if containerID == "" {
		// 监听进程本身不在容器中。当 Docker 守护进程侧的辅助程序——dockerd、
		// containerd 或 docker-proxy——持有宿主机侧发布的端口时，这正是预期的
		// 情况。此时询问 Docker 实际是谁发布了该端口，并改为按容器的进程进行
		// 分类。
		if cid, statePID, containerName := findContainerPublishingPort(port); cid != "" {
			info.ContainerID = cid
			info.ContainerName = containerName
			info.PID = statePID
			if inHostNetnsOf(statePID) {
				info.Kind = OwnerDockerHostNetwork
			} else {
				info.Kind = OwnerDockerBridgeNetwork
			}
			return info, nil
		}
		info.Kind = OwnerHostProcess
		return info, nil
	}

	info.ContainerID = containerID
	info.ContainerName = dockerContainerName(containerID)

	if inHostNetns {
		info.Kind = OwnerDockerHostNetwork
	} else {
		info.Kind = OwnerDockerBridgeNetwork
	}
	return info, nil
}

// inHostNetnsOf 报告 /proc/<pid> 的网络命名空间是否就是宿主机自身的 netns
// （PID 1 的 netns）。
func inHostNetnsOf(pid int) bool {
	selfNetns, err1 := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	hostNetns, err2 := os.Readlink("/proc/1/ns/net")
	return err1 == nil && err2 == nil && selfNetns == hostNetns
}

// findContainerPublishingPort 解析 `docker ps --no-trunc` 的输出，查找其 PORTS
// 列发布了给定宿主机 TCP 端口的容器，然后通过 docker inspect 解析该容器的 init
// PID 和友好名称。运行 docker-proxy 的 Docker 守护进程（或者越来越常见的、没有
// 单独 docker-proxy 的情况——由 dockerd/containerd 直接绑定发布的 TCP socket）
// 会把宿主机侧的监听 socket 放在宿主机 netns 中，因此监听 PID 不带任何 /docker/
// cgroup 线索，纯粹基于 /proc 的检测无法对该端口分类。正是这个回退机制让
// OwnerDockerBridgeNetwork 检测在这种极其常见的情况下得以工作。
func findContainerPublishingPort(port uint16) (containerID string, statePID int, containerName string) {
	out, err := exec.Command("docker", "ps", "--no-trunc").Output()
	if err != nil {
		return "", 0, ""
	}
	want := strconv.Itoa(int(port)) + "->"
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, want) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		candidate := fields[0]
		// NAMES 列是最后一个字段；同时匹配实际的
		// "0.0.0.0:<port>-><port>/tcp" 片段，而不是做子串匹配，以避免
		// "80->" 与 "8080->" 之类的误判，例如要求数字前面是 ':' 或端口规格的
		// 起始位置。
		if idx := strings.Index(line, ":"+want); idx == -1 {
			continue
		}
		pidOut, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", candidate).Output()
		if err != nil {
			continue
		}
		statePID, _ = strconv.Atoi(strings.TrimSpace(string(pidOut)))
		if statePID <= 0 {
			continue
		}
		nameOut, _ := exec.Command("docker", "inspect", "-f", "{{.Name}}", candidate).Output()
		containerName = strings.TrimPrefix(strings.TrimSpace(string(nameOut)), "/")
		return candidate, statePID, containerName
	}
	return "", 0, ""
}

// findListeningPID 扫描 /proc/net/tcp 和 /proc/net/tcp6，查找给定端口上处于
// LISTEN 状态的 socket，然后遍历 /proc/<pid>/fd 找出拥有该 socket inode 的进程。
// 这与 `ss -tlnp` 内部的做法一致，这里直接实现，以免依赖 `ss`/`netstat`
// 可执行文件的存在。
func findListeningPID(port uint16) (int, error) {
	inode, err := findListeningInode("/proc/net/tcp", port)
	if err != nil {
		return 0, err
	}
	if inode == "" {
		inode, err = findListeningInode("/proc/net/tcp6", port)
		if err != nil {
			return 0, err
		}
	}
	if inode == "" {
		return 0, nil
	}

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("envcheck: read /proc: %w", err)
	}
	target := "socket:[" + inode + "]"
	for _, entry := range procEntries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // 不是 PID 目录
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // 进程已退出或无权限，跳过
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			if link == target {
				return pid, nil
			}
		}
	}
	return 0, nil
}

// findListeningInode 解析 /proc/net/tcp{,6} 格式的文件，查找给定本地端口上的
// LISTEN（状态 0A）条目，并返回其 inode。
const tcpListenState = "0A"

func findListeningInode(path string, port uint16) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // 例如不支持 IPv6，不算错误
		}
		return "", fmt.Errorf("envcheck: open %s: %w", path, err)
	}
	defer f.Close()

	wantHex := strings.ToUpper(strconv.FormatUint(uint64(port), 16))
	if len(wantHex) < 4 {
		wantHex = strings.Repeat("0", 4-len(wantHex)) + wantHex
	}

	scanner := bufio.NewScanner(f)
	scanner.Scan() // 跳过表头行
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		localAddr := fields[1] // 格式：十六进制的 "IP:PORT"
		state := fields[3]
		inode := fields[9]

		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}
		portHex := strings.ToUpper(parts[1])
		if portHex == wantHex && state == tcpListenState {
			return inode, nil
		}
	}
	return "", scanner.Err()
}

func processName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// dockerCgroupInfo 检查 /proc/<pid>/cgroup，以确定该进程是否属于 Docker 管理
// 的容器，以及该容器的网络命名空间是宿主机自身的（--network host）还是隔离的
// （bridge/自定义网络）。
//
// 检测策略：
//  1. 从 cgroup 路径中解析 Docker 容器 ID。Cgroup v2 统一层级的路径形如：
//     0::/system.slice/docker-<64-hex-id>.scope
//     Cgroup v1 的路径形如：
//     .../docker/<64-hex-id>
//  2. 如果找到了容器 ID，就将 /proc/<pid>/ns/net 指向的 inode 与
//     /proc/1/ns/net 进行比较（在非容器化的宿主机上，PID 1 总是位于宿主机的
//     根网络命名空间中，至少也是一个稳定的参照点）。如果两者一致，说明容器使用
//     --network host；如果不同，则是隔离的网络命名空间（实际中几乎总是 bridge
//     模式）。
func dockerCgroupInfo(pid int) (containerID string, inHostNetns bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", false
	}

	for _, line := range strings.Split(string(data), "\n") {
		if id := extractDockerID(line); id != "" {
			containerID = id
			break
		}
	}
	if containerID == "" {
		return "", false
	}

	selfNetns, err1 := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	hostNetns, err2 := os.Readlink("/proc/1/ns/net")
	if err1 == nil && err2 == nil && selfNetns == hostNetns {
		inHostNetns = true
	}
	return containerID, inHostNetns
}

func extractDockerID(cgroupLine string) string {
	// cgroup v2 示例："0::/system.slice/docker-<id>.scope"
	if idx := strings.Index(cgroupLine, "docker-"); idx != -1 {
		rest := cgroupLine[idx+len("docker-"):]
		if end := strings.Index(rest, ".scope"); end != -1 {
			id := rest[:end]
			if isHexID(id) {
				return id
			}
		}
	}
	// cgroup v1 示例：".../docker/<id>"
	if idx := strings.Index(cgroupLine, "/docker/"); idx != -1 {
		rest := cgroupLine[idx+len("/docker/"):]
		rest = strings.TrimRight(rest, "\n")
		// 可能带有后续路径段；截取到下一个 '/' 为止
		if slash := strings.Index(rest, "/"); slash != -1 {
			rest = rest[:slash]
		}
		if isHexID(rest) {
			return rest
		}
	}
	return ""
}

func isHexID(s string) bool {
	if len(s) < 12 { // 短 ID 至少 12 个十六进制字符；完整 ID 为 64 个
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// dockerContainerName 通过 `docker inspect` 将容器 ID 解析为人类可读的名称。
// 该操作只读且尽力而为：如果 docker CLI 不可用或查询失败，则返回 ""，调用方
// 应回退为显示原始容器 ID。
func dockerContainerName(containerID string) string {
	out, err := exec.Command("docker", "inspect", "--format", "{{.Name}}", containerID).Output()
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "/")
}
