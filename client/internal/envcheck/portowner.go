package envcheck

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// PortOwnerKind classifies what is actually listening on a local port, which
// determines which TPROXY deployment strategy (if any) can work. See
// docs/01-architecture.md section 6 for the full rationale behind each case.
type PortOwnerKind int

const (
	// OwnerUnknown means we could not determine the owner (port not
	// listening yet, or /proc access denied).
	OwnerUnknown PortOwnerKind = iota
	// OwnerHostProcess is a normal process running directly in the host's
	// network namespace. Standard TPROXY + CONNMARK works without any
	// special handling -- this is the fully-validated baseline case.
	OwnerHostProcess
	// OwnerDockerHostNetwork is a Docker container running with
	// --network host. From TPROXY's perspective this is indistinguishable
	// from OwnerHostProcess (same network namespace), fully supported.
	OwnerDockerHostNetwork
	// OwnerDockerBridgeNetwork is a Docker container using the default
	// bridge network (or a custom bridge) with a -p port mapping. A pure
	// kernel-level TPROXY on the HOST cannot preserve the spoofed source IP
	// across Docker's bridge MASQUERADE (see docs/01 section 6.2 in the old
	// design) -- BUT setting up the whole spoofed-source connection INSIDE
	// the container's own network namespace works (docs/01 section 6.5), so
	// unlike the old design this OwnerKind is now considered supported via
	// the client's container-netns spoofed-dial strategy.
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

// PortOwnerInfo is the result of inspecting who owns a given local port.
type PortOwnerInfo struct {
	Kind          PortOwnerKind
	PID           int
	ProcessName   string
	ContainerID   string // only set for Docker-owned ports
	ContainerName string // only set for Docker-owned ports, requires `docker` CLI
}

// CanPreserveSourceIP reports whether OpenNoFrp's TPROXY mechanism is
// expected to work for this port owner, based on validated sandbox testing.
func (info PortOwnerInfo) CanPreserveSourceIP() (bool, string) {
	switch info.Kind {
	case OwnerHostProcess, OwnerDockerHostNetwork:
		return true, ""
	case OwnerDockerBridgeNetwork:
		// v1: supported via the netns-worker strategy (the client setns()s
		// into the container's network namespace and dials the service
		// there with the spoofed source address). See
		// client/internal/rulesync and docs/01-architecture.md section 6.5.
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

// DetectPortOwner inspects /proc to find which process (if any) is listening
// on the given TCP port on the given IP, then classifies it.
//
// This is entirely read-only: it parses /proc/net/tcp[6] and /proc/<pid>/cgroup,
// and optionally shells out to `docker inspect` (also read-only) to resolve a
// human-friendly container name. It never modifies anything.
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
		// The listener process is not itself in a container. That's the
		// expected situation when a Docker daemon-side helper -- dockerd,
		// containerd, or docker-proxy -- holds the host-side published
		// port. In that case ask Docker who actually publishes this port
		// and classify by the CONTAINER's process instead.
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

// inHostNetnsOf reports whether the network namespace of /proc/<pid>
// belongs to the host's own netns (PID 1's netns).
func inHostNetnsOf(pid int) bool {
	selfNetns, err1 := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	hostNetns, err2 := os.Readlink("/proc/1/ns/net")
	return err1 == nil && err2 == nil && selfNetns == hostNetns
}

// findContainerPublishingPort parses `docker ps --no-trunc` output for a
// container whose PORTS column publishes the given host TCP port, then
// resolves the container's init PID and friendly name via docker inspect.
// Docker daemons that run docker-proxy (or, increasingly, no separate
// docker-proxy -- dockerd/containerd binds the published TCP socket
// directly) hold the host-side listening socket in the HOST netns, so the
// listening PID carries no /docker/ cgroup hint and the pure
// /proc-based detection cannot classify the port. This fallback is what
// makes OwnerDockerBridgeNetwork detection work in that extremely common
// case.
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
		// The NAMES column is the last field; also match the actual
		// "0.0.0.0:<port>-><port>/tcp" fragment rather than substring
		// "80->" vs "8080->" style false positives, e.g. requiring the
		// digits be preceded by a ':' or start-of-port spec.
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

// findListeningPID scans /proc/net/tcp and /proc/net/tcp6 for a socket in
// LISTEN state on the given port, then walks /proc/<pid>/fd to find which
// process owns that socket's inode. This mirrors what `ss -tlnp` does
// internally, implemented directly so we don't depend on the `ss`/`netstat`
// binaries being present.
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
			continue // not a PID directory
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process exited or no permission, skip
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

// findListeningInode parses a /proc/net/tcp{,6}-style file looking for a
// LISTEN (state 0A) entry on the given local port, returning its inode.
const tcpListenState = "0A"

func findListeningInode(path string, port uint16) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // e.g. no IPv6 support, not an error
		}
		return "", fmt.Errorf("envcheck: open %s: %w", path, err)
	}
	defer f.Close()

	wantHex := strings.ToUpper(strconv.FormatUint(uint64(port), 16))
	if len(wantHex) < 4 {
		wantHex = strings.Repeat("0", 4-len(wantHex)) + wantHex
	}

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		localAddr := fields[1] // format: "IP:PORT" in hex
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

// dockerCgroupInfo inspects /proc/<pid>/cgroup to determine whether the
// process belongs to a Docker-managed container, and whether that
// container's network namespace is the host's own (--network host) or an
// isolated one (bridge/custom network).
//
// Detection strategy:
//  1. Parse the cgroup path for a Docker container ID. Cgroup v2 unified
//     hierarchy paths look like:
//       0::/system.slice/docker-<64-hex-id>.scope
//     Cgroup v1 paths look like:
//       .../docker/<64-hex-id>
//  2. If a container ID is found, compare /proc/<pid>/ns/net's target inode
//     against /proc/1/ns/net (PID 1, which is always in the host's root
//     network namespace on a non-containerized host, or at minimum is a
//     stable reference point). If they match, the container uses
//     --network host; if they differ, it's an isolated network namespace
//     (almost always bridge mode in practice).
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
	// cgroup v2 example: "0::/system.slice/docker-<id>.scope"
	if idx := strings.Index(cgroupLine, "docker-"); idx != -1 {
		rest := cgroupLine[idx+len("docker-"):]
		if end := strings.Index(rest, ".scope"); end != -1 {
			id := rest[:end]
			if isHexID(id) {
				return id
			}
		}
	}
	// cgroup v1 example: ".../docker/<id>"
	if idx := strings.Index(cgroupLine, "/docker/"); idx != -1 {
		rest := cgroupLine[idx+len("/docker/"):]
		rest = strings.TrimRight(rest, "\n")
		// may have trailing path segments; take up to the next '/'
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
	if len(s) < 12 { // short IDs are at least 12 hex chars; full is 64
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// dockerContainerName resolves a container ID to its human-readable name via
// `docker inspect`. This is read-only and best-effort: if the docker CLI
// isn't available or the lookup fails, it returns "" and callers should fall
// back to displaying the raw container ID.
func dockerContainerName(containerID string) string {
	out, err := exec.Command("docker", "inspect", "--format", "{{.Name}}", containerID).Output()
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "/")
}
