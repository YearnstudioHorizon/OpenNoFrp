// Package hosts manages only the entries owned by one VPN process.
package hosts

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"opennofrp/pkg/tempvpn"
)

// Install appends a uniquely marked entry after checking existing mappings.
// Cleanup rereads the file and removes only that exact entry, preserving edits
// made by others and leaving preexisting mappings to the same address alone.
func Install(names []string, address string) (func() error, error) {
	names, err := tempvpn.NormalizeHosts(names)
	if err != nil {
		return nil, err
	}
	noop := func() error { return nil }
	if len(names) == 0 {
		return noop, nil
	}
	ip := net.ParseIP(address)
	if ip == nil || address != "10.203.0.1" {
		return nil, fmt.Errorf("无效的 VPN HOST 地址")
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	marker := " # OpenNoFrp temporary VPN " + hex.EncodeToString(random)
	entry := ""
	err = edit(func(data string) (string, error) {
		found := map[string]bool{}
		for _, line := range strings.Split(data, "\n") {
			fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(fields) < 2 {
				continue
			}
			for _, alias := range fields[1:] {
				for _, name := range names {
					if strings.EqualFold(strings.TrimSuffix(alias, "."), name) {
						if mapped := net.ParseIP(fields[0]); mapped == nil || !mapped.Equal(ip) {
							return "", fmt.Errorf("HOST %s 已指向 %s；未修改已有配置", name, fields[0])
						}
						found[name] = true
					}
				}
			}
		}
		missing := []string{}
		for _, name := range names {
			if !found[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) == 0 {
			return data, nil
		}
		newline := "\n"
		if strings.Contains(data, "\r\n") {
			newline = "\r\n"
		}
		entry = address + "\t" + strings.Join(missing, " ") + marker + newline
		if len(data) > 0 && !strings.HasSuffix(data, "\n") {
			data += newline
		}
		return data + entry, nil
	})
	if err != nil {
		return nil, fmt.Errorf("添加 HOST 映射失败：%w", err)
	}
	if entry == "" {
		return noop, nil
	}
	flushCache()
	return func() error {
		err := edit(func(data string) (string, error) {
			var result strings.Builder
			for _, line := range strings.SplitAfter(data, "\n") {
				if line != entry {
					result.WriteString(line)
				}
			}
			return result.String(), nil
		})
		if err == nil {
			flushCache()
		}
		return err
	}, nil
}

// Open and lock the existing file rather than replacing it, preserving ACLs,
// ownership, and Linux bind mounts. Locks serialize cooperating VPN processes.
func edit(update func(string) (string, error)) error {
	file, err := os.OpenFile(systemPath(), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	unlock, err := lock(file)
	if err != nil {
		return err
	}
	defer unlock()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("hosts 文件超过 1 MiB，拒绝修改")
	}
	next, err := update(string(data))
	if err != nil || next == string(data) {
		return err
	}
	if len(next) > 1<<20 {
		return fmt.Errorf("hosts 文件超过 1 MiB，拒绝修改")
	}
	if err := write(file, []byte(next)); err != nil {
		if restore := write(file, data); restore != nil {
			return fmt.Errorf("写入失败 %v，恢复失败 %v；请检查 %s", err, restore, systemPath())
		}
		return err
	}
	return nil
}

func write(file *os.File, data []byte) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	n, err := file.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := file.Truncate(int64(len(data))); err != nil {
		return err
	}
	return file.Sync()
}
