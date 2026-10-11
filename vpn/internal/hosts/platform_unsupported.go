//go:build !windows && !linux

package hosts

import (
	"fmt"
	"os"
)

func systemPath() string            { return "/etc/hosts" }
func lock(*os.File) (func(), error) { return nil, fmt.Errorf("此系统暂不支持 HOST 配置") }
func flushCache()                   {}
