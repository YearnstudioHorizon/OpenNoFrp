// Package version 管理 OpenNoFrp 的版本号信息
package version

import (
	"fmt"
	"runtime"
)

// Version 是当前程序的语义化版本号，可在构建时通过 ldflags 注入：
// -ldflags="-X 'opennofrp/pkg/version.Version=v1.0.0' -X 'opennofrp/pkg/version.Commit=$(git rev-parse --short HEAD)'"
var (
	Version   = "v0.1.0"
	Commit    = "dev"
	BuildDate = "unknown"
)

// String 返回格式化后的版本信息字符串
func String(component string) string {
	return fmt.Sprintf("%s %s (%s, %s, %s/%s)", component, Version, Commit, BuildDate, runtime.GOOS, runtime.GOARCH)
}
