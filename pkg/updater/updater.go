// Package updater 负责检查 GitHub Releases 最新版本并支持在线一键自更新 (Self-Update)。
package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"opennofrp/pkg/version"
)

const GitHubRepo = "YearnstudioHorizon/OpenNoFrp"

// ReleaseAsset 代表 GitHub Release 中的一个二进制资源文件
type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// GitHubRelease 代表 GitHub API 返回的 Release 结构
type GitHubRelease struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	Body        string         `json:"body"`
	PublishedAt time.Time      `json:"published_at"`
	HTMLURL     string         `json:"html_url"`
	Assets      []ReleaseAsset `json:"assets"`
}

// UpdateInfo 汇总后的更新检测结果
type UpdateInfo struct {
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
	HasUpdate      bool      `json:"has_update"`
	ReleaseNotes   string    `json:"release_notes"`
	ReleaseURL     string    `json:"release_url"`
	PublishedAt    time.Time `json:"published_at"`
	DownloadURL    string    `json:"download_url"`
	AssetName      string    `json:"asset_name"`
}

// CheckUpdate 查询 GitHub API 获取最新版本信息
func CheckUpdate(ctx context.Context, currentVersion string) (*UpdateInfo, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("updater: 创建请求失败: %w", err)
	}

	req.Header.Set("User-Agent", "OpenNoFrp-Updater/"+version.Version)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("updater: 请求 GitHub API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("updater: 尚未找到任何已发布的 Release")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("updater: GitHub API 返回错误状态码 %d: %s", resp.StatusCode, string(body))
	}

	var rel GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("updater: 解析 Release JSON 失败: %w", err)
	}

	latestTag := strings.TrimSpace(rel.TagName)
	hasUpdate := compareVersions(currentVersion, latestTag)

	info := &UpdateInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  latestTag,
		HasUpdate:      hasUpdate,
		ReleaseNotes:   rel.Body,
		ReleaseURL:     rel.HTMLURL,
		PublishedAt:    rel.PublishedAt,
	}

	return info, nil
}

// FindMatchingAsset 在 Release 中查找与当前操作系统和架构匹配的二进制文件
func (info *UpdateInfo) FindMatchingAsset(componentName string, assets []ReleaseAsset) string {
	// 例如：opennofrp-server-linux-amd64 或 opennofrp-client-linux-arm64
	targetSuffix := fmt.Sprintf("%s-%s-%s", componentName, runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		targetSuffix += ".exe"
	}

	for _, a := range assets {
		if strings.EqualFold(a.Name, targetSuffix) {
			return a.BrowserDownloadURL
		}
	}
	return ""
}

// Result distinguishes an installed update from an already-current executable.
type Result struct {
	Updated bool
	Version string
}

// SelfUpdate 执行当前二进制文件的在线一键更新。
func SelfUpdate(ctx context.Context, componentName string) error {
	_, err := SelfUpdateWithResult(ctx, componentName)
	return err
}

// SelfUpdateWithResult reports whether a new executable was actually installed.
func SelfUpdateWithResult(ctx context.Context, componentName string) (Result, error) {
	result := Result{Version: version.Version}
	err := selfUpdate(ctx, componentName, func(tag string) { result = Result{Updated: true, Version: tag} })
	return result, err
}

func selfUpdate(ctx context.Context, componentName string, installed func(string)) error {
	fmt.Printf("[OpenNoFrp] 正在检查最新版本 (当前版本: %s)...\n", version.Version)

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "OpenNoFrp-Updater/"+version.Version)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("网络请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取 Release 失败 (HTTP %d)", resp.StatusCode)
	}

	var rel GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return fmt.Errorf("解析版本信息失败: %w", err)
	}

	latestTag := strings.TrimSpace(rel.TagName)
	if !compareVersions(version.Version, latestTag) {
		fmt.Printf("[OpenNoFrp] 当前已是最新版本 (%s)，无需更新。\n", version.Version)
		return nil
	}

	fmt.Printf("[OpenNoFrp] 发现新版本: %s (当前: %s)\n", latestTag, version.Version)
	if rel.Body != "" {
		fmt.Printf("--- 更新说明 ---\n%s\n----------------\n", rel.Body)
	}

	// 查找当前系统与架构匹配的文件
	targetName := fmt.Sprintf("%s-%s-%s", componentName, runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		targetName += ".exe"
	}

	var downloadURL string
	for _, a := range rel.Assets {
		if a.Name == targetName {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("在 %s 的 Release 中未找到适用于当前平台 (%s/%s) 的二进制文件: %s", latestTag, runtime.GOOS, runtime.GOARCH, targetName)
	}

	const mirrorPrefix = "https://mirror.yearnstudio.cn/"

	// 定位当前正在运行的程序真实路径
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取当前程序路径失败: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("解析符号链接失败: %w", err)
	}

	// 创建临时文件写入
	tmpFile, err := os.CreateTemp(filepath.Dir(execPath), "opennofrp-update-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	fmt.Printf("[OpenNoFrp] 正在下载最新版本: %s ...\n", downloadURL)
	if err := downloadAssetToFile(ctx, tmpFile, downloadURL, mirrorPrefix); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("同步升级文件失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("关闭升级文件失败: %w", err)
	}

	// 完整性校验：验证二进制文件头魔数，防止将网络拦截返回的 HTML 页面误写入可执行文件
	checkFile, err := os.Open(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("校验升级文件失败: %w", err)
	}
	var magic [4]byte
	n, _ := io.ReadFull(checkFile, magic[:])
	checkFile.Close()
	if runtime.GOOS == "windows" {
		if n < 2 || !bytes.Equal(magic[:2], []byte("MZ")) {
			return fmt.Errorf("下载的文件不是有效的 Windows 可执行程序（可能包含 HTML 错误页或被篡改）")
		}
	} else if runtime.GOOS == "linux" {
		if n < 4 || !bytes.Equal(magic[:4], []byte("\x7fELF")) {
			return fmt.Errorf("下载的文件不是有效的 Linux 可执行程序（可能包含 HTML 错误页或被篡改）")
		}
	}

	// 赋予可执行权限
	if err := os.Chmod(tmpFile.Name(), 0o755); err != nil {
		return fmt.Errorf("修改权限失败: %w", err)
	}

	// 在 Linux 上执行原子重命名替换 (即使原程序正在运行，inode 替换也是安全的)
	if err := os.Rename(tmpFile.Name(), execPath); err != nil {
		return fmt.Errorf("替换当前执行文件失败: %w (请确认是否有 sudo/管理员权限)", err)
	}

	fmt.Printf("[OpenNoFrp] 恭喜！已成功将 %s 更新至 %s\n", componentName, latestTag)
	installed(latestTag)
	fmt.Printf("[OpenNoFrp] 请执行以下命令重启对应服务以生效：\n")
	if componentName == "opennofrp-server" {
		fmt.Printf("  sudo systemctl restart opennofrp-server\n")
	} else {
		fmt.Printf("  sudo systemctl restart opennofrp-client\n")
	}

	return nil
}

var (
	directDownloadTimeout = 20 * time.Second
	mirrorDownloadTimeout = 180 * time.Second
)

func downloadAssetToFile(ctx context.Context, tmpFile *os.File, downloadURL, mirrorPrefix string) error {
	downloadToFile := func(targetURL string, timeout time.Duration) error {
		if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := tmpFile.Truncate(0); err != nil {
			return err
		}
		dCtx, dCancel := context.WithTimeout(ctx, timeout)
		defer dCancel()
		req, err := http.NewRequestWithContext(dCtx, http.MethodGet, targetURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "OpenNoFrp-Updater/"+version.Version)
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		written, err := io.Copy(tmpFile, io.LimitReader(resp.Body, 200<<20))
		if err != nil {
			return err
		}
		if written == 0 {
			return errors.New("下载的文件为空")
		}
		return nil
	}

	downErr := downloadToFile(downloadURL, directDownloadTimeout)
	if downErr != nil {
		mirrorURL := mirrorPrefix + downloadURL
		fmt.Printf("[OpenNoFrp] 直连 GitHub 下载失败或超时（%v），正在自动切换至国内加速镜像: %s ...\n", downErr, mirrorURL)
		if mErr := downloadToFile(mirrorURL, mirrorDownloadTimeout); mErr != nil {
			return fmt.Errorf("写入临时升级文件失败 (GitHub 直连: %v; 加速镜像: %w)", downErr, mErr)
		}
	}
	return nil
}

// compareVersions 比较两个语义化版本号，若 latest 比 current 新则返回 true
func compareVersions(current, latest string) bool {
	c := cleanVersion(current)
	l := cleanVersion(latest)
	if c == "" || l == "" {
		return false
	}
	latestParts, latestPre, validLatest := parseVersion(l)
	if !validLatest {
		return false
	}
	if c == "dev" {
		return true // 开发版本允许升级至正式发布版
	}
	currentParts, currentPre, validCurrent := parseVersion(c)
	if !validCurrent {
		return false
	}
	for i := range currentParts {
		if latestParts[i] != currentParts[i] {
			return latestParts[i] > currentParts[i]
		}
	}
	if currentPre == latestPre {
		return false
	}
	if currentPre == "" {
		return false
	}
	if latestPre == "" {
		return true
	}
	cids, lids := strings.Split(currentPre, "."), strings.Split(latestPre, ".")
	for i := 0; i < len(cids) && i < len(lids); i++ {
		if cids[i] == lids[i] {
			continue
		}
		cn := strings.Trim(cids[i], "0123456789") == ""
		ln := strings.Trim(lids[i], "0123456789") == ""
		if cn && ln {
			if len(lids[i]) != len(cids[i]) {
				return len(lids[i]) > len(cids[i])
			}
			return lids[i] > cids[i]
		}
		if cn {
			return true
		}
		if ln {
			return false
		}
		return lids[i] > cids[i]
	}
	return len(lids) > len(cids)
}

func parseVersion(v string) ([3]uint64, string, bool) {
	var parts [3]uint64
	core, build, hasBuild := strings.Cut(v, "+")
	if hasBuild && !validVersionIdentifiers(build, false) {
		return parts, "", false
	}
	core, pre, hasPre := strings.Cut(core, "-")
	if hasPre && !validVersionIdentifiers(pre, true) {
		return parts, "", false
	}
	numbers := strings.Split(core, ".")
	if len(numbers) != 3 {
		return parts, "", false
	}
	for i, s := range numbers {
		if s == "" || (len(s) > 1 && s[0] == '0') {
			return parts, "", false
		}
		for _, ch := range s {
			if ch < '0' || ch > '9' {
				return parts, "", false
			}
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return parts, "", false
		}
		parts[i] = n
	}
	return parts, pre, true
}

func validVersionIdentifiers(s string, prerelease bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		numeric := true
		for _, ch := range id {
			if ch < '0' || ch > '9' {
				numeric = false
			}
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '-') {
				return false
			}
		}
		if prerelease && numeric && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	return v
}
