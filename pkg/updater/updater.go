// Package updater 负责检查 GitHub Releases 最新版本并支持在线一键自更新 (Self-Update)。
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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
		if strings.EqualFold(a.Name, targetSuffix) || strings.Contains(strings.ToLower(a.Name), strings.ToLower(targetSuffix)) {
			return a.BrowserDownloadURL
		}
	}
	return ""
}

// SelfUpdate 执行当前二进制文件的在线一键更新
func SelfUpdate(ctx context.Context, componentName string) error {
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
	fmt.Printf("[OpenNoFrp] 正在下载最新版本: %s ...\n", downloadURL)

	// 首先尝试 GitHub 直连下载，失败或超时则回退到 YearnStudio 镜像加速
	var downResp *http.Response
	downReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err == nil {
		downClient := &http.Client{Timeout: 15 * time.Second}
		downResp, err = downClient.Do(downReq)
	}

	if err != nil || (downResp != nil && downResp.StatusCode != http.StatusOK) {
		if downResp != nil {
			downResp.Body.Close()
		}
		mirrorURL := mirrorPrefix + downloadURL
		fmt.Printf("[OpenNoFrp] 直连 GitHub 下载失败或超时，正在自动切换至国内加速镜像: %s ...\n", mirrorURL)
		mirrorReq, mErr := http.NewRequestWithContext(ctx, http.MethodGet, mirrorURL, nil)
		if mErr != nil {
			return fmt.Errorf("创建镜像请求失败: %w", mErr)
		}
		mirrorClient := &http.Client{Timeout: 60 * time.Second}
		downResp, err = mirrorClient.Do(mirrorReq)
		if err != nil {
			return fmt.Errorf("通过加速镜像下载依然失败: %w", err)
		}
	}
	defer downResp.Body.Close()

	if downResp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载返回 HTTP %d", downResp.StatusCode)
	}

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

	_, err = io.Copy(tmpFile, downResp.Body)
	tmpFile.Close()
	if err != nil {
		return fmt.Errorf("写入临时升级文件失败: %w", err)
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
	fmt.Printf("[OpenNoFrp] 请执行以下命令重启对应服务以生效：\n")
	if componentName == "opennofrp-server" {
		fmt.Printf("  sudo systemctl restart opennofrp-server\n")
	} else {
		fmt.Printf("  sudo systemctl restart opennofrp-client\n")
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
	if c == "dev" {
		return true // 开发版本允许升级至正式发布版
	}
	return c != l
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	return v
}
