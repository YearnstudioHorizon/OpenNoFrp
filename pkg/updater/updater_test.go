package updater

import (
	"fmt"
	"runtime"
	"testing"
)

func TestFindMatchingAssetExcludesArchives(t *testing.T) {
	name := fmt.Sprintf("opennofrp-server-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	assets := []ReleaseAsset{{Name: name + ".zip", BrowserDownloadURL: "archive"}, {Name: name + ".sha256", BrowserDownloadURL: "checksum"}, {Name: name, BrowserDownloadURL: "binary"}}
	var info UpdateInfo
	if got := info.FindMatchingAsset("opennofrp-server", assets); got != "binary" {
		t.Fatalf("selected asset: %s", got)
	}
	if got := info.FindMatchingAsset("opennofrp-server", assets[:2]); got != "" {
		t.Fatalf("selected non-binary asset: %s", got)
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"v0.1.0", "v0.1.0", false},
		{"v0.1.0", "v0.2.0", true},
		{"0.1.0", "v0.1.0", false},
		{"0.1.0", "v0.2.0", true},
		{"dev", "v1.0.0", true},
		{"v0.4.1", "v0.4.0", false},
		{"v0.9.0", "v0.10.0", true},
		{"v0.4.1-rc.2", "v0.4.1-rc.10", true},
		{"v0.4.1-rc.1", "v0.4.1", true},
		{"v0.4.1", "v0.4.1-rc.1", false},
		{"v0.4.1+build1", "v0.4.1+build2", false},
		{"v0.4.1", "invalid", false},
		{"dev", "invalid", false},
		{"v0.4.1", "v00.5.0", false},
	}

	for _, tt := range tests {
		got := compareVersions(tt.current, tt.latest)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}
