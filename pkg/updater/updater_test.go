package updater

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"
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

func TestDownloadAssetToFileFallback(t *testing.T) {
	t.Run("header error fallback", func(t *testing.T) {
		// 1. Direct server fails with 500 error
		directSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "server error", http.StatusInternalServerError)
		}))
		defer directSrv.Close()

		mirrorContent := []byte("mirror-binary-content-12345")
		mirrorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(mirrorContent)
		}))
		defer mirrorSrv.Close()

		tmpFile, err := os.CreateTemp("", "updater-test-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = downloadAssetToFile(ctx, tmpFile, directSrv.URL+"/asset", mirrorSrv.URL+"/")
		if err != nil {
			t.Fatalf("downloadAssetToFile failed: %v", err)
		}

		content, err := os.ReadFile(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(content, mirrorContent) {
			t.Fatalf("got %q, want %q", string(content), string(mirrorContent))
		}
	})

	t.Run("slow body timeout fallback", func(t *testing.T) {
		// Direct server sends 200 OK headers immediately, but stalls on body
		directSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(500 * time.Millisecond) // Stalls longer than test timeout
		}))
		defer directSrv.Close()

		mirrorContent := []byte("mirror-binary-content-from-slow-body")
		mirrorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(mirrorContent)
		}))
		defer mirrorSrv.Close()

		tmpFile, err := os.CreateTemp("", "updater-test-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		oldTimeout := directDownloadTimeout
		directDownloadTimeout = 50 * time.Millisecond
		defer func() { directDownloadTimeout = oldTimeout }()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = downloadAssetToFile(ctx, tmpFile, directSrv.URL+"/asset", mirrorSrv.URL+"/")
		if err != nil {
			t.Fatalf("downloadAssetToFile failed: %v", err)
		}

		content, err := os.ReadFile(tmpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(content, mirrorContent) {
			t.Fatalf("got %q, want %q", string(content), string(mirrorContent))
		}
	})
}
