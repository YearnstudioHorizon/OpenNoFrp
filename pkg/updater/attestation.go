package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ReleaseScript contains the equivalent release verification helpers for
// the generated Linux and macOS bootstrap scripts.
//
//go:embed release.sh
var ReleaseScript string

const (
	releaseManifest = "release-manifest.txt"
	releaseBundle   = "release-attestation.jsonl"
	maxAssetSize    = 200 << 20
)

type assetDigest struct {
	size int64
	hex  string
}

func fetchVerifiedDigest(ctx context.Context, base, tag, asset string) (assetDigest, error) {
	dir, err := os.MkdirTemp("", "opennofrp-attestation-")
	if err != nil {
		return assetDigest{}, err
	}
	defer os.RemoveAll(dir)
	for _, name := range []string{releaseManifest, releaseBundle} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			return assetDigest{}, err
		}
		err = downloadBounded(ctx, f, base+"/"+name, 20*time.Second, 1<<20)
		closeErr := f.Close()
		if err != nil {
			return assetDigest{}, err
		}
		if closeErr != nil {
			return assetDigest{}, closeErr
		}
	}

	verifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	manifest := filepath.Join(dir, releaseManifest)
	cmd := exec.CommandContext(verifyCtx, "gh", "attestation", "verify", manifest,
		"--hostname", "github.com", "--repo", GitHubRepo, "--bundle", filepath.Join(dir, releaseBundle),
		"--signer-workflow", GitHubRepo+"/.github/workflows/release.yml",
		"--source-ref", "refs/tags/"+tag, "--deny-self-hosted-runners")
	if out, err := cmd.CombinedOutput(); err != nil {
		return assetDigest{}, fmt.Errorf("release attestation verification (GitHub CLI required): %w: %s", err, out)
	}

	f, err := os.Open(manifest)
	if err != nil {
		return assetDigest{}, err
	}
	defer f.Close()
	return readAssetDigest(f, asset)
}

func readAssetDigest(r io.Reader, asset string) (assetDigest, error) {
	var digest assetDigest
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) != 3 || fields[2] != asset {
			continue
		}
		if digest.size != 0 {
			return assetDigest{}, fmt.Errorf("duplicate release asset %s", asset)
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		hash, hexErr := hex.DecodeString(fields[0])
		if err != nil || size < 1 || size > maxAssetSize || hexErr != nil || len(hash) != sha256.Size {
			return assetDigest{}, fmt.Errorf("invalid release manifest entry for %s", asset)
		}
		digest = assetDigest{size, strings.ToLower(fields[0])}
	}
	if err := scan.Err(); err != nil {
		return assetDigest{}, err
	}
	if digest.size == 0 {
		return assetDigest{}, fmt.Errorf("missing release manifest entry for %s", asset)
	}
	return digest, nil
}

func (d assetDigest) verify(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, d.size+1))
	if err != nil {
		return err
	}
	if n != d.size || hex.EncodeToString(hash.Sum(nil)) != d.hex {
		return fmt.Errorf("download size or SHA-256 digest differs from signed release")
	}
	return nil
}
