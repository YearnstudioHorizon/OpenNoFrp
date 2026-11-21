package updater

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedAssetMetadataAndContents(t *testing.T) {
	content := []byte("verified release binary")
	name := "opennofrp-client-linux-amd64"
	entry := fmt.Sprintf("%x %d %s\n", sha256.Sum256(content), len(content), name)
	digest, err := readAssetDigest(strings.NewReader(entry), name)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), name)
	for _, c := range []struct {
		data []byte
		pass bool
	}{
		{content, true},
		{content[:len(content)-1], false},
		{append(append([]byte(nil), content...), 'x'), false},
		{[]byte(strings.Repeat("x", len(content))), false},
	} {
		if err := os.WriteFile(path, c.data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := digest.verify(path); (err == nil) != c.pass {
			t.Fatalf("verify release bytes: expected pass=%v, got %v", c.pass, err)
		}
	}
	for _, manifest := range []string{entry + entry, strings.ReplaceAll(entry, name, "other-platform")} {
		if _, err := readAssetDigest(strings.NewReader(manifest), name); err == nil {
			t.Fatal("ambiguous or missing platform entry accepted")
		}
	}
}
