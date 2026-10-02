package tlsutil

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAndFingerprint(t *testing.T) {
	certPEM, keyPEM, fp, err := GenerateSelfSignedCert([]string{"example.com", "1.2.3.4"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("empty PEM returned")
	}

	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("expected SHA256: prefix, got: %s", fp)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode certificate PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	calculatedFP := CertFingerprint(cert)
	if calculatedFP != fp {
		t.Fatalf("fingerprint mismatch: got %s, want %s", calculatedFP, fp)
	}

	norm1 := NormalizeFingerprint(fp)
	norm2 := NormalizeFingerprint(strings.ToLower(strings.TrimPrefix(fp, "SHA256:")))
	if norm1 != norm2 {
		t.Fatalf("normalize mismatch: %s vs %s", norm1, norm2)
	}
}

func TestLoadOrCreateCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tlsutil-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")

	// 1. 首次创建
	cert1, fp1, err := LoadOrCreateCert(certPath, keyPath, []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("LoadOrCreateCert creation failed: %v", err)
	}
	if len(cert1.Certificate) == 0 || fp1 == "" {
		t.Fatal("invalid cert or empty fingerprint")
	}

	// 2. 第二次加载（必须与第一次一致）
	cert2, fp2, err := LoadOrCreateCert(certPath, keyPath, []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("LoadOrCreateCert reload failed: %v", err)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint changed across reload: %s vs %s", fp1, fp2)
	}
	if len(cert2.Certificate) == 0 {
		t.Fatal("empty certificate after reload")
	}
}
