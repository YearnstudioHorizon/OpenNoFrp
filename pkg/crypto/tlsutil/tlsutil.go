// Package tlsutil 提供自签名证书生成、持久化、TLS 配置构造与 SHA-256 证书指纹 (Certificate Pinning) 校验功能。
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertFingerprint 计算 X.509 证书的 SHA-256 指纹，格式为大写冒号分隔：
// 例如："SHA256:2D:4F:9A:..."
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	var sb strings.Builder
	sb.WriteString("SHA256:")
	for i, b := range sum {
		if i > 0 {
			sb.WriteString(":")
		}
		sb.WriteString(fmt.Sprintf("%02X", b))
	}
	return sb.String()
}

// NormalizeFingerprint 规范化指纹字符串，便于容错比对：
// 移除 "SHA256:" 前缀、冒号、连字符和空格，转为全小写十六进制字符串。
func NormalizeFingerprint(fp string) string {
	s := strings.TrimSpace(strings.ToUpper(fp))
	s = strings.TrimPrefix(s, "SHA256:")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return strings.ToLower(s)
}

// GenerateSelfSignedCert 生成用于服务端的自签名 ECDSA P-256 证书和私钥
func GenerateSelfSignedCert(hosts []string) (certPEM, keyPEM []byte, fingerprint string, err error) {
	// 1. 生成 ECDSA 私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("tlsutil: 生成私钥失败: %w", err)
	}

	// 2. 构造证书模版
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, "", fmt.Errorf("tlsutil: 生成证书序列号失败: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"OpenNoFrp"},
			CommonName:   "opennofrp-server",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10年有效期
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 默认信任本地环回
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	template.DNSNames = append(template.DNSNames, "localhost")

	for _, h := range hosts {
		if h == "" || h == "0.0.0.0" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// 3. 签名生成证书 DER 字节流
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("tlsutil: 创建证书失败: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, "", fmt.Errorf("tlsutil: 解析自签名证书失败: %w", err)
	}
	fp := CertFingerprint(cert)

	// 4. PEM 编码
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("tlsutil: 序列化 EC 私钥失败: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, fp, nil
}

// LoadOrCreateCert 检查指定路径的证书和私钥文件；
// 若不存在则自动生成自签名证书并持久化保存；若存在则直接读取加载并计算其 SHA-256 指纹。
func LoadOrCreateCert(certPath, keyPath string, hosts []string) (tls.Certificate, string, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		// 创建父目录
		if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
			return tls.Certificate{}, "", fmt.Errorf("tlsutil: 创建证书目录失败: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return tls.Certificate{}, "", fmt.Errorf("tlsutil: 创建私钥目录失败: %w", err)
		}

		certPEM, keyPEM, fp, err := GenerateSelfSignedCert(hosts)
		if err != nil {
			return tls.Certificate{}, "", err
		}

		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return tls.Certificate{}, "", fmt.Errorf("tlsutil: 写入证书文件失败: %w", err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, "", fmt.Errorf("tlsutil: 写入私钥文件失败: %w", err)
		}

		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return tls.Certificate{}, "", fmt.Errorf("tlsutil: 解析新证书失败: %w", err)
		}
		return tlsCert, fp, nil
	}

	// 已存在，直接从磁盘读取
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("tlsutil: 加载证书对失败: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("tlsutil: 解析证书文件失败: %w", err)
	}

	return tlsCert, CertFingerprint(x509Cert), nil
}

// NewServerTLSConfig 创建服务端的 TLS 配置
func NewServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// NewClientTLSConfig 创建客户端的 TLS 配置，启用证书指纹校验 (Certificate Pinning)
func NewClientTLSConfig(expectedFingerprint string, onFirstSeenFingerprint func(fp string) error) *tls.Config {
	expectedNorm := NormalizeFingerprint(expectedFingerprint)

	return &tls.Config{
		InsecureSkipVerify: true, // 跳过系统 CA 校验，改由我们严格校验公钥/证书 SHA-256 指纹
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("tlsutil: 服务端未提供任何证书")
			}

			// 获取服务端对端叶子证书并计算 SHA-256
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("tlsutil: 解析服务端证书失败: %w", err)
			}

			actualFP := CertFingerprint(cert)
			actualNorm := NormalizeFingerprint(actualFP)

			// 1. 如果客户端已配置指纹，进行强校验 (Certificate Pinning)
			if expectedNorm != "" {
				if actualNorm != expectedNorm {
					return fmt.Errorf("tlsutil: 证书指纹不匹配！可能遭受中间人攻击(MITM)。期望: %s, 实际: %s", expectedFingerprint, actualFP)
				}
				return nil
			}

			// 2. 如果未配置指纹，触发 TOFU (首次使用信任) 回调进行记录
			if onFirstSeenFingerprint != nil {
				return onFirstSeenFingerprint(actualFP)
			}

			return nil
		},
	}
}

// RawCertFingerprint 直接计算 DER 字节切片的 SHA256 指纹字符串
func RawCertFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
