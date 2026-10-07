package listener

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"opennofrp/pkg/protocol"
	"opennofrp/server/internal/session"
)

func selfSignedPEM(t *testing.T, host string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
	return certPEM, keyPEM
}

func TestValidateCertPair(t *testing.T) {
	c, k := selfSignedPEM(t, "a.test")
	if err := ValidateCertPair(c, k); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
	_, k2 := selfSignedPEM(t, "a.test")
	if err := ValidateCertPair(c, k2); err == nil {
		t.Fatalf("mismatched pair accepted")
	}
}

func TestRedirectTarget(t *testing.T) {
	m := NewManager("127.0.0.1", slog.New(slog.NewTextHandler(io.Discard, nil)), func(string) *session.Session { return nil })
	need := m.updateTLSState([]RuleView{
		{ID: 1, Protocol: "http", Port: 443, Domains: []string{"a.test"}, TLSMode: "acme", RedirectHTTPS: true},
		{ID: 2, Protocol: "http", Port: 8443, Domains: []string{"*.b.test"}, TLSMode: "custom", RedirectHTTPS: true},
		{ID: 3, Protocol: "http", Port: 443, Domains: []string{"c.test"}, TLSMode: "acme"},
	})
	if !need {
		t.Fatal("expected redirect listener to be needed")
	}
	if p, ok := m.redirectTarget("A.test:80"); !ok || p != 443 {
		t.Errorf("a.test redirect = %d,%v", p, ok)
	}
	if p, ok := m.redirectTarget("x.b.test"); !ok || p != 8443 {
		t.Errorf("x.b.test redirect = %d,%v", p, ok)
	}
	if _, ok := m.redirectTarget("c.test"); ok {
		t.Errorf("c.test should not redirect")
	}
	hosts := strings.Join(m.ACMEHosts(), ",")
	if !strings.Contains(hosts, "a.test") || !strings.Contains(hosts, "c.test") || strings.Contains(hosts, "b.test") {
		t.Errorf("acme hosts = %q", hosts)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x.b.test/p?q=1", nil)
	serveRedirect(rec, req, 8443)
	if rec.Code != 301 || rec.Header().Get("Location") != "https://x.b.test:8443/p?q=1" {
		t.Errorf("redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHTTPSCustomCertE2E(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("proto=" + r.Header.Get("X-Forwarded-Proto")))
	}))
	defer backend.Close()

	a, b := net.Pipe()
	srvYm, err := yamux.Server(a, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	cliYm, err := yamux.Client(b, yamux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer srvYm.Close()
	defer cliYm.Close()
	go fakeClient(t, cliYm, backend.Listener.Addr().String())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sess := session.New("s", "c1", srvYm, logger, nil)
	sess.Capabilities = []string{protocol.CapDialAck}
	m := NewManager("127.0.0.1", logger, func(string) *session.Session { return sess })

	certPEM, keyPEM := selfSignedPEM(t, "a.test")
	cert, err := parseRouteCert(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	route := httpRoute{RuleID: 1, ClientID: "c1", Domains: []string{"a.test"}, PathPrefix: "/", TLSMode: "custom", cert: cert}
	if err := m.openHTTPPort(0, []httpRoute{route}); err != nil {
		t.Fatal(err)
	}
	defer m.closeHTTPPort(0)
	addr := m.http[0].ln.Addr().String()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(certPEM))
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "a.test"},
	}}
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Host = "a.test"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "proto=https" {
		t.Fatalf("https: %d %q", resp.StatusCode, body)
	}
}
