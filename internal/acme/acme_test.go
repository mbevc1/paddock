package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func selfPair(t *testing.T, now time.Time) tls.Certificate {
	t.Helper()
	c, k, fp, err := SelfSigned("panel.example.com", []net.IP{net.ParseIP("192.0.2.5")}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != 95 {
		t.Errorf("fingerprint = %q", fp)
	}
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// failingCA refuses every ACME request without a retryable status, so fetches end quickly.
func failingCA(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "refused", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFallsBackToSelfSigned(t *testing.T) {
	now := time.Now()
	self := selfPair(t, now)
	m := New(Config{Hostname: "panel.example.com", CacheDir: t.TempDir(), DirectoryURL: failingCA(t), SelfSigned: self})
	for _, sni := range []string{"", "other.example.com", "192.0.2.5", "panel.example.com"} {
		got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil || got != m.self {
			t.Errorf("SNI %q: got %p, %v; want the self-signed certificate", sni, got, err)
		}
	}
	if m.Trusted() {
		t.Error("trusted without an ACME certificate")
	}
	leaf, err := x509.ParseCertificate(self.Certificate[0])
	if err != nil || leaf.VerifyHostname("panel.example.com") != nil || leaf.VerifyHostname("192.0.2.5") != nil {
		t.Errorf("self-signed certificate does not cover the hostname and IP: %v", err)
	}
}

func TestServesCachedACMECertificate(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	issued := selfPair(t, now)
	// autocert caches the ECDSA key and chain under the hostname.
	certPEM, keyPEM, _, err := SelfSigned("panel.example.com", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "panel.example.com"), append(keyPEM, certPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	m := New(Config{Hostname: "panel.example.com", CacheDir: dir, DirectoryURL: failingCA(t), SelfSigned: issued})
	hello := &tls.ClientHelloInfo{
		ServerName:       "panel.example.com",
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	if first, _ := m.GetCertificate(hello); first != m.self {
		t.Error("the first handshake waited for ACME instead of serving the self-signed certificate")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !m.Trusted() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !m.Trusted() {
		t.Fatal("cached ACME certificate never loaded")
	}
	got, err := m.GetCertificate(hello)
	if err != nil || got == m.self {
		t.Fatalf("got the self-signed certificate after loading: %v", err)
	}
	if other, _ := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); other != m.self {
		t.Error("ACME certificate served for another name")
	}
}

func TestChallengeHandler(t *testing.T) {
	m := New(Config{Hostname: "panel.example.com", CacheDir: t.TempDir(), SelfSigned: selfPair(t, time.Now())})
	h := m.ChallengeHandler()
	for _, tc := range []struct {
		method, path string
	}{
		{"GET", "/"},
		{"GET", "/login"},
		{"POST", "/.well-known/acme-challenge/token"},
		{"GET", "/.well-known/acme-challenge/unknown-token"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), tc.method, "http://panel.example.com"+tc.path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
}

func TestServeChallengesSocket(t *testing.T) {
	m := New(Config{Hostname: "panel.example.com", CacheDir: t.TempDir(), SelfSigned: selfPair(t, time.Now())})
	socket := filepath.Join(t.TempDir(), "acme.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.ServeChallenges(ctx, socket) }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	var resp *http.Response
	var err error
	for range 50 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://panel/.well-known/acme-challenge/x", nil)
		if resp, err = client.Do(req); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if fi, err := os.Stat(socket); err != nil || fi.Mode().Perm() != 0o666 {
		t.Errorf("socket mode = %v, %v", fi.Mode().Perm(), err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("ServeChallenges = %v", err)
	}
}
