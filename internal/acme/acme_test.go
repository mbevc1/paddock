package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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

// waitFetched waits until no certificate fetch is running.
func waitFetched(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for m.fetching.Load() {
		if time.Now().After(deadline) {
			t.Fatal("certificate fetch still running")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The panel starts its first fetch before it serves challenges, so HTTP-01 must be on from New,
// and TLS-ALPN-01, which fails behind the front Apache, must never be tried.
func TestOnlyHTTP01TriedFromTheFirstFetch(t *testing.T) {
	ca := newFakeCA(t)
	m := New(Config{Hostname: "panel.example.com", CacheDir: t.TempDir(), DirectoryURL: ca.directory(), SelfSigned: selfPair(t, time.Now())})
	m.Prefetch()
	waitFetched(t, m)
	if got := ca.acceptedTypes(); !slices.Equal(got, []string{"http-01"}) {
		t.Errorf("challenges accepted = %q, want only http-01", got)
	}
}

// autocert answers a repeat request within a minute of real time from its own record of the
// failure, so the attempts are counted in Paddock's log rather than at the CA.
func TestFailedFetchesBackOff(t *testing.T) {
	ca := newFakeCA(t)
	now := time.Date(2026, 11, 18, 22, 30, 0, 0, time.UTC)
	var logs syncBuffer
	m := New(Config{Hostname: "panel.example.com", CacheDir: t.TempDir(), DirectoryURL: ca.directory(),
		SelfSigned: selfPair(t, now), Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	attempts := func() int { return strings.Count(logs.String(), "obtaining the panel certificate failed") }
	visit := func() {
		_, _ = m.GetCertificate(&tls.ClientHelloInfo{ServerName: "panel.example.com"})
		waitFetched(t, m)
	}

	visit()
	if attempts() != 1 || ca.requestCount() == 0 {
		t.Fatalf("first visit: %d failed attempts, %d CA requests", attempts(), ca.requestCount())
	}
	for i, wait := range []time.Duration{2, 4, 8, 16, 32, 60, 60} {
		wait *= time.Minute
		now = now.Add(wait - time.Second)
		visit()
		if attempts() != i+1 {
			t.Fatalf("a visit %v after failure %d started another attempt", wait-time.Second, i+1)
		}
		now = now.Add(time.Second)
		visit()
		if attempts() != i+2 {
			t.Fatalf("a visit %v after failure %d started no attempt", wait, i+1)
		}
	}
}

func TestRetryDelay(t *testing.T) {
	for failures, want := range map[int]time.Duration{1: 2 * time.Minute, 2: 4 * time.Minute, 5: 32 * time.Minute,
		6: time.Hour, 1000: time.Hour} {
		if got := retryDelay(failures); got != want {
			t.Errorf("retryDelay(%d) = %v, want %v", failures, got, want)
		}
	}
}

// Let's Encrypt allows five failed validations per hostname per hour.
func TestRetriesStayWithinTheFailedValidationLimit(t *testing.T) {
	var at []time.Duration
	var now time.Duration
	for n := 1; now < 48*time.Hour; n++ {
		at = append(at, now)
		now += retryDelay(n)
	}
	for i := range at {
		in := 0
		for _, a := range at[i:] {
			if a-at[i] < time.Hour {
				in++
			}
		}
		if in > 5 {
			t.Fatalf("%d attempts in the hour from %v", in, at[i])
		}
	}
}

// syncBuffer is a bytes.Buffer safe for the fetch goroutine to log into.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
