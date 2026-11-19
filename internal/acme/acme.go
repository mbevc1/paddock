// Package acme gets the panel's own Let's Encrypt certificate over HTTP-01 and falls back to
// the self-signed certificate made at install (§10).
package acme

import (
	"context"
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
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	xacme "golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// RenewBefore starts renewal this long before expiry (§T1.20).
	RenewBefore = 30 * 24 * time.Hour
	// LetsEncryptStaging is the staging directory, for tests against real ACME.
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	selfSignedLife     = 10 * 365 * 24 * time.Hour
	// FirstRetryAfter is the wait after a failed attempt, doubling with each further failure.
	// Let's Encrypt allows five failed validations per hostname per hour: waits of 2, 4, 8, 16
	// and 32 minutes fit five attempts into the first hour.
	FirstRetryAfter = 2 * time.Minute
	// MaxRetryAfter caps the wait between attempts.
	MaxRetryAfter   = time.Hour
	challengePrefix = "/.well-known/acme-challenge/"
)

// Manager serves the panel certificate: Let's Encrypt for the panel hostname when available,
// the self-signed certificate otherwise.
type Manager struct {
	hostname string
	auto     *autocert.Manager
	self     *tls.Certificate
	trusted  atomic.Bool
	fetching atomic.Bool
	// nextTry is the Unix time in nanoseconds before which no new attempt starts.
	nextTry   atomic.Int64
	failures  atomic.Int32
	report    *caReport
	challenge http.Handler
	now       func() time.Time
	log       *slog.Logger
}

// Config configures a Manager.
type Config struct {
	Hostname string
	// CacheDir keeps the ACME account key and certificates (web.db's directory, mode 0700).
	CacheDir string
	Email    string
	// DirectoryURL defaults to Let's Encrypt production.
	DirectoryURL string
	SelfSigned   tls.Certificate
	Log          *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// New returns a Manager. It does not contact the CA until a certificate is needed.
func New(c Config) *Manager {
	log := c.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	self := c.SelfSigned
	m := &Manager{hostname: strings.ToLower(c.Hostname), self: &self, log: log, report: &caReport{}}
	m.auto = &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		HostPolicy:  autocert.HostWhitelist(m.hostname),
		Cache:       autocert.DirCache(c.CacheDir),
		Email:       c.Email,
		RenewBefore: RenewBefore,
	}
	dir := c.DirectoryURL
	if dir == "" {
		dir = autocert.DefaultACMEDirectory
	}
	m.auto.Client = &xacme.Client{DirectoryURL: dir,
		HTTPClient: &http.Client{Transport: httpOnly{base: http.DefaultTransport, report: m.report}}}
	// autocert offers HTTP-01 only after its handler exists, and only HTTP-01 works behind the
	// front Apache, so the handler is made before any certificate can be requested.
	m.challenge = m.auto.HTTPHandler(http.NotFoundHandler())
	m.now = c.Now
	if m.now == nil {
		m.now = time.Now
	}
	return m
}

// GetCertificate implements tls.Config.GetCertificate. No handshake waits for the CA: until a
// Let's Encrypt certificate is in hand, the self-signed one is served while one background
// fetch runs. Afterwards autocert answers from memory and renews in the background.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), m.hostname) {
		return m.self, nil
	}
	if m.trusted.Load() {
		cert, err := m.auto.GetCertificate(hello)
		if err == nil {
			return cert, nil
		}
		m.log.Warn("ACME certificate unavailable, serving the self-signed one", "err", err)
		return m.self, nil
	}
	m.fetch(hello)
	return m.self, nil
}

func (m *Manager) fetch(hello *tls.ClientHelloInfo) {
	if m.now().UnixNano() < m.nextTry.Load() || !m.fetching.CompareAndSwap(false, true) {
		return
	}
	h := *hello
	go func() {
		defer m.fetching.Store(false)
		m.report.take()
		m.log.Info("requesting the panel certificate", "hostname", m.hostname)
		cert, err := m.auto.GetCertificate(&h)
		if err != nil {
			wait := retryDelay(int(m.failures.Add(1)))
			m.nextTry.Store(m.now().Add(wait).UnixNano())
			args := []any{"err", err, "retry_in", wait.String()}
			if reason := m.report.take(); reason != "" {
				args = append(args, "ca_error", reason)
			}
			m.log.Warn("obtaining the panel certificate failed", args...)
			return
		}
		m.failures.Store(0)
		m.trusted.Store(true)
		if cert.Leaf != nil {
			m.log.Info("obtained the panel certificate", "not_after", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
		}
	}()
}

// retryDelay is the wait after the given number of consecutive failures, counting from 1.
func retryDelay(failures int) time.Duration {
	d := FirstRetryAfter
	for i := 1; i < failures && d < MaxRetryAfter; i++ {
		d *= 2
	}
	return min(d, MaxRetryAfter)
}

// Trusted reports whether a Let's Encrypt certificate has been served, which turns HSTS on.
func (m *Manager) Trusted() bool { return m.trusted.Load() }

// Prefetch starts fetching the certificate, so it is ready before the first visitor.
func (m *Manager) Prefetch() {
	_, _ = m.GetCertificate(&tls.ClientHelloInfo{
		ServerName:       m.hostname,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
}

// ChallengeHandler answers HTTP-01 challenges and nothing else.
func (m *Manager) ChallengeHandler() http.Handler {
	h := m.challenge
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, challengePrefix) {
			http.NotFound(w, r)
			return
		}
		r.Host = m.hostname
		h.ServeHTTP(w, r)
	})
}

// ServeChallenges answers challenges on a Unix socket, which the front Apache proxies to
// (§7.4), until ctx ends. Challenge responses are public, so the socket is world-writable.
func (m *Manager) ServeChallenges(ctx context.Context, socket string) error {
	if fi, err := os.Lstat(socket); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket", socket)
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	}
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(socket, 0o666); err != nil { // #nosec G302 -- Apache connects as user apache.
		_ = l.Close()
		return err
	}
	srv := &http.Server{Handler: m.ChallengeHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// SelfSigned makes an ECDSA P-256 certificate for the hostname and the server's IPs, and
// returns its PEM certificate, PEM key, and SHA-256 fingerprint.
func SelfSigned(hostname string, ips []net.IP, now time.Time) (certPEM, keyPEM []byte, fingerprint string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		IPAddresses:  ips,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(selfSignedLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, "", err
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}),
		formatFingerprint(sum[:]), nil
}

func formatFingerprint(sum []byte) string {
	h := strings.ToUpper(hex.EncodeToString(sum))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}
