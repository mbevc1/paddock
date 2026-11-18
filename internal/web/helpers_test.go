package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/web/store"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func mustUser(t *testing.T, s *store.Store, name string) store.User {
	t.Helper()
	u, err := s.GetUserByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func ioPipe() (*io.PipeReader, *io.PipeWriter) { return io.Pipe() }

// streamRecorder is a ResponseWriter that passes the body through a pipe and can flush.
type streamRecorder struct {
	w      *io.PipeWriter
	header http.Header
}

func (s *streamRecorder) Header() http.Header         { return s.header }
func (s *streamRecorder) Write(b []byte) (int, error) { return s.w.Write(b) }
func (s *streamRecorder) WriteHeader(int)             {}
func (s *streamRecorder) Flush()                      {}

// uploadPair returns a valid certificate chain and key for a domain.
func uploadPair(t *testing.T, domain string) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
}
