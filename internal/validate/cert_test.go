package validate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

var certNow = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func selfSigned(t *testing.T, key crypto.Signer, names []string, notBefore, notAfter time.Time) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func keyPEM(t *testing.T, key any, pkcs8 bool) string {
	t.Helper()
	if !pkcs8 {
		if ec, ok := key.(*ecdsa.PrivateKey); ok {
			der, err := x509.MarshalECPrivateKey(ec)
			if err != nil {
				t.Fatal(err)
			}
			return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestCertificateBundle(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"shop.example.com", "www.shop.example.com"}
	valid := selfSigned(t, ec, names, certNow.Add(-time.Hour), certNow.Add(90*24*time.Hour))

	b, err := CertificateBundle(valid, keyPEM(t, ec, false), names, certNow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b.KeyPEM), "-----BEGIN PRIVATE KEY-----") || len(b.Fingerprint) != 64 ||
		!b.NotAfter.Equal(certNow.Add(90*24*time.Hour)) || string(b.ChainPEM) != valid {
		t.Errorf("bundle = %+v", b)
	}

	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		chain, key string
		domains    []string
	}{
		"key does not match": {valid, keyPEM(t, other, true), names},
		"expired":            {selfSigned(t, ec, names, certNow.Add(-48*time.Hour), certNow.Add(-time.Hour)), keyPEM(t, ec, true), names},
		"not yet valid":      {selfSigned(t, ec, names, certNow.Add(time.Hour), certNow.Add(48*time.Hour)), keyPEM(t, ec, true), names},
		"domain missing":     {valid, keyPEM(t, ec, true), append(names, "other.example.com")},
		"empty chain":        {"", keyPEM(t, ec, true), names},
		"key in chain":       {valid + keyPEM(t, ec, true), keyPEM(t, ec, true), names},
		"junk after chain":   {valid + "Include /etc/shadow\n", keyPEM(t, ec, true), names},
		"two keys":           {valid, keyPEM(t, ec, true) + keyPEM(t, ec, true), names},
		"small RSA key":      {selfSigned(t, rsa1024, names, certNow.Add(-time.Hour), certNow.Add(time.Hour)), keyPEM(t, rsa1024, true), names},
		"ed25519 key":        {selfSigned(t, edKey, names, certNow.Add(-time.Hour), certNow.Add(time.Hour)), keyPEM(t, edKey, true), names},
		"P-521 key":          {selfSigned(t, p521, names, certNow.Add(-time.Hour), certNow.Add(time.Hour)), keyPEM(t, p521, true), names},
		"oversized":          {strings.Repeat("A", maxPEMBytes+1), keyPEM(t, ec, true), names},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CertificateBundle(tc.chain, tc.key, tc.domains, certNow)
			assertInvalid(t, err)
			if err != nil && strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Errorf("error quotes the key: %v", err)
			}
		})
	}
}
