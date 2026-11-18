package validate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"
)

const (
	maxPEMBytes   = 64 * 1024
	maxChainCerts = 10
	minRSAKeyBits = 2048
)

// CertBundle is an uploaded certificate after validation, re-encoded so nothing but the
// parsed certificates and key is written to disk.
type CertBundle struct {
	ChainPEM    []byte
	KeyPEM      []byte
	NotAfter    time.Time
	Fingerprint string // SHA-256 of the leaf, hex
}

type publicKeyEqualer interface {
	Equal(crypto.PublicKey) bool
}

// CertificateBundle checks a PEM chain (leaf first) and its private key: the key must match
// the leaf, the leaf must be valid at now and cover every domain, and the key must be RSA of
// at least 2048 bits or ECDSA P-256 or P-384. Errors never quote the key.
func CertificateBundle(chainPEM, keyPEM string, domains []string, now time.Time) (CertBundle, error) {
	if len(chainPEM) > maxPEMBytes || len(keyPEM) > maxPEMBytes {
		return CertBundle{}, invalid("certificate or key larger than %d bytes", maxPEMBytes)
	}
	certs, err := parseChain(chainPEM)
	if err != nil {
		return CertBundle{}, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return CertBundle{}, err
	}
	leaf := certs[0]
	pub, ok := key.Public().(publicKeyEqualer)
	if !ok || !pub.Equal(leaf.PublicKey) {
		return CertBundle{}, invalid("private key does not match the certificate")
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return CertBundle{}, invalid("certificate is not valid now (valid %s to %s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	for _, d := range domains {
		if err := leaf.VerifyHostname(d); err != nil {
			return CertBundle{}, invalid("certificate does not cover %s", d)
		}
	}

	var chain strings.Builder
	for _, c := range certs {
		if err := pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return CertBundle{}, err
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CertBundle{}, invalid("private key cannot be encoded")
	}
	sum := sha256.Sum256(leaf.Raw)
	return CertBundle{
		ChainPEM:    []byte(chain.String()),
		KeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		NotAfter:    leaf.NotAfter.UTC(),
		Fingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

func parseChain(chainPEM string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(chainPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, invalid("chain must contain only CERTIFICATE blocks")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, invalid("chain contains an unreadable certificate")
		}
		certs = append(certs, c)
		if len(certs) > maxChainCerts {
			return nil, invalid("chain longer than %d certificates", maxChainCerts)
		}
	}
	if len(certs) == 0 {
		return nil, invalid("no certificate found")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, invalid("chain contains data outside PEM blocks")
	}
	return certs, nil
}

func parseKey(keyPEM string) (crypto.Signer, error) {
	block, rest := pem.Decode([]byte(keyPEM))
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, invalid("key must be exactly one PEM block")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, invalid("unsupported key block %q", block.Type)
	}
	if err != nil {
		return nil, invalid("private key is unreadable")
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minRSAKeyBits {
			return nil, invalid("RSA key must have at least %d bits", minRSAKeyBits)
		}
		return k, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, invalid("ECDSA key must use P-256 or P-384")
		}
		return k, nil
	default:
		return nil, invalid("key must be RSA or ECDSA")
	}
}
