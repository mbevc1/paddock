package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

// caProblem is the error a failed challenge carries, as Let's Encrypt reports it.
const caProblem = "Invalid response from http://panel.example.com/.well-known/acme-challenge/token-http-01: 503"

// fakeCA is just enough of an RFC 8555 server for autocert. It offers tls-alpn-01 and http-01
// for each order's one authorization and records which challenges the client accepts. A failing
// CA marks every accepted challenge invalid; an issuing one marks it valid and signs the CSR.
type fakeCA struct {
	srv   *httptest.Server
	issue bool
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate

	mu       sync.Mutex
	nonce    int
	orders   int
	accepted []string
	status   map[string]string // authorization path to status
	chains   map[string][]byte // order number to PEM chain
	requests int
}

func newFakeCA(t *testing.T) *fakeCA { return startFakeCA(t, false) }

// newIssuingCA validates every accepted challenge and issues a certificate for the CSR.
func newIssuingCA(t *testing.T) *fakeCA { return startFakeCA(t, true) }

func startFakeCA(t *testing.T, issue bool) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &fakeCA{issue: issue, key: key, cert: cert, status: map[string]string{}, chains: map[string][]byte{}}
	ca.srv = httptest.NewServer(http.HandlerFunc(ca.serve))
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeCA) directory() string { return ca.srv.URL + "/dir" }

func (ca *fakeCA) acceptedTypes() []string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return append([]string(nil), ca.accepted...)
}

func (ca *fakeCA) requestCount() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.requests
}

func (ca *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.requests++
	ca.nonce++
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", ca.nonce))
	base := ca.srv.URL
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	identifier := map[string]string{"type": "dns", "value": "panel.example.com"}
	order := func(n string) map[string]any {
		o := map[string]any{
			"status": "pending", "identifiers": []any{identifier},
			"authorizations": []string{base + "/authz/" + n}, "finalize": base + "/finalize/" + n,
		}
		if ca.status["/authz/"+n] == "valid" {
			o["status"] = "ready"
		}
		if ca.chains[n] != nil {
			o["status"], o["certificate"] = "valid", base+"/cert/"+n
		}
		return o
	}
	switch p := r.URL.Path; {
	case p == "/dir":
		reply(http.StatusOK, map[string]string{
			"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order",
			"revokeCert": base + "/revoke", "keyChange": base + "/key",
		})
	case p == "/nonce":
		w.WriteHeader(http.StatusOK)
	case p == "/account":
		w.Header().Set("Location", base+"/account/1")
		reply(http.StatusCreated, map[string]any{"status": "valid"})
	case p == "/order":
		ca.orders++
		n := fmt.Sprint(ca.orders)
		w.Header().Set("Location", base+"/order/"+n)
		reply(http.StatusCreated, order(n))
	case strings.HasPrefix(p, "/order/"):
		reply(http.StatusOK, order(path.Base(p)))
	case strings.HasPrefix(p, "/finalize/"):
		n := path.Base(p)
		chain, err := ca.sign(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ca.chains[n] = chain
		w.Header().Set("Location", base+"/order/"+n)
		reply(http.StatusOK, order(n))
	case strings.HasPrefix(p, "/cert/"):
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(ca.chains[path.Base(p)])
	case strings.HasPrefix(p, "/authz/") && strings.Count(p, "/") == 3:
		// Accepting a challenge decides its authorization at once.
		authz, typ := path.Split(p)
		authz = strings.TrimSuffix(authz, "/")
		ca.accepted = append(ca.accepted, typ)
		ca.status[authz] = "invalid"
		if ca.issue {
			ca.status[authz] = "valid"
		}
		reply(http.StatusOK, map[string]string{"type": typ, "url": base + p, "token": "token-" + typ, "status": "processing"})
	case strings.HasPrefix(p, "/authz/"):
		status := ca.status[p]
		if status == "" {
			status = "pending"
		}
		httpChallenge := map[string]any{"type": "http-01", "url": base + p + "/http-01", "token": "token-http-01", "status": "pending"}
		if status != "pending" {
			httpChallenge["status"] = status
		}
		if status == "invalid" {
			httpChallenge["error"] = map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": caProblem, "status": 403}
		}
		reply(http.StatusOK, map[string]any{
			"status": status, "identifier": identifier,
			"challenges": []any{
				map[string]string{"type": "tls-alpn-01", "url": base + p + "/tls-alpn-01", "token": "token-tls-alpn-01", "status": "pending"},
				httpChallenge,
			},
		})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// sign issues a 90-day certificate for the CSR in a finalize request's JWS payload.
func (ca *fakeCA) sign(body io.Reader) ([]byte, error) {
	var jws struct{ Payload string }
	if err := json.NewDecoder(body).Decode(&jws); err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil, err
	}
	var req struct{ CSR string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	der, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...), nil
}
