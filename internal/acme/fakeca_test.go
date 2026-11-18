package acme

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"
)

// fakeCA is just enough of an RFC 8555 server for autocert to reach the challenge stage. It
// offers tls-alpn-01 and http-01 for one authorization, records which challenges the client
// accepts, and fails every authorization so that each fetch ends.
type fakeCA struct {
	srv *httptest.Server

	mu       sync.Mutex
	nonce    int
	orders   int
	accepted []string
	failed   map[string]bool
	requests int
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	ca := &fakeCA{failed: map[string]bool{}}
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
		w.Header().Set("Location", fmt.Sprintf("%s/order/%d", base, ca.orders))
		reply(http.StatusCreated, map[string]any{
			"status": "pending", "identifiers": []any{identifier},
			"authorizations": []string{fmt.Sprintf("%s/authz/%d", base, ca.orders)},
			"finalize":       fmt.Sprintf("%s/finalize/%d", base, ca.orders),
		})
	case strings.HasPrefix(p, "/authz/") && strings.Count(p, "/") == 3:
		// Accepting a challenge: record its type and fail the authorization.
		authz, typ := path.Split(p)
		ca.accepted = append(ca.accepted, typ)
		ca.failed[strings.TrimSuffix(authz, "/")] = true
		reply(http.StatusOK, map[string]string{"type": typ, "url": base + p, "token": "token-" + typ, "status": "processing"})
	case strings.HasPrefix(p, "/authz/"):
		status := "pending"
		if ca.failed[p] {
			status = "invalid"
		}
		reply(http.StatusOK, map[string]any{
			"status": status, "identifier": identifier,
			"challenges": []map[string]string{
				{"type": "tls-alpn-01", "url": base + p + "/tls-alpn-01", "token": "token-tls-alpn-01", "status": "pending"},
				{"type": "http-01", "url": base + p + "/http-01", "token": "token-http-01", "status": "pending"},
			},
		})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}
