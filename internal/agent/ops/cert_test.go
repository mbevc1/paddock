package ops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

// testCert returns a chain and key covering the reference vhost's domains.
func testCert(t *testing.T, now time.Time, names ...string) (chain, key string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour)}
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

const (
	certFile = "etc/pki/paddock/v00001.crt"
	keyFile  = "etc/pki/paddock/v00001.key"
)

func TestCertUpload(t *testing.T) {
	ctx := context.Background()
	e, web, owner, mark := activeVhost(t)
	chain, key := testCert(t, e.now, "shop.example.com", "www.shop.example.com")

	var status CertStatus
	if err := web.Call(ctx, "cert.upload", owner, "", CertUploadArgs{VhostID: "v00001", ChainPEM: chain, KeyPEM: key}, &status); err != nil {
		t.Fatal(err)
	}
	if status.Source != state.CertUpload || status.NotAfter == nil {
		t.Errorf("status = %+v", status)
	}
	for file, mode := range map[string]fs.FileMode{certFile: 0o644, keyFile: 0o600} {
		fi, err := os.Stat(filepath.Join(e.root, file))
		if err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s: %v, %v", file, fi, err)
		}
	}
	front := frontConfig(t, e)
	if !strings.Contains(front, "SSLCertificateFile /etc/pki/paddock/v00001.crt") || strings.Contains(front, "MDomain") {
		t.Errorf("front:\n%s", front)
	}
	if got, want := e.run.Commands()[mark:], []string{"/usr/sbin/apachectl configtest", "/usr/bin/systemctl reload httpd.service"}; !slices.Equal(got, want) {
		t.Errorf("commands = %q", got)
	}
	if c, _ := e.store.GetCert(ctx, 1); c.Source != state.CertUpload || len(c.Fingerprint) != 64 {
		t.Errorf("state cert = %+v", c)
	}

	// A suspended vhost keeps answering 503 with its uploaded certificate after resume.
	admin := adminSession(t, e, web)
	if v := runJob(t, web, "vhost.suspend", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	if front := frontConfig(t, e); !strings.Contains(front, "SSLCertificateFile") || !strings.Contains(front, "Redirect 503") {
		t.Errorf("suspended front lost the uploaded certificate:\n%s", front)
	}

	entries, err := e.store.ListAudit(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if strings.Contains(en.Args, "PRIVATE KEY") {
			t.Errorf("audit entry contains the key: %s", en.Op)
		}
	}
}

func TestCertUploadRejects(t *testing.T) {
	ctx := context.Background()
	e, web, owner, mark := activeVhost(t)
	chain, _ := testCert(t, e.now, "shop.example.com", "www.shop.example.com")
	_, otherKey := testCert(t, e.now, "shop.example.com", "www.shop.example.com")
	partial, partialKey := testCert(t, e.now, "shop.example.com")
	stranger := &api.Actor{UserID: 9, Role: api.RoleOwner, OwnerID: 999}

	wantCode(t, web.Call(ctx, "cert.upload", owner, "", CertUploadArgs{VhostID: "v00001", ChainPEM: chain, KeyPEM: otherKey}, nil), api.CodeInvalidArgument)
	wantCode(t, web.Call(ctx, "cert.upload", owner, "", CertUploadArgs{VhostID: "v00001", ChainPEM: partial, KeyPEM: partialKey}, nil), api.CodeInvalidArgument)
	wantCode(t, web.Call(ctx, "cert.upload", stranger, "", CertUploadArgs{VhostID: "v00001", ChainPEM: partial, KeyPEM: partialKey}, nil), api.CodeNotFound)
	if len(e.run.Calls()) != mark {
		t.Error("rejected uploads ran commands")
	}
	for _, f := range []string{certFile, keyFile} {
		if _, err := os.Stat(filepath.Join(e.root, f)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s written for a rejected upload", f)
		}
	}
}

func TestCertUploadConfigtestFailureRestores(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	before := frontConfig(t, e)
	chain, key := testCert(t, e.now, "shop.example.com", "www.shop.example.com")
	e.run.On("/usr/sbin/apachectl", "configtest").Fail("AH00526: Syntax error").Times(1)

	wantCode(t, web.Call(ctx, "cert.upload", owner, "", CertUploadArgs{VhostID: "v00001", ChainPEM: chain, KeyPEM: key}, nil), api.CodeApplyFailed)
	if got := frontConfig(t, e); got != before {
		t.Errorf("front not restored:\n%s", got)
	}
	for _, f := range []string{certFile, keyFile} {
		if _, err := os.Stat(filepath.Join(e.root, f)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left after a failed upload", f)
		}
	}
	if c, _ := e.store.GetCert(ctx, 1); c.Source != state.CertACME {
		t.Errorf("cert source = %s", c.Source)
	}
	if slices.Contains(e.run.Commands(), "/usr/bin/systemctl reload httpd.service") &&
		e.run.Commands()[len(e.run.Commands())-1] == "/usr/bin/systemctl reload httpd.service" {
		t.Error("Apache reloaded with a config that failed configtest")
	}
}

func TestCertStatusFromMDStatus(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	until := time.Date(2027, 1, 30, 10, 0, 0, 0, time.UTC)
	e.host.MDStatus = func(context.Context) ([]MDDomain, error) {
		return []MDDomain{{Name: "other.example.com"}, {Name: "shop.example.com", State: "ok", NotAfter: until}}, nil
	}
	var st CertStatus
	if err := web.Call(ctx, "cert.status", owner, "", VhostIDArgs{VhostID: "v00001"}, &st); err != nil {
		t.Fatal(err)
	}
	if st.Source != state.CertACME || st.State != "ok" || st.NotAfter == nil || !st.NotAfter.Equal(until) {
		t.Errorf("status = %+v", st)
	}

	e.host.MDStatus = func(context.Context) ([]MDDomain, error) { return nil, errors.New("connection refused") }
	if err := web.Call(ctx, "cert.status", owner, "", VhostIDArgs{VhostID: "v00001"}, &st); err != nil || st.Error != "certificate status unavailable" {
		t.Errorf("status without md-status = %+v, %v", st, err)
	}
}

func TestParseMDStatus(t *testing.T) {
	body := `{"version":"2.4.26","managed-domains":[
	  {"name":"shop.example.com","state":2,"state-descr":"certificate(rsa) is valid",
	   "cert":{"rsa":{"valid":{"from":"Tue, 17 Nov 2026 10:00:00 GMT","until":"Mon, 15 Feb 2027 10:00:00 GMT"}},
	           "secp256r1":{"valid":{"until":"Sun, 14 Feb 2027 10:00:00 GMT"}}}},
	  {"name":"new.example.com","state":1,
	   "renewal":{"last":{"status":"error","problem":"urn:ietf:params:acme:error:dns"}}},
	  {"name":"staged.example.com","state":1,
	   "renewal":{"finished":true,"last-run":"Thu, 19 Nov 2026 19:34:36 GMT","last":{"status":0}}}]}`
	got, err := parseMDStatus([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	want := []MDDomain{
		{Name: "shop.example.com", State: "certificate(rsa) is valid", NotAfter: time.Date(2027, 2, 14, 10, 0, 0, 0, time.UTC)},
		{Name: "new.example.com", State: "1", Error: "urn:ietf:params:acme:error:dns"},
		{Name: "staged.example.com", State: "1", Staged: true, RenewalRun: "Thu, 19 Nov 2026 19:34:36 GMT"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseMDStatus:\n got %+v\nwant %+v", got, want)
	}
	if _, err := parseMDStatus([]byte("<html>")); err == nil {
		t.Error("HTML accepted as md-status")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	if domains, err := fetchMDStatus(context.Background(), srv.Client(), srv.URL); err != nil || len(domains) != 3 {
		t.Errorf("fetchMDStatus = %v, %v", domains, err)
	}
}

func TestMDRenewed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	root, web := e.client(0), e.client(webUID)
	if err := root.Call(ctx, "front.md-renewed", nil, "", MDRenewedArgs{Domains: []string{"shop.example.com"}}, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := e.run.Commands(), []string{"/usr/sbin/apachectl configtest", "/usr/bin/systemctl reload httpd.service"}; !slices.Equal(got, want) {
		t.Errorf("commands = %q", got)
	}
	wantCode(t, web.Call(ctx, "front.md-renewed", nil, "", MDRenewedArgs{Domains: []string{"shop.example.com"}}, nil), api.CodeForbidden)
	wantCode(t, root.Call(ctx, "front.md-renewed", nil, "", MDRenewedArgs{Domains: []string{"bad domain"}}, nil), api.CodeInvalidArgument)

	e.run.On("/usr/sbin/apachectl").Fail("Syntax error")
	mark := len(e.run.Calls())
	wantCode(t, root.Call(ctx, "front.md-renewed", nil, "", MDRenewedArgs{Domains: []string{"shop.example.com"}}, nil), api.CodeApplyFailed)
	if got := e.run.Commands()[mark:]; !slices.Equal(got, []string{"/usr/sbin/apachectl configtest"}) {
		t.Errorf("reloaded after a failed configtest: %q", got)
	}
}

func uploadedVhost(t *testing.T) (*env, *agent.Client, *api.Actor) {
	t.Helper()
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	chain, key := testCert(t, e.now, "shop.example.com", "www.shop.example.com")
	if err := web.Call(ctx, "cert.upload", owner, "", CertUploadArgs{VhostID: "v00001", ChainPEM: chain, KeyPEM: key}, nil); err != nil {
		t.Fatal(err)
	}
	return e, web, owner
}

func TestCertBackToACME(t *testing.T) {
	ctx := context.Background()
	e, web, owner := uploadedVhost(t)
	mark := len(e.run.Calls())

	var status CertStatus
	if err := web.Call(ctx, "cert.acme", owner, "", VhostIDArgs{VhostID: "v00001"}, &status); err != nil {
		t.Fatal(err)
	}
	if status.Source != state.CertACME {
		t.Errorf("status = %+v", status)
	}
	if front := frontConfig(t, e); !strings.Contains(front, "MDomain") || strings.Contains(front, "SSLCertificateFile") {
		t.Errorf("front:\n%s", front)
	}
	if got, want := e.run.Commands()[mark:], []string{"/usr/sbin/apachectl configtest", "/usr/bin/systemctl reload httpd.service"}; !slices.Equal(got, want) {
		t.Errorf("commands = %q", got)
	}
	for _, f := range []string{certFile, keyFile} {
		if _, err := os.Stat(filepath.Join(e.root, f)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left after switching to ACME", f)
		}
	}
	if c, _ := e.store.GetCert(ctx, 1); c.Source != state.CertACME || c.Fingerprint != "" {
		t.Errorf("state cert = %+v", c)
	}

	mark = len(e.run.Calls())
	if err := web.Call(ctx, "cert.acme", owner, "", VhostIDArgs{VhostID: "v00001"}, nil); err != nil || len(e.run.Calls()) != mark {
		t.Errorf("switching a vhost already on ACME ran commands: %v", err)
	}

	other, err := e.store.CreateOwner(ctx, "other", state.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	stranger := &api.Actor{UserID: 9, Role: api.RoleOwner, OwnerID: other.ID}
	wantCode(t, web.Call(ctx, "cert.acme", stranger, "", VhostIDArgs{VhostID: "v00001"}, nil), api.CodeNotFound)
}

func TestCertBackToACMEConfigtestFailureKeepsUpload(t *testing.T) {
	ctx := context.Background()
	e, web, owner := uploadedVhost(t)
	before := frontConfig(t, e)
	e.run.On("/usr/sbin/apachectl", "configtest").Fail("AH00526: Syntax error").Times(1)

	wantCode(t, web.Call(ctx, "cert.acme", owner, "", VhostIDArgs{VhostID: "v00001"}, nil), api.CodeApplyFailed)
	if got := frontConfig(t, e); got != before {
		t.Errorf("front not restored:\n%s", got)
	}
	for _, f := range []string{certFile, keyFile} {
		if _, err := os.Stat(filepath.Join(e.root, f)); err != nil {
			t.Errorf("%s removed after a failed switch: %v", f, err)
		}
	}
	if c, _ := e.store.GetCert(ctx, 1); c.Source != state.CertUpload {
		t.Errorf("cert source = %s", c.Source)
	}
}
