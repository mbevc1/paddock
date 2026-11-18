package validate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func authorizedKey(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
}

func TestSSHPublicKey(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ed := authorizedKey(t, edPub)

	valid := map[string]string{
		ed:                                   ed,
		ed + " laptop@home":                  ed + " laptop@home",
		"  " + ed + "  ":                     ed,
		authorizedKey(t, &ecKey.PublicKey):   authorizedKey(t, &ecKey.PublicKey),
		authorizedKey(t, &rsa3072.PublicKey): authorizedKey(t, &rsa3072.PublicKey),
	}
	for in, want := range valid {
		got, err := SSHPublicKey(in)
		if err != nil || got != want {
			t.Errorf("SSHPublicKey(%.40q) = %.40q, %v; want %.40q", in, got, err, want)
		}
	}

	signer, err := ssh.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	sshEd, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: sshEd, CertType: ssh.UserCert, ValidPrincipals: []string{"v00012"}}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}

	invalidKeys := []string{
		"",
		"not a key",
		authorizedKey(t, &rsa2048.PublicKey),
		strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(cert)), "\n"),
		`command="/bin/sh" ` + ed,
		`no-pty ` + ed,
		ed + "\n" + ed,
		ed + "\ncommand=x",
		ed + " comment\x00",
		ed + " comment\twith-tab",
		ed + " " + strings.Repeat("c", 101),
		ed + " $(id)\r",
		"ssh-ed25519 AAAA",
		strings.Repeat("A", 20000),
	}
	for _, in := range invalidKeys {
		_, err := SSHPublicKey(in)
		assertInvalid(t, err)
	}
}
