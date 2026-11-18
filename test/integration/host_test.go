//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

// run executes a host command and returns its stdout.
func run(ctx context.Context, argv ...string) (string, error) {
	res, err := (system.Exec{}).Run(ctx, argv, system.Opts{})
	return string(res.Stdout), err
}

// output executes a host command and returns stdout and stderr together, whatever its exit code.
func output(t *testing.T, stdin string, argv ...string) string {
	t.Helper()
	res, _ := (system.Exec{}).Run(context.Background(), argv, system.Opts{Stdin: strings.NewReader(stdin)})
	return strings.TrimSpace(string(res.Stdout) + string(res.Stderr))
}

func mustRun(t *testing.T, argv ...string) string {
	t.Helper()
	out, err := run(context.Background(), argv...)
	if err != nil {
		t.Fatalf("%s: %v", strings.Join(argv, " "), err)
	}
	return strings.TrimSpace(out)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("not a number: %q", s)
	}
	return n
}

// vhostN returns N from a vhost ID such as v00012.
func vhostN(t *testing.T, id string) int { t.Helper(); return atoi(t, strings.TrimPrefix(id, "v")) }

// uidOf returns the vhost's UID, state.UIDBase + N.
func uidOf(t *testing.T, id string) string {
	t.Helper()
	return strconv.Itoa(state.UIDBase + vhostN(t, id))
}

// backendAddr returns the vhost's loopback address, 127.64.N/256.N%256.
func backendAddr(t *testing.T, id string) string {
	t.Helper()
	n := vhostN(t, id)
	return "127.64." + strconv.Itoa(n>>8) + "." + strconv.Itoa(n&255)
}

func phpCLI(version string) string {
	return "/opt/remi/php" + strings.ReplaceAll(version, ".", "") + "/root/usr/bin/php"
}

func mainPID(t *testing.T, unit string) string {
	t.Helper()
	return mustRun(t, "/usr/bin/systemctl", "show", "-p", "MainPID", "--value", unit)
}

// writeAs writes a file under /srv/www/<id>/ owned by the vhost user.
func writeAs(t *testing.T, id, rel, content string, mode os.FileMode) string {
	t.Helper()
	u, err := user.Lookup(id)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("/srv/www", id, rel)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(path, atoi(t, u.Uid), atoi(t, u.Gid)); err != nil {
		t.Fatal(err)
	}
	return path
}

// asVhostUID runs a command with the vhost's UID and GID in the host namespaces.
func asVhostUID(t *testing.T, id string, argv ...string) string {
	t.Helper()
	uid := uidOf(t, id)
	return output(t, "", append([]string{"/usr/bin/setpriv", "--reuid=" + uid, "--regid=" + uid, "--clear-groups", "--"}, argv...)...)
}

// asApache runs a command as the front Apache user, the only UID the loopback rule lets reach a
// backend.
func asApache(t *testing.T, argv ...string) string {
	t.Helper()
	return output(t, "", append([]string{"/usr/bin/setpriv", "--reuid=apache", "--regid=apache", "--init-groups", "--"}, argv...)...)
}

// backendGet requests a path from a vhost's backend directly, with the given Host header.
func backendGet(t *testing.T, id, path, host string) string {
	t.Helper()
	return asApache(t, "/usr/bin/curl", "-sS", "-m", "30", "-H", "Host: "+host, "http://"+backendAddr(t, id)+":81"+path)
}

// phpEval runs PHP code in the vhost's backend, as tenant code runs, and returns the response.
func phpEval(t *testing.T, id, code string) string {
	t.Helper()
	name := "probe-" + randomHex(t, 6) + ".php"
	path := writeAs(t, id, "public/"+name, "<?php\n"+code+"\n", 0o640)
	defer os.Remove(path)
	return strings.TrimSpace(backendGet(t, id, "/"+name, "localhost"))
}

// phpShell runs shell code as a child of the vhost's PHP: inside its sandbox, SELinux domain and
// UID, without PHP's own restrictions such as open_basedir.
func phpShell(t *testing.T, id, script string) string {
	t.Helper()
	enc := base64.StdEncoding.EncodeToString([]byte("{ " + script + "\n} 2>&1"))
	return phpEval(t, id, `passthru(base64_decode("`+enc+`"));`)
}

// fetchFront fetches a path from the front Apache over HTTPS on this host. mod_md serves a
// temporary self-signed certificate for test domains, so verification is off.
func fetchFront(t *testing.T, domain, path string) (int, string) {
	t.Helper()
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true}, // #nosec G402 -- see above.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, "127.0.0.1:443")
			},
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+domain+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET https://%s%s: %v", domain, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func frontGet(t *testing.T, domain string) (int, string) {
	t.Helper()
	return fetchFront(t, domain, "/")
}

// servePHP writes code to public/name in a vhost and returns what the front answers for it.
func servePHP(t *testing.T, id, domain, name, code string) string {
	t.Helper()
	path := writeAs(t, id, "public/"+name, "<?php\n"+code+"\n", 0o640)
	defer os.Remove(path)
	_, body := fetchFront(t, domain, "/"+name)
	return body
}

var sshOpts = []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10"}

// sshKey writes a new ed25519 key pair and returns the private key path and public key.
func sshKey(t *testing.T) (string, string) {
	t.Helper()
	key := filepath.Join(t.TempDir(), "id")
	mustRun(t, "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return key, strings.TrimSpace(string(pub))
}

func sshRun(t *testing.T, key, user, stdin string, argv ...string) string {
	t.Helper()
	full := append([]string{"/usr/bin/ssh", "-i", key}, sshOpts...)
	full = append(full, user+"@127.0.0.1")
	return output(t, stdin, append(full, argv...)...)
}
