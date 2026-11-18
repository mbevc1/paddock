//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/state"
)

// frontGet fetches / from the front Apache over HTTPS on this host. mod_md serves a
// temporary self-signed certificate for test domains, so verification is off.
func frontGet(t *testing.T, domain string) (int, string) {
	t.Helper()
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, "127.0.0.1:443")
			},
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET https://%s/: %v", domain, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func TestVhostLifecycle(t *testing.T) {
	h := newAgent(t)
	if v := h.job("php.version.install", ops.PHPVersionArgs{Version: "8.3"}, 15*time.Minute); v.Status != state.JobSucceeded {
		t.Fatalf("install PHP 8.3: %+v", v)
	}
	var owner ops.OwnerCreated
	if err := h.client.Call(context.Background(), "owner.create", h.admin, "", ops.OwnerCreateArgs{Name: "itest"}, &owner); err != nil {
		t.Fatal(err)
	}
	domain := "itest-" + time.Now().UTC().Format("150405") + ".test"
	v := h.job("vhost.create", ops.VhostCreateArgs{OwnerID: owner.OwnerID, PrimaryDomain: domain, PHPVersion: "8.3"}, 5*time.Minute)
	if v.Status != state.JobSucceeded {
		t.Fatalf("create: %+v", v)
	}
	id := strings.Trim(strings.TrimPrefix(string(v.Result), `{"vhost_id":`), `"}`)
	u, err := user.Lookup(id)
	if err != nil {
		t.Fatalf("user %s: %v", id, err)
	}

	index := filepath.Join("/srv/www", id, "public", "index.php")
	if err := os.WriteFile(index, []byte("<?php phpinfo();\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	uid, gid := atoi(t, u.Uid), atoi(t, u.Gid)
	if err := os.Chown(index, uid, gid); err != nil {
		t.Fatal(err)
	}
	status, body := frontGet(t, domain)
	if status != http.StatusOK || !strings.Contains(body, "PHP Version 8.3") {
		t.Errorf("front answered %d: %.200s", status, body)
	}

	if v := h.job("vhost.delete", ops.VhostDeleteArgs{VhostID: id, Confirm: domain}, 5*time.Minute); v.Status != state.JobSucceeded {
		t.Fatalf("delete: %+v", v)
	}
	if _, err := user.Lookup(id); err == nil {
		t.Errorf("user %s still exists", id)
	}
	for _, p := range []string{
		"/srv/www/" + id, "/srv/jail/" + id, "/run/paddock/fpm/" + id,
		"/etc/paddock/httpd/" + id + ".conf", "/etc/paddock/fpm/" + id + ".conf",
		"/etc/httpd/conf.d/paddock-" + id + ".conf", "/etc/tmpfiles.d/paddock-" + id + ".conf",
		"/etc/systemd/system/paddock-httpd@" + id + ".service.d",
		"/etc/systemd/system/srv-jail-" + id + "-site.mount",
	} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left behind: %v", p, err)
		}
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mounts), "/srv/jail/"+id) {
		t.Errorf("jail of %s still mounted", id)
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// newVhost installs PHP versions, creates an owner and a vhost serving index.php, and deletes
// the vhost when the test ends.
func newVhost(t *testing.T, h *agentHarness, versions ...string) (id, domain string) {
	t.Helper()
	for _, v := range versions {
		if job := h.job("php.version.install", ops.PHPVersionArgs{Version: v}, 15*time.Minute); job.Status != state.JobSucceeded {
			t.Fatalf("install PHP %s: %+v", v, job)
		}
	}
	var owner ops.OwnerCreated
	if err := h.client.Call(context.Background(), "owner.create", h.admin, "", ops.OwnerCreateArgs{Name: "itest " + t.Name()}, &owner); err != nil {
		t.Fatal(err)
	}
	domain = "itest-" + strings.ToLower(time.Now().UTC().Format("150405.000")) + ".test"
	domain = strings.ReplaceAll(domain, ".000", "")
	job := h.job("vhost.create", ops.VhostCreateArgs{OwnerID: owner.OwnerID, PrimaryDomain: domain, PHPVersion: versions[0]}, 5*time.Minute)
	if job.Status != state.JobSucceeded {
		t.Fatalf("create: %+v", job)
	}
	id = strings.Trim(strings.TrimPrefix(string(job.Result), `{"vhost_id":`), `"}`)
	t.Cleanup(func() {
		if job := h.job("vhost.delete", ops.VhostDeleteArgs{VhostID: id, Confirm: domain}, 5*time.Minute); job.Status != state.JobSucceeded {
			t.Errorf("delete: %+v", job)
		}
	})
	u, err := user.Lookup(id)
	if err != nil {
		t.Fatal(err)
	}
	index := filepath.Join("/srv/www", id, "public", "index.php")
	if err := os.WriteFile(index, []byte("<?php echo PHP_MAJOR_VERSION, '.', PHP_MINOR_VERSION;\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(index, atoi(t, u.Uid), atoi(t, u.Gid)); err != nil {
		t.Fatal(err)
	}
	return id, domain
}

func TestVhostPHPSwitchSuspendResume(t *testing.T) {
	h := newAgent(t)
	id, domain := newVhost(t, h, "8.3", "8.4")
	if status, body := frontGet(t, domain); status != http.StatusOK || body != "8.3" {
		t.Fatalf("before the switch: %d %q", status, body)
	}

	stop := make(chan struct{})
	results := make(chan string, 1024)
	go func() {
		defer close(results)
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				status, body := frontGet(t, domain)
				results <- strconv.Itoa(status) + " " + body
			}
		}
	}()
	time.Sleep(2 * time.Second)
	job := h.job("vhost.php.switch", ops.VhostPHPSwitchArgs{VhostID: id, Version: "8.4"}, 2*time.Minute)
	time.Sleep(2 * time.Second)
	close(stop)
	if job.Status != state.JobSucceeded {
		t.Fatalf("switch: %+v", job)
	}
	var seen []string
	for r := range results {
		seen = append(seen, r)
		if r != "200 8.3" && r != "200 8.4" {
			t.Errorf("request during the switch answered %q", r)
		}
	}
	if len(seen) == 0 || seen[len(seen)-1] != "200 8.4" {
		t.Errorf("responses = %q, want the last from 8.4", seen)
	}

	if job := h.job("vhost.suspend", ops.VhostIDArgs{VhostID: id}, 2*time.Minute); job.Status != state.JobSucceeded {
		t.Fatalf("suspend: %+v", job)
	}
	if status, _ := frontGet(t, domain); status != http.StatusServiceUnavailable {
		t.Errorf("suspended vhost answered %d", status)
	}
	if job := h.job("vhost.resume", ops.VhostIDArgs{VhostID: id}, 2*time.Minute); job.Status != state.JobSucceeded {
		t.Fatalf("resume: %+v", job)
	}
	if status, body := frontGet(t, domain); status != http.StatusOK || body != "8.4" {
		t.Errorf("after resume: %d %q", status, body)
	}
}
