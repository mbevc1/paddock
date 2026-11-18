//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
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

func TestVhostLifecycle(t *testing.T) {
	h := newAgent(t)
	h.installPHP(t, "8.3")
	owner := h.newOwner(t, ops.LimitsArgs{})
	domain := "itest-" + randomHex(t, 4) + ".test"
	v := h.mustJob(t, "vhost.create", ops.VhostCreateArgs{OwnerID: owner, PrimaryDomain: domain, PHPVersion: "8.3"}, 5*time.Minute)
	var created struct {
		VhostID string `json:"vhost_id"`
	}
	if err := json.Unmarshal(v.Result, &created); err != nil {
		t.Fatal(err)
	}
	id := created.VhostID
	t.Cleanup(func() {
		vs, err := h.store.ListVhosts(context.Background(), 0)
		if err != nil {
			t.Error(err)
			return
		}
		for _, sv := range vs {
			if sv.ID == id {
				h.job(t, "vhost.delete", ops.VhostDeleteArgs{VhostID: id, Confirm: domain}, 5*time.Minute)
			}
		}
	})
	if _, err := user.Lookup(id); err != nil {
		t.Fatalf("user %s: %v", id, err)
	}
	writeAs(t, id, "public/index.php", "<?php phpinfo();\n", 0o640)
	status, body := frontGet(t, domain)
	if status != http.StatusOK || !strings.Contains(body, "PHP Version 8.3") {
		t.Errorf("front answered %d: %.200s", status, body)
	}

	h.mustJob(t, "vhost.delete", ops.VhostDeleteArgs{VhostID: id, Confirm: domain}, 5*time.Minute)
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
	job := h.job(t, "vhost.php.switch", ops.VhostPHPSwitchArgs{VhostID: id, Version: "8.4"}, 2*time.Minute)
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

	h.mustJob(t, "vhost.suspend", ops.VhostIDArgs{VhostID: id}, 2*time.Minute)
	if status, _ := frontGet(t, domain); status != http.StatusServiceUnavailable {
		t.Errorf("suspended vhost answered %d", status)
	}
	h.mustJob(t, "vhost.resume", ops.VhostIDArgs{VhostID: id}, 2*time.Minute)
	if status, body := frontGet(t, domain); status != http.StatusOK || body != "8.4" {
		t.Errorf("after resume: %d %q", status, body)
	}
}

func TestQuotaRevocation(t *testing.T) {
	h := newAgent(t)
	ctx := context.Background()
	id, domain := newVhost(t, h, "8.3")
	sv := mustVhost(t, h, id)
	h.mustCall(t, "owner.limits.set", ops.OwnerLimitsArgs{OwnerID: sv.OwnerID, Limits: ops.LimitsArgs{DiskMB: ptrTo(50)}}, nil)
	h.mustCall(t, "db.create", ops.DBArgs{VhostID: id, Suffix: "app"}, nil)
	sql := func(stmt string) string {
		return servePHP(t, id, domain, "q.php", "mysqli_report(MYSQLI_REPORT_OFF);\n"+
			"$m = new mysqli('localhost', '"+id+"', '', '"+id+"_app');\n"+
			"echo $m->query(\""+stmt+"\") ? 'OK' : 'ERR';")
	}
	if got := sql("CREATE TABLE t (v INT)"); got != "OK" {
		t.Fatalf("create table: %q", got)
	}
	if got := sql("INSERT INTO t VALUES (1)"); got != "OK" {
		t.Fatalf("insert under the limit: %q", got)
	}

	// 60 MB of files puts the owner over 50 MB; root's writes are not held to the quota.
	filler := filepath.Join("/srv/www", id, "private", "filler")
	if err := os.WriteFile(filler, make([]byte, 60<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ops.ScanUsage(ctx, h.store, h.host); err != nil {
		t.Fatal(err)
	}
	if got := sql("INSERT INTO t VALUES (2)"); got != "ERR" {
		t.Errorf("insert over the limit: %q", got)
	}
	if got := sql("SELECT v FROM t"); got != "OK" {
		t.Errorf("select over the limit: %q", got)
	}
	events, err := h.store.ListEvents(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var exceeded bool
	for _, e := range events {
		exceeded = exceeded || e.Kind == state.EventQuotaExceeded && e.OwnerID == sv.OwnerID
	}
	if !exceeded {
		t.Errorf("no quota_exceeded event: %+v", events)
	}

	if err := os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	if err := ops.ScanUsage(ctx, h.store, h.host); err != nil {
		t.Fatal(err)
	}
	if got := sql("INSERT INTO t VALUES (3)"); got != "OK" {
		t.Errorf("insert after cleanup: %q", got)
	}
}

func TestReconcileRestoresVhost(t *testing.T) {
	h := newAgent(t)
	ctx := context.Background()
	id, domain := newVhost(t, h, "8.3")
	for _, p := range []string{
		"/etc/paddock/httpd/" + id + ".conf",
		"/etc/paddock/fpm/" + id + ".conf",
		"/etc/httpd/conf.d/paddock-" + id + ".conf",
	} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, unit := range []string{"paddock-httpd@" + id + ".service", "paddock-php83-fpm@" + id + ".service"} {
		mustRun(t, "/usr/bin/systemctl", "stop", unit)
	}
	res, err := ops.Reconcile(ctx, h.store, h.host)
	if err != nil || len(res.Errors) != 0 {
		t.Fatalf("Reconcile = %+v, %v", res, err)
	}
	if status, body := frontGet(t, domain); status != http.StatusOK || body != "8.3" {
		t.Errorf("after reconcile: %d %q", status, body)
	}
}
