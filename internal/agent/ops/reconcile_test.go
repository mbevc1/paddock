package ops

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

func snapshot(t *testing.T, e *env, rels ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, rel := range rels {
		b, err := os.ReadFile(filepath.Join(e.root, rel))
		if err != nil {
			t.Fatal(err)
		}
		out[rel] = string(b)
	}
	return out
}

var reconciledFiles = []string{
	"etc/paddock/httpd/v00001.conf",
	"etc/paddock/fpm/v00001.conf",
	"etc/httpd/conf.d/paddock-v00001.conf",
	"etc/systemd/system/paddock-php83-fpm@v00001.service.d/10-sandbox.conf",
	"etc/systemd/system/paddock-php83-fpm@.service",
}

func TestReconcileRestoresDeletedConfigs(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := activeVhost(t)
	if err := e.store.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	// The PHP template comes from php.version.install, which this env skipped.
	if _, err := Reconcile(ctx, e.store, e.host); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, e, reconciledFiles...)
	for _, rel := range reconciledFiles[:4] {
		if err := os.Remove(filepath.Join(e.root, rel)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(e.root, "srv/www/v00001/sessions")); err != nil {
		t.Fatal(err)
	}

	mark := len(e.run.Calls())
	res, err := Reconcile(ctx, e.store, e.host)
	if err != nil || len(res.Errors) != 0 || res.Vhosts != 1 {
		t.Fatalf("Reconcile = %+v, %v", res, err)
	}
	if got := snapshot(t, e, reconciledFiles...); len(got) != len(before) {
		t.Fatal("files missing")
	} else {
		for k, v := range before {
			if got[k] != v {
				t.Errorf("%s differs after reconcile", k)
			}
		}
	}
	if fi, err := os.Stat(filepath.Join(e.root, "srv/www/v00001/sessions")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("sessions directory = %v, %v", fi, err)
	}
	cmds := e.run.Commands()[mark:]
	for _, want := range []string{
		"/usr/bin/systemctl daemon-reload",
		"/usr/sbin/httpd -t -f /etc/paddock/httpd/v00001.conf",
		"/usr/bin/systemctl restart paddock-php83-fpm@v00001.service",
		"/usr/bin/systemctl reload paddock-httpd@v00001.service",
		"/usr/sbin/apachectl configtest",
		"/usr/bin/systemctl reload httpd.service",
	} {
		if !slices.Contains(cmds, want) {
			t.Errorf("missing %q in %q", want, cmds)
		}
	}
	if len(res.Changed) != 4 {
		t.Errorf("changed = %q", res.Changed)
	}

	mark = len(e.run.Calls())
	res, err = Reconcile(ctx, e.store, e.host)
	if err != nil || len(res.Changed) != 0 {
		t.Fatalf("second reconcile = %+v, %v", res, err)
	}
	for _, c := range e.run.Commands()[mark:] {
		if strings.Contains(c, "restart") || strings.Contains(c, "reload") || strings.Contains(c, "configtest") {
			t.Errorf("idle reconcile ran %q", c)
		}
	}
}

func TestReconcileSuspendedWithAccess(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	if v := runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Keys: []string{newSSHKey(t, "k")}}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	admin := adminSession(t, e, web)
	if v := runJob(t, web, "vhost.suspend", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	for _, rel := range []string{"etc/httpd/conf.d/paddock-v00001.conf", "etc/ssh/authorized_keys/v00001"} {
		if err := os.Remove(filepath.Join(e.root, rel)); err != nil {
			t.Fatal(err)
		}
	}
	mark := len(e.run.Calls())
	if res, err := Reconcile(ctx, e.store, e.host); err != nil || len(res.Errors) != 0 {
		t.Fatalf("Reconcile = %+v, %v", res, err)
	}
	if !strings.Contains(frontConfig(t, e), "Redirect 503 /") {
		t.Error("suspended front not restored as 503")
	}
	if !fileExists(e, "etc/ssh/authorized_keys/v00001") {
		t.Error("authorized_keys not restored")
	}
	cmds := e.run.Commands()[mark:]
	for _, want := range []string{
		"/usr/bin/systemctl disable --now paddock-httpd@v00001.service",
		"/usr/bin/systemctl enable --now srv-jail-v00001-site.mount",
	} {
		if !slices.Contains(cmds, want) {
			t.Errorf("missing %q in %q", want, cmds)
		}
	}
	if slices.Contains(cmds, "/usr/bin/systemctl enable --now paddock-httpd@v00001.service") {
		t.Error("suspended backend started")
	}
}

// rewriteConfigs replaces each file under the env's root with a hand edit.
func rewriteConfigs(t *testing.T, e *env, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		if err := os.WriteFile(filepath.Join(e.root, rel), []byte("# hand edit\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReconcileReloadsChangedConfigs(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := activeVhost(t)
	if _, err := Reconcile(ctx, e.store, e.host); err != nil {
		t.Fatal(err)
	}
	rewriteConfigs(t, e, "etc/paddock/httpd/v00001.conf", "etc/paddock/fpm/v00001.conf")
	mark := len(e.run.Calls())
	if res, err := Reconcile(ctx, e.store, e.host); err != nil || len(res.Errors) != 0 {
		t.Fatalf("Reconcile = %+v, %v", res, err)
	}
	cmds := e.run.Commands()[mark:]
	for _, want := range []string{
		"/usr/bin/systemctl reload paddock-php83-fpm@v00001.service",
		"/usr/bin/systemctl reload paddock-httpd@v00001.service",
	} {
		if !slices.Contains(cmds, want) {
			t.Errorf("missing %q in %q", want, cmds)
		}
	}
	for _, c := range cmds {
		if strings.Contains(c, "restart") {
			t.Errorf("a config change restarted a unit: %q", c)
		}
	}
}

func TestReconcileKeepsTheRunningConfigWhenACheckFails(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := activeVhost(t)
	backend := filepath.Join(e.root, "etc/paddock/httpd/v00001.conf")
	rewriteConfigs(t, e, "etc/paddock/httpd/v00001.conf")
	e.run.On("/usr/sbin/httpd", "-t").Fail("Syntax error").Times(1)
	mark := len(e.run.Calls())
	res, err := Reconcile(ctx, e.store, e.host)
	if err != nil || len(res.Errors) != 1 || res.Errors[0] != "units of v00001" {
		t.Fatalf("Reconcile = %+v, %v", res, err)
	}
	if b, _ := os.ReadFile(backend); string(b) != "# hand edit\n" {
		t.Errorf("backend config after a failed check = %q", b)
	}
	cmds := e.run.Commands()[mark:]
	if slices.Contains(cmds, "/usr/bin/systemctl reload paddock-httpd@v00001.service") {
		t.Error("reloaded the backend after a failed check")
	}
	if !slices.Contains(cmds, "/usr/bin/systemctl enable --now paddock-httpd@v00001.service") {
		t.Error("a failed check left the backend unit unmanaged")
	}
}

func TestReconcileRestartsFPMWhenItsUnitTemplateChanges(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := activeVhost(t)
	if _, err := Reconcile(ctx, e.store, e.host); err != nil {
		t.Fatal(err)
	}
	rewriteConfigs(t, e, "etc/systemd/system/paddock-php83-fpm@.service")
	mark := len(e.run.Calls())
	if res, err := Reconcile(ctx, e.store, e.host); err != nil || len(res.Errors) != 0 {
		t.Fatalf("Reconcile = %+v, %v", res, err)
	}
	cmds := e.run.Commands()[mark:]
	if !slices.Contains(cmds, "/usr/bin/systemctl restart paddock-php83-fpm@v00001.service") {
		t.Errorf("FPM not restarted after its unit template changed: %q", cmds)
	}
	if slices.ContainsFunc(cmds, func(c string) bool {
		return strings.Contains(c, "paddock-httpd@v00001.service") && !strings.Contains(c, "enable")
	}) {
		t.Errorf("the backend was reloaded or restarted for an FPM unit change: %q", cmds)
	}
}

func TestReconcileRestoresFrontOnConfigtestFailure(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := activeVhost(t)
	front := filepath.Join(e.root, "etc/httpd/conf.d/paddock-v00001.conf")
	if err := os.WriteFile(front, []byte("# hand edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.run.On("/usr/sbin/apachectl").Fail("Syntax error").Times(1)
	res, err := Reconcile(ctx, e.store, e.host)
	if err != nil || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "configtest") {
		t.Fatalf("Reconcile = %+v, %v", res, err)
	}
	if b, _ := os.ReadFile(front); string(b) != "# hand edit\n" {
		t.Errorf("front after failed configtest = %q", b)
	}
	if e.run.Commands()[len(e.run.Calls())-1] == "/usr/bin/systemctl reload httpd.service" {
		t.Error("reloaded after a failed configtest")
	}
}

func TestReconcileReportsStuckVhosts(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := activeVhost(t)
	if err := e.store.SetVhostStatus(ctx, 1, state.VhostFailed); err != nil {
		t.Fatal(err)
	}
	res, err := Reconcile(ctx, e.store, e.host)
	if err != nil || res.Vhosts != 0 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "v00001 is failed") {
		t.Errorf("Reconcile = %+v, %v", res, err)
	}
}

func TestReconcileOperations(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	var res ReconcileResult
	if err := e.client(0).Call(ctx, "reconcile.run", nil, "", struct{}{}, &res); err != nil || res.Vhosts != 1 {
		t.Fatalf("reconcile.run = %+v, %v", res, err)
	}
	wantCode(t, web.Call(ctx, "reconcile.run", nil, "", struct{}{}, nil), api.CodeForbidden)
	wantCode(t, web.Call(ctx, "reconcile.all", owner, "", struct{}{}, nil), api.CodeForbidden)
	admin := adminSession(t, e, web)
	if v := runJob(t, web, "reconcile.all", admin, struct{}{}); v.Status != state.JobSucceeded {
		t.Errorf("reconcile.all = %+v", v)
	}
}

func TestReconcileOnVersionChange(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := activeVhost(t)
	if err := ReconcileOnVersionChange(ctx, e.store, e.host, "0.5.1"); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.store.ReconciledVersion(ctx); v != "0.5.1" {
		t.Fatalf("reconciled version = %q", v)
	}

	mark := len(e.run.Calls())
	if err := ReconcileOnVersionChange(ctx, e.store, e.host, "0.5.1"); err != nil {
		t.Fatal(err)
	}
	if cmds := e.run.Commands()[mark:]; len(cmds) != 0 {
		t.Errorf("the same version reconciled again: %q", cmds)
	}

	if err := e.store.SetVhostStatus(ctx, 1, state.VhostFailed); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileOnVersionChange(ctx, e.store, e.host, "0.5.2"); err != nil {
		t.Fatal(err)
	}
	events, err := e.store.ListEvents(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != state.EventApplyFailed || events[0].OwnerID != 0 ||
		!strings.Contains(events[0].Message, "version 0.5.2 left 1 problems: vhost v00001 is failed") {
		t.Errorf("events = %+v", events)
	}
	if v, _ := e.store.ReconciledVersion(ctx); v != "0.5.2" {
		t.Errorf("a reconcile with problems did not record its version: %q", v)
	}
}

func TestReconcileOnVersionChangeRetriesAfterStopping(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := activeVhost(t)
	if err := e.store.SetReconciledVersion(ctx, "0.5.1"); err != nil {
		t.Fatal(err)
	}
	rewriteConfigs(t, e, "etc/paddock/fpm/v00001.conf")
	e.run.On("/usr/bin/systemctl", "daemon-reload").Fail("Access denied").Times(1)
	if err := ReconcileOnVersionChange(ctx, e.store, e.host, "0.5.2"); err == nil {
		t.Fatal("a stopped reconcile reported success")
	}
	if v, _ := e.store.ReconciledVersion(ctx); v != "0.5.1" {
		t.Errorf("a stopped reconcile recorded version %q", v)
	}
	if events, _ := e.store.ListEvents(ctx, 0, 10); len(events) != 1 || !strings.Contains(events[0].Message, "retries at its next start") {
		t.Errorf("events = %+v", events)
	}
}
