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
		"/usr/bin/systemctl restart paddock-php83-fpm@v00001.service",
		"/usr/bin/systemctl restart paddock-httpd@v00001.service",
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

func TestReconcileSuspendedAndShell(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	allowShell(t, e, owner.OwnerID)
	if v := runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Kind: state.AccessShell, Keys: []string{newSSHKey(t, "k")}}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	admin := adminSession(t, e, web)
	if v := runJob(t, web, "vhost.suspend", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	for _, rel := range []string{"etc/httpd/conf.d/paddock-v00001.conf", "etc/ssh/authorized_keys/v00001", "srv/jail/v00001/etc/passwd"} {
		if err := os.Remove(filepath.Join(e.root, rel)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(e.root, "srv/jail/v00001/opt/paddock/bin/php")); err != nil {
		t.Fatal(err)
	}
	mark := len(e.run.Calls())
	if res, err := Reconcile(ctx, e.store, e.host); err != nil || len(res.Errors) != 0 {
		t.Fatalf("Reconcile = %+v, %v", res, err)
	}
	if !strings.Contains(frontConfig(t, e), "Redirect 503 /") {
		t.Error("suspended front not restored as 503")
	}
	for _, rel := range []string{"etc/ssh/authorized_keys/v00001", "srv/jail/v00001/etc/passwd"} {
		if !fileExists(e, rel) {
			t.Errorf("%s not restored", rel)
		}
	}
	if got, _ := os.Readlink(filepath.Join(e.root, "srv/jail/v00001/opt/paddock/bin/php")); got != "/opt/remi/php83/root/usr/bin/php" {
		t.Errorf("php link = %q", got)
	}
	cmds := e.run.Commands()[mark:]
	for _, want := range []string{
		"/usr/bin/systemctl disable --now paddock-httpd@v00001.service",
		"/usr/bin/systemctl enable --now srv-jail-v00001-proc.mount",
	} {
		if !slices.Contains(cmds, want) {
			t.Errorf("missing %q in %q", want, cmds)
		}
	}
	if slices.Contains(cmds, "/usr/bin/systemctl enable --now paddock-httpd@v00001.service") {
		t.Error("suspended backend started")
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
