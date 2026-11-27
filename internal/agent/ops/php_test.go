package ops

import (
	"context"
	"errors"
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

const (
	php84Packages = "php84-php-fpm php84-php-cli php84-php-mysqlnd php84-php-opcache php84-php-gd " +
		"php84-php-mbstring php84-php-xml php84-php-intl php84-php-pecl-zip php84-php-bcmath php84-php-pecl-apcu"
	php83Packages = "php83-php-fpm php83-php-cli php83-php-mysqlnd php83-php-opcache php83-php-gd " +
		"php83-php-mbstring php83-php-xml php83-php-intl php83-php-pecl-zip php83-php-bcmath php83-php-pecl-apcu"
	rpmQuery84   = "/usr/bin/rpm -q --quiet " + php84Packages
	dnfInstall84 = "/usr/bin/dnf -y install " + php84Packages
	dnfRemove84  = "/usr/bin/dnf -y remove " + php84Packages
	fpm84Check   = "/opt/remi/php84/root/usr/sbin/php-fpm -v"
	daemonReload = "/usr/bin/systemctl daemon-reload"
	fpm84Unit    = "etc/systemd/system/paddock-php84-fpm@.service"
)

// runJob submits a long operation and waits for its outcome.
func runJob(t *testing.T, c *agent.Client, op string, actor *api.Actor, args any) agent.JobView {
	t.Helper()
	ctx := context.Background()
	var job api.JobResult
	if err := c.Call(ctx, op, actor, "", args, &job); err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var v agent.JobView
		if err := c.Call(ctx, "job.get", actor, "", map[string]string{"job_id": job.JobID}, &v); err != nil {
			t.Fatal(err)
		}
		if v.Status == state.JobSucceeded || v.Status == state.JobFailed {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s still %s", job.JobID, v.Status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func wantJobError(t *testing.T, v agent.JobView, code api.Code) {
	t.Helper()
	if v.Status != state.JobFailed || v.Error == nil || v.Error.Code != code {
		t.Errorf("job = %+v, want failure %s", v, code)
	}
}

func installed(t *testing.T, e *env) []string {
	t.Helper()
	v, err := e.store.ListPHPVersions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func unitExists(e *env) bool {
	_, err := os.Stat(filepath.Join(e.root, fpm84Unit))
	return err == nil
}

func TestPHPInstall(t *testing.T) {
	e := newEnv(t)
	web := e.client(webUID)
	admin := adminSession(t, e, web)
	e.run.On("/usr/bin/rpm").Fail("package php84-php-fpm is not installed")

	v := runJob(t, web, "php.version.install", admin, PHPVersionArgs{Version: "8.4"})
	if v.Status != state.JobSucceeded || string(v.Result) != `{"version":"8.4"}` {
		t.Fatalf("job = %+v", v)
	}
	want := []string{rpmQuery84, dnfInstall84, daemonReload, fpm84Check}
	if got := e.run.Commands(); !slices.Equal(got, want) {
		t.Errorf("commands:\n got %q\nwant %q", got, want)
	}
	unit, err := os.ReadFile(filepath.Join(e.root, fpm84Unit))
	if err != nil || !strings.Contains(string(unit), "/opt/remi/php84/root/usr/sbin/php-fpm --nodaemonize") {
		t.Errorf("unit = %q, %v", unit, err)
	}
	if got := installed(t, e); !slices.Equal(got, []string{"8.4"}) {
		t.Errorf("installed = %q", got)
	}
}

func TestPHPInstallAlreadyPresentSkipsDnf(t *testing.T) {
	e := newEnv(t)
	web := e.client(webUID)
	admin := adminSession(t, e, web)

	if v := runJob(t, web, "php.version.install", admin, PHPVersionArgs{Version: "8.4"}); v.Status != state.JobSucceeded {
		t.Fatalf("job = %+v", v)
	}
	if got, want := e.run.Commands(), []string{rpmQuery84, daemonReload, fpm84Check}; !slices.Equal(got, want) {
		t.Errorf("commands = %q, want %q", got, want)
	}
}

func TestPHPInstallRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name        string
		preinstall  bool
		failOn      []string
		wantCmds    []string
		wantMessage string
	}{
		{
			name:        "dnf install fails",
			failOn:      []string{"/usr/bin/dnf", "-y", "install"},
			wantCmds:    []string{rpmQuery84, dnfInstall84},
			wantMessage: "installing PHP 8.4 failed: fake exited with code 1",
		},
		{
			name:        "daemon-reload fails",
			failOn:      []string{"/usr/bin/systemctl", "daemon-reload"},
			wantCmds:    []string{rpmQuery84, dnfInstall84, daemonReload, daemonReload, dnfRemove84},
			wantMessage: "reloading systemd failed",
		},
		{
			name:        "php-fpm check fails",
			failOn:      []string{"/opt/remi/php84/root/usr/sbin/php-fpm"},
			wantCmds:    []string{rpmQuery84, dnfInstall84, daemonReload, fpm84Check, daemonReload, dnfRemove84},
			wantMessage: "checking /opt/remi/php84/root/usr/sbin/php-fpm failed",
		},
		{
			name:        "preinstalled packages stay",
			preinstall:  true,
			failOn:      []string{"/opt/remi/php84/root/usr/sbin/php-fpm"},
			wantCmds:    []string{rpmQuery84, daemonReload, fpm84Check, daemonReload},
			wantMessage: "checking /opt/remi/php84/root/usr/sbin/php-fpm failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			web := e.client(webUID)
			admin := adminSession(t, e, web)
			if !tc.preinstall {
				e.run.On("/usr/bin/rpm").Fail("not installed")
			}
			// Only the first daemon-reload fails, so the rollback's reload succeeds.
			e.run.On(tc.failOn...).Fail("boom").Times(1)

			v := runJob(t, web, "php.version.install", admin, PHPVersionArgs{Version: "8.4"})
			wantJobError(t, v, api.CodeApplyFailed)
			if v.Error != nil && !strings.HasPrefix(v.Error.Message, tc.wantMessage) {
				t.Errorf("message = %q, want prefix %q", v.Error.Message, tc.wantMessage)
			}
			if got := e.run.Commands(); !slices.Equal(got, tc.wantCmds) {
				t.Errorf("commands:\n got %q\nwant %q", got, tc.wantCmds)
			}
			if unitExists(e) {
				t.Error("unit file left behind")
			}
			if got := installed(t, e); len(got) != 0 {
				t.Errorf("version recorded: %q", got)
			}
		})
	}
}

func TestPHPRemove(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	web := e.client(webUID)
	admin := adminSession(t, e, web)
	if v := runJob(t, web, "php.version.install", admin, PHPVersionArgs{Version: "8.4"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}

	o, err := e.store.CreateOwner(ctx, "acme", state.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	vh, err := e.store.CreateVhost(ctx, o.ID, "8.4", "a.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	before := len(e.run.Calls())
	v := runJob(t, web, "php.version.remove", admin, PHPVersionArgs{Version: "8.4"})
	wantJobError(t, v, api.CodeConflict)
	if v.Error != nil && v.Error.Message != "PHP 8.4 is used by 1 vhosts" {
		t.Errorf("message = %q", v.Error.Message)
	}
	if len(e.run.Calls()) != before || !unitExists(e) || len(installed(t, e)) != 1 {
		t.Error("refused removal changed the host or state")
	}

	if err := e.store.DeleteVhost(ctx, vh.N); err != nil {
		t.Fatal(err)
	}
	if v := runJob(t, web, "php.version.remove", admin, PHPVersionArgs{Version: "8.4"}); v.Status != state.JobSucceeded {
		t.Fatalf("remove: %+v", v)
	}
	if got, want := e.run.Commands()[before:], []string{daemonReload, dnfRemove84}; !slices.Equal(got, want) {
		t.Errorf("commands = %q, want %q", got, want)
	}
	if unitExists(e) || len(installed(t, e)) != 0 {
		t.Error("unit or state left after removal")
	}

	// A rerun cleans the host again even though state.db no longer knows the version.
	if v := runJob(t, web, "php.version.remove", admin, PHPVersionArgs{Version: "8.4"}); v.Status != state.JobSucceeded {
		t.Errorf("rerun: %+v", v)
	}
}

func TestPHPArguments(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	web := e.client(webUID)
	admin := adminSession(t, e, web)
	for _, args := range []any{
		PHPVersionArgs{Version: "7.4"},
		PHPVersionArgs{Version: "8.4; rm -rf /"},
		map[string]string{"version": "8.4", "extra": "x"},
	} {
		v := runJob(t, web, "php.version.install", admin, args)
		wantJobError(t, v, api.CodeInvalidArgument)
	}
	if n := len(e.run.Calls()); n != 0 {
		t.Errorf("invalid arguments ran %d commands", n)
	}
	owner := &api.Actor{UserID: 7, Role: api.RoleOwner, OwnerID: 1}
	var job api.JobResult
	err := web.Call(ctx, "php.version.install", owner, "", PHPVersionArgs{Version: "8.4"}, &job)
	var apiErr *api.Error
	if !errors.As(err, &apiErr) || apiErr.Code != api.CodeForbidden {
		t.Errorf("owner install: %v", err)
	}
}

// Re-running install on a version in use adds packages the list gained since, and reloads
// the version's running FPM masters so they load the new extensions.
func TestPHPReinstallAddsPackagesAndReloadsMasters(t *testing.T) {
	e, web, _, _ := activeVhost(t)
	admin := adminSession(t, e, web)
	mark := len(e.run.Calls())
	e.run.On("/usr/bin/rpm").Fail("package php83-php-pecl-apcu is not installed").Times(1)
	if v := runJob(t, web, "php.version.install", admin, PHPVersionArgs{Version: "8.3"}); v.Status != state.JobSucceeded {
		t.Fatalf("job = %+v", v)
	}
	want := []string{"/usr/bin/rpm -q --quiet " + php83Packages, "/usr/bin/dnf -y install " + php83Packages, daemonReload,
		"/opt/remi/php83/root/usr/sbin/php-fpm -v", "/usr/bin/systemctl reload paddock-php83-fpm@v00001.service"}
	if got := e.run.Commands()[mark:]; !slices.Equal(got, want) {
		t.Errorf("commands:\n got %q\nwant %q", got, want)
	}
}

// A failed re-run must not remove the packages that running vhosts use.
func TestPHPReinstallFailureKeepsPackages(t *testing.T) {
	e, web, _, _ := activeVhost(t)
	admin := adminSession(t, e, web)
	mark := len(e.run.Calls())
	e.run.On("/usr/bin/rpm").Fail("package php83-php-pecl-apcu is not installed").Times(1)
	e.run.On("/opt/remi/php83/root/usr/sbin/php-fpm", "-v").Fail("boom").Times(1)
	wantJobError(t, runJob(t, web, "php.version.install", admin, PHPVersionArgs{Version: "8.3"}), api.CodeApplyFailed)
	for _, c := range e.run.Commands()[mark:] {
		if strings.Contains(c, "dnf -y remove") {
			t.Errorf("a failed re-run removed packages: %q", c)
		}
	}
	if got := installed(t, e); !slices.Contains(got, "8.3") {
		t.Errorf("installed = %q, 8.3 was forgotten", got)
	}
}
