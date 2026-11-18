package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

// activeVhost creates v00001 on PHP 8.3 with 8.4 also installed, and returns the env with the
// commands recorded so far cleared from view.
func activeVhost(t *testing.T) (*env, *agent.Client, *api.Actor, int) {
	t.Helper()
	e, web, owner, o := vhostEnv(t)
	if err := e.store.AddPHPVersion(context.Background(), "8.4"); err != nil {
		t.Fatal(err)
	}
	if v := runJob(t, web, "vhost.create", owner, createArgs(o)); v.Status != state.JobSucceeded {
		t.Fatalf("create: %+v", v)
	}
	return e, web, owner, len(e.run.Calls())
}

func vhostState(t *testing.T, e *env) state.Vhost {
	t.Helper()
	sv, err := e.store.GetVhost(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return sv
}

func fileExists(e *env, rel string) bool {
	_, err := os.Stat(filepath.Join(e.root, rel))
	return err == nil
}

const (
	dropIn83 = "etc/systemd/system/paddock-php83-fpm@v00001.service.d/10-sandbox.conf"
	dropIn84 = "etc/systemd/system/paddock-php84-fpm@v00001.service.d/10-sandbox.conf"
)

var wantSwitchCommands = []string{
	"/usr/bin/systemctl daemon-reload",
	"/usr/bin/setpriv --reuid=1000000001 --regid=1000000001 --clear-groups -- /opt/remi/php84/root/usr/sbin/php-fpm -t --fpm-config /etc/paddock/fpm/v00001.conf",
	"/usr/bin/systemctl enable --now paddock-php84-fpm@v00001.service",
	"/usr/bin/systemctl disable --now paddock-php83-fpm@v00001.service",
	"/usr/bin/systemctl daemon-reload",
}

func TestPHPSwitch(t *testing.T) {
	e, web, owner, mark := activeVhost(t)
	if v := runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}); v.Status != state.JobSucceeded {
		t.Fatalf("switch: %+v", v)
	}
	if got := e.run.Commands()[mark:]; !slices.Equal(got, wantSwitchCommands) {
		t.Errorf("commands:\n got %q\nwant %q", got, wantSwitchCommands)
	}
	if fileExists(e, dropIn83) || !fileExists(e, dropIn84) {
		t.Error("drop-ins not moved to the new unit")
	}
	if sv := vhostState(t, e); sv.PHPVersion != "8.4" {
		t.Errorf("PHP = %s", sv.PHPVersion)
	}

	mark = len(e.run.Calls())
	if v := runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}); v.Status != state.JobSucceeded {
		t.Errorf("switch to the current version: %+v", v)
	}
	if len(e.run.Calls()) != mark {
		t.Error("switching to the current version ran commands")
	}
}

func TestPHPSwitchRestartsWhenSocketVanishes(t *testing.T) {
	e, web, owner, mark := activeVhost(t)
	waits := 0
	e.host.WaitSocket = func(context.Context, string) error {
		waits++
		if waits == 1 {
			return errors.New("socket gone")
		}
		return nil
	}
	if v := runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}); v.Status != state.JobSucceeded {
		t.Fatalf("switch: %+v", v)
	}
	if !slices.Contains(e.run.Commands()[mark:], "/usr/bin/systemctl restart paddock-php84-fpm@v00001.service") {
		t.Errorf("new FPM not restarted: %q", e.run.Commands()[mark:])
	}
}

func TestPHPSwitchRollsBack(t *testing.T) {
	for i, failing := range wantSwitchCommands[1:4] {
		t.Run(failing, func(t *testing.T) {
			e, web, owner, mark := activeVhost(t)
			e.run.OnFunc(func(argv []string) bool { return strings.Join(argv, " ") == failing }).Fail("boom").Times(1)
			v := runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"})
			wantJobError(t, v, api.CodeApplyFailed)

			cmds := e.run.Commands()[mark:]
			if i >= 1 && !slices.Contains(cmds, "/usr/bin/systemctl disable --now paddock-php84-fpm@v00001.service") {
				t.Errorf("new FPM left running: %q", cmds)
			}
			if i >= 2 && !slices.Contains(cmds, "/usr/bin/systemctl enable --now paddock-php83-fpm@v00001.service") {
				t.Errorf("old FPM not restarted: %q", cmds)
			}
			if fileExists(e, dropIn84) || !fileExists(e, dropIn83) {
				t.Error("drop-ins not restored")
			}
			if sv := vhostState(t, e); sv.PHPVersion != "8.3" {
				t.Errorf("PHP = %s after a failed switch", sv.PHPVersion)
			}
		})
	}
	t.Run("socket never returns", func(t *testing.T) {
		e, web, owner, mark := activeVhost(t)
		e.socketErr = errors.New("socket gone")
		wantJobError(t, runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}), api.CodeApplyFailed)
		cmds := e.run.Commands()[mark:]
		if !slices.Contains(cmds, "/usr/bin/systemctl enable --now paddock-php83-fpm@v00001.service") {
			t.Errorf("old FPM not restarted: %q", cmds)
		}
		if sv := vhostState(t, e); sv.PHPVersion != "8.3" {
			t.Errorf("PHP = %s", sv.PHPVersion)
		}
	})
}

func TestPHPSwitchChecks(t *testing.T) {
	ctx := context.Background()
	e, web, owner, mark := activeVhost(t)
	l := state.DefaultLimits()
	l.PHPVersions = []string{"8.3"}
	if err := e.store.SetLimits(ctx, owner.OwnerID, l); err != nil {
		t.Fatal(err)
	}
	stranger := &api.Actor{UserID: 9, Role: api.RoleOwner, OwnerID: 999}
	for _, tc := range []struct {
		name  string
		actor *api.Actor
		args  VhostPHPSwitchArgs
		want  api.Code
	}{
		{"not allowed", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}, api.CodeForbidden},
		{"not installed", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.2"}, api.CodeInvalidArgument},
		{"bad version", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8"}, api.CodeInvalidArgument},
		{"another owner's vhost", stranger, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.3"}, api.CodeNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantJobError(t, runJob(t, web, "vhost.php.switch", tc.actor, tc.args), tc.want)
		})
	}
	if err := e.store.SetLimits(ctx, owner.OwnerID, state.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := e.store.SetVhostStatus(ctx, 1, state.VhostSuspended); err != nil {
		t.Fatal(err)
	}
	wantJobError(t, runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}), api.CodeConflict)
	if len(e.run.Calls()) != mark {
		t.Error("refused switches ran commands")
	}
}

func frontConfig(t *testing.T, e *env) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.root, "etc/httpd/conf.d/paddock-v00001.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSuspendAndResume(t *testing.T) {
	e, web, owner, mark := activeVhost(t)
	admin := adminSession(t, e, web)

	wantCode(t, web.Call(context.Background(), "vhost.suspend", owner, "", VhostIDArgs{VhostID: "v00001"}, nil), api.CodeForbidden)

	if v := runJob(t, web, "vhost.suspend", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatalf("suspend: %+v", v)
	}
	wantSuspend := []string{
		"/usr/sbin/apachectl configtest",
		"/usr/bin/systemctl reload httpd.service",
		"/usr/bin/systemctl disable --now paddock-httpd@v00001.service",
		"/usr/bin/systemctl disable --now paddock-php83-fpm@v00001.service",
	}
	if got := e.run.Commands()[mark:]; !slices.Equal(got, wantSuspend) {
		t.Errorf("suspend commands:\n got %q\nwant %q", got, wantSuspend)
	}
	front := frontConfig(t, e)
	if !strings.Contains(front, "Redirect 503 /") || strings.Contains(front, "ProxyPass ") {
		t.Errorf("suspended front:\n%s", front)
	}
	if sv := vhostState(t, e); sv.Status != state.VhostSuspended {
		t.Errorf("status = %s", sv.Status)
	}

	mark = len(e.run.Calls())
	if v := runJob(t, web, "vhost.resume", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatalf("resume: %+v", v)
	}
	wantResume := []string{
		"/usr/bin/systemctl enable --now paddock-php83-fpm@v00001.service",
		"/usr/bin/systemctl enable --now paddock-httpd@v00001.service",
		"/usr/sbin/apachectl configtest",
		"/usr/bin/systemctl reload httpd.service",
	}
	if got := e.run.Commands()[mark:]; !slices.Equal(got, wantResume) {
		t.Errorf("resume commands:\n got %q\nwant %q", got, wantResume)
	}
	if front := frontConfig(t, e); strings.Contains(front, "Redirect 503") || !strings.Contains(front, "ProxyPass ") {
		t.Errorf("resumed front:\n%s", front)
	}
	if sv := vhostState(t, e); sv.Status != state.VhostActive {
		t.Errorf("status = %s", sv.Status)
	}

	mark = len(e.run.Calls())
	if v := runJob(t, web, "vhost.resume", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Errorf("resuming an active vhost: %+v", v)
	}
	if len(e.run.Calls()) != mark {
		t.Error("resuming an active vhost ran commands")
	}
}

func TestSuspendRollsBack(t *testing.T) {
	e, web, _, mark := activeVhost(t)
	admin := adminSession(t, e, web)
	before := frontConfig(t, e)
	e.run.On("/usr/bin/systemctl", "disable", "--now", "paddock-php83-fpm@v00001.service").Fail("boom").Times(1)
	wantJobError(t, runJob(t, web, "vhost.suspend", admin, VhostIDArgs{VhostID: "v00001"}), api.CodeApplyFailed)
	cmds := e.run.Commands()[mark:]
	if !slices.Contains(cmds, "/usr/bin/systemctl enable --now paddock-httpd@v00001.service") {
		t.Errorf("backend not restarted: %q", cmds)
	}
	if got := frontConfig(t, e); got != before {
		t.Errorf("front not restored:\n%s", got)
	}
	if cmds[len(cmds)-1] != "/usr/bin/systemctl reload httpd.service" {
		t.Errorf("front not reloaded after restore: %q", cmds)
	}
	if sv := vhostState(t, e); sv.Status != state.VhostActive {
		t.Errorf("status = %s", sv.Status)
	}
}

func TestResumeRollsBack(t *testing.T) {
	e, web, _, _ := activeVhost(t)
	admin := adminSession(t, e, web)
	if v := runJob(t, web, "vhost.suspend", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	mark := len(e.run.Calls())
	e.run.On("/usr/sbin/apachectl", "configtest").Fail("Syntax error").Times(1)
	wantJobError(t, runJob(t, web, "vhost.resume", admin, VhostIDArgs{VhostID: "v00001"}), api.CodeApplyFailed)
	cmds := e.run.Commands()[mark:]
	for _, want := range []string{
		"/usr/bin/systemctl disable --now paddock-httpd@v00001.service",
		"/usr/bin/systemctl disable --now paddock-php83-fpm@v00001.service",
	} {
		if !slices.Contains(cmds, want) {
			t.Errorf("missing %q in %q", want, cmds)
		}
	}
	if !strings.Contains(frontConfig(t, e), "Redirect 503 /") {
		t.Error("front no longer suspended after a failed resume")
	}
	if sv := vhostState(t, e); sv.Status != state.VhostSuspended {
		t.Errorf("status = %s", sv.Status)
	}
}
