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

const (
	fpmConf     = "etc/paddock/fpm/v00001.conf"
	backendConf = "etc/paddock/httpd/v00001.conf"
)

// The new FPM master starts on its own socket while the old one serves; the backend moves to
// the new socket with a graceful reload before the old master stops.
var wantSwitchCommands = []string{
	"/usr/bin/systemctl daemon-reload",
	"/usr/bin/setpriv --reuid=1000000001 --regid=1000000001 --clear-groups -- /opt/remi/php84/root/usr/sbin/php-fpm -t --fpm-config /etc/paddock/fpm/v00001.conf",
	"/usr/bin/systemctl enable --now paddock-php84-fpm@v00001.service",
	"/usr/sbin/httpd -t -f /etc/paddock/httpd/v00001.conf",
	"/usr/bin/systemctl reload paddock-httpd@v00001.service",
	"/usr/bin/systemctl disable --now paddock-php83-fpm@v00001.service",
	"/usr/bin/systemctl daemon-reload",
}

func fileHas(t *testing.T, e *env, rel, s string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(b), s)
}

func TestPHPSwitch(t *testing.T) {
	e, web, owner, mark := activeVhost(t)
	if !fileHas(t, e, fpmConf, "/php83.sock") || !fileHas(t, e, backendConf, "/php83.sock") {
		t.Fatal("a new vhost is not on the PHP 8.3 socket")
	}
	var waited []string
	e.host.WaitSocket = func(_ context.Context, vhostID, socket string) error {
		waited = append(waited, vhostID+"/"+socket)
		return nil
	}
	if v := runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}); v.Status != state.JobSucceeded {
		t.Fatalf("switch: %+v", v)
	}
	if got := e.run.Commands()[mark:]; !slices.Equal(got, wantSwitchCommands) {
		t.Errorf("commands:\n got %q\nwant %q", got, wantSwitchCommands)
	}
	if !slices.Equal(waited, []string{"v00001/php84.sock"}) {
		t.Errorf("waited for %q, want the new version's socket", waited)
	}
	if !fileHas(t, e, fpmConf, "listen = /run/paddock/fpm/v00001/php84.sock") ||
		!fileHas(t, e, backendConf, "proxy:unix:/run/paddock/fpm/v00001/php84.sock|") {
		t.Error("FPM or backend config not moved to the PHP 8.4 socket")
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

// wantSwitchRolledBack checks a failed switch left the vhost on PHP 8.3 with the old master
// serving: configs, drop-ins and the recorded version all as before.
func wantSwitchRolledBack(t *testing.T, e *env, mark int) []string {
	t.Helper()
	cmds := e.run.Commands()[mark:]
	if !fileHas(t, e, fpmConf, "/php83.sock") || !fileHas(t, e, backendConf, "/php83.sock") {
		t.Error("FPM or backend config not restored to the PHP 8.3 socket")
	}
	if fileExists(e, dropIn84) || !fileExists(e, dropIn83) {
		t.Error("drop-ins not restored")
	}
	if sv := vhostState(t, e); sv.PHPVersion != "8.3" {
		t.Errorf("PHP = %s after a failed switch", sv.PHPVersion)
	}
	return cmds
}

func TestPHPSwitchRollsBack(t *testing.T) {
	const (
		stopNew   = "/usr/bin/systemctl disable --now paddock-php84-fpm@v00001.service"
		startOld  = "/usr/bin/systemctl enable --now paddock-php83-fpm@v00001.service"
		stopOld   = "/usr/bin/systemctl disable --now paddock-php83-fpm@v00001.service"
		reloadOld = "/usr/bin/systemctl reload paddock-httpd@v00001.service"
	)
	// Failing commands: php-fpm -t, starting the new FPM, httpd -t, the backend reload, and
	// stopping the old FPM.
	for i, failing := range wantSwitchCommands[1:6] {
		t.Run(failing, func(t *testing.T) {
			e, web, owner, mark := activeVhost(t)
			e.run.OnFunc(func(argv []string) bool { return strings.Join(argv, " ") == failing }).Fail("boom").Times(1)
			wantJobError(t, runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}), api.CodeApplyFailed)
			cmds := wantSwitchRolledBack(t, e, mark)
			if i >= 1 && !slices.Contains(cmds, stopNew) {
				t.Errorf("new FPM left running: %q", cmds)
			}
			reloads := 0
			for _, c := range cmds {
				if c == reloadOld {
					reloads++
				}
			}
			// From httpd -t on, the new backend config is written, so the undo reloads the
			// backend onto the restored one: after the forward reload too, if that ran.
			want := 0
			if i >= 2 {
				want++
			}
			if i >= 3 {
				want++
			}
			if reloads != want {
				t.Errorf("backend reloaded %d times, want %d: %q", reloads, want, cmds)
			}
			if i < 4 && slices.Contains(cmds, stopOld) {
				t.Errorf("old FPM stopped although the switch failed before: %q", cmds)
			}
			if i == 4 && !slices.Contains(cmds, startOld) {
				t.Errorf("old FPM not restarted: %q", cmds)
			}
		})
	}
	t.Run("new socket never appears", func(t *testing.T) {
		e, web, owner, mark := activeVhost(t)
		e.socketErr = errors.New("FPM socket did not appear")
		wantJobError(t, runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}), api.CodeApplyFailed)
		cmds := wantSwitchRolledBack(t, e, mark)
		if !slices.Contains(cmds, stopNew) || slices.Contains(cmds, stopOld) {
			t.Errorf("want the new FPM stopped and the old one untouched: %q", cmds)
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

// A vhost suspended before each PHP version had its own socket resumes on the new one.
func TestResumeRewritesConfigsFromBeforeVersionedSockets(t *testing.T) {
	e, web, _, _ := activeVhost(t)
	admin := adminSession(t, e, web)
	if v := runJob(t, web, "vhost.suspend", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatalf("suspend: %+v", v)
	}
	for _, rel := range []string{fpmConf, backendConf} {
		path := filepath.Join(e.root, rel)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(b), "/php83.sock", "/php.sock")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if v := runJob(t, web, "vhost.resume", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatalf("resume: %+v", v)
	}
	if !fileHas(t, e, fpmConf, "listen = /run/paddock/fpm/v00001/php83.sock") ||
		!fileHas(t, e, backendConf, "proxy:unix:/run/paddock/fpm/v00001/php83.sock|") {
		t.Error("resume left a config on the old shared socket")
	}
}
