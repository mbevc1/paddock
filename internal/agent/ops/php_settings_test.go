package ops

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
)

const (
	testFPM83   = "/usr/bin/setpriv --reuid=1000000001 --regid=1000000001 --clear-groups -- /opt/remi/php83/root/usr/sbin/php-fpm -t --fpm-config /etc/paddock/fpm/v00001.conf"
	reloadFPM83 = "/usr/bin/systemctl reload paddock-php83-fpm@v00001.service"
)

var raisedPHP = VhostPHPSettingsArgs{VhostID: "v00001", MemoryLimitMB: 512, UploadMaxMB: 64, MaxExecutionS: 120}

func TestRenderAndStateAgreeOnPHPDefaults(t *testing.T) {
	d := state.DefaultPHPSettings()
	if render.DefaultPHPSettings != (render.PHPSettings{MemoryLimitMB: d.MemoryLimitMB, UploadMaxMB: d.UploadMaxMB, MaxExecutionS: d.MaxExecutionS}) {
		t.Errorf("render defaults %+v differ from state defaults %+v", render.DefaultPHPSettings, d)
	}
}

func TestPHPSettings(t *testing.T) {
	ctx := context.Background()
	e, web, owner, mark := activeVhost(t)
	if v := runJob(t, web, "vhost.php.settings", owner, raisedPHP); v.Status != state.JobSucceeded {
		t.Fatalf("settings: %+v", v)
	}
	if got := e.run.Commands()[mark:]; !slices.Equal(got, []string{testFPM83, reloadFPM83}) {
		t.Errorf("commands: %q", got)
	}
	for _, want := range []string{"memory_limit] = 512M", "upload_max_filesize] = 64M", "post_max_size] = 64M", "max_execution_time] = 120"} {
		if !fileHas(t, e, fpmConf, want) {
			t.Errorf("FPM config lacks %q", want)
		}
	}
	if sv := vhostState(t, e); sv.PHP != (state.PHPSettings{MemoryLimitMB: 512, UploadMaxMB: 64, MaxExecutionS: 120}) {
		t.Errorf("stored = %+v", sv.PHP)
	}

	var d VhostDetail
	if err := web.Call(ctx, "vhost.get", owner, "", VhostIDArgs{VhostID: "v00001"}, &d); err != nil ||
		d.PHP != (PHPSettingsView{MemoryLimitMB: 512, UploadMaxMB: 64, MaxExecutionS: 120, MemoryCapMB: 2048}) {
		t.Errorf("vhost.get PHP = %+v, %v", d.PHP, err)
	}

	tooMuch := raisedPHP
	tooMuch.MemoryLimitMB = 4096
	wantJobError(t, runJob(t, web, "vhost.php.settings", owner, tooMuch), api.CodeInvalidArgument)
}

func TestPHPSettingsRollBack(t *testing.T) {
	for _, failing := range []string{testFPM83, reloadFPM83} {
		t.Run(failing, func(t *testing.T) {
			e, web, owner, mark := activeVhost(t)
			e.run.OnFunc(func(argv []string) bool { return strings.Join(argv, " ") == failing }).Fail("boom").Times(1)
			wantJobError(t, runJob(t, web, "vhost.php.settings", owner, raisedPHP), api.CodeApplyFailed)
			if !fileHas(t, e, fpmConf, "memory_limit] = 128M") {
				t.Error("FPM config not restored")
			}
			if sv := vhostState(t, e); sv.PHP != state.DefaultPHPSettings() {
				t.Errorf("stored settings changed: %+v", sv.PHP)
			}
			cmds := e.run.Commands()[mark:]
			if failing == reloadFPM83 && cmds[len(cmds)-1] != reloadFPM83 {
				t.Errorf("FPM not reloaded with the restored config: %q", cmds)
			}
		})
	}
}

func TestPHPSettingsOnSuspendedVhost(t *testing.T) {
	ctx := context.Background()
	e, web, owner, mark := activeVhost(t)
	if err := e.store.SetVhostStatus(ctx, 1, state.VhostSuspended); err != nil {
		t.Fatal(err)
	}
	if v := runJob(t, web, "vhost.php.settings", owner, raisedPHP); v.Status != state.JobSucceeded {
		t.Fatalf("settings: %+v", v)
	}
	if got := e.run.Commands()[mark:]; !slices.Equal(got, []string{testFPM83}) {
		t.Errorf("a stopped FPM master was reloaded: %q", got)
	}
}

func TestPHPMemoryFollowsALoweredOwnerLimit(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	if v := runJob(t, web, "vhost.php.settings", owner, raisedPHP); v.Status != state.JobSucceeded {
		t.Fatalf("settings: %+v", v)
	}
	l := state.DefaultLimits()
	l.MemoryMaxMB = 256
	if err := e.store.SetLimits(ctx, owner.OwnerID, l); err != nil {
		t.Fatal(err)
	}
	sv := vhostState(t, e)
	v, err := renderedVhost(ctx, e.store, sv)
	if err != nil || v.PHPSettings().MemoryLimitMB != 256 {
		t.Errorf("rendered memory limit = %d, %v; want the owner's 256", v.PHPSettings().MemoryLimitMB, err)
	}
}
