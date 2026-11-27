package ops

import (
	"slices"
	"testing"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

func TestOwnerDisablesAndEnablesTheirVhost(t *testing.T) {
	e, web, owner, mark := activeVhost(t)
	if v := runJob(t, web, "vhost.disable", owner, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatalf("disable: %+v", v)
	}
	if sv := vhostState(t, e); sv.Status != state.VhostSuspended || sv.SuspendedBy != state.SuspendedByOwner {
		t.Errorf("after disable = %s by %q", sv.Status, sv.SuspendedBy)
	}
	cmds := e.run.Commands()[mark:]
	for _, want := range []string{"/usr/bin/systemctl disable --now paddock-httpd@v00001.service", "/usr/bin/systemctl disable --now paddock-php83-fpm@v00001.service"} {
		if !slices.Contains(cmds, want) {
			t.Errorf("disable did not run %q: %q", want, cmds)
		}
	}
	if v := runJob(t, web, "vhost.disable", owner, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Errorf("disabling twice: %+v", v)
	}
	if v := runJob(t, web, "vhost.enable", owner, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatalf("enable: %+v", v)
	}
	if sv := vhostState(t, e); sv.Status != state.VhostActive || sv.SuspendedBy != "" {
		t.Errorf("after enable = %s by %q", sv.Status, sv.SuspendedBy)
	}
}

func TestOwnerCannotLiftAnAdminSuspension(t *testing.T) {
	e, web, owner, _ := activeVhost(t)
	admin := adminSession(t, e, web)
	if v := runJob(t, web, "vhost.suspend", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	if sv := vhostState(t, e); sv.SuspendedBy != state.SuspendedByAdmin {
		t.Errorf("admin suspension recorded as %q", sv.SuspendedBy)
	}
	wantJobError(t, runJob(t, web, "vhost.enable", owner, VhostIDArgs{VhostID: "v00001"}), api.CodeForbidden)
	if v := runJob(t, web, "vhost.disable", owner, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Errorf("disabling an admin-suspended vhost: %+v", v)
	}
	if sv := vhostState(t, e); sv.SuspendedBy != state.SuspendedByAdmin {
		t.Errorf("an owner's disable replaced the admin suspension: %q", sv.SuspendedBy)
	}
}

func TestAdminTakesOverAnOwnerDisable(t *testing.T) {
	e, web, owner, _ := activeVhost(t)
	admin := adminSession(t, e, web)
	if v := runJob(t, web, "vhost.disable", owner, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	mark := len(e.run.Calls())
	if v := runJob(t, web, "vhost.suspend", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	if len(e.run.Calls()) != mark {
		t.Errorf("taking over a suspension ran commands: %q", e.run.Commands()[mark:])
	}
	if sv := vhostState(t, e); sv.SuspendedBy != state.SuspendedByAdmin {
		t.Errorf("suspended by %q after the admin took over", sv.SuspendedBy)
	}
	wantJobError(t, runJob(t, web, "vhost.enable", owner, VhostIDArgs{VhostID: "v00001"}), api.CodeForbidden)
	if v := runJob(t, web, "vhost.resume", admin, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	if sv := vhostState(t, e); sv.Status != state.VhostActive || sv.SuspendedBy != "" {
		t.Errorf("after resume = %s by %q", sv.Status, sv.SuspendedBy)
	}
}
