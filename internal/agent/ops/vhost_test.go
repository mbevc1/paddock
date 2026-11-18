package ops

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

// vhostEnv returns an environment with PHP 8.3 installed and one owner.
func vhostEnv(t *testing.T) (*env, *agent.Client, *api.Actor, state.Owner) {
	t.Helper()
	ctx := context.Background()
	e := newEnv(t)
	if err := e.store.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	o, err := e.store.CreateOwner(ctx, "acme", state.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return e, e.client(webUID), &api.Actor{UserID: 7, Role: api.RoleOwner, OwnerID: o.ID}, o
}

func createArgs(o state.Owner) VhostCreateArgs {
	return VhostCreateArgs{OwnerID: o.ID, PrimaryDomain: "shop.example.com", Aliases: []string{"www.shop.example.com"}, PHPVersion: "8.3"}
}

// regularFiles lists the regular files below root, relative to it.
func regularFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, _ := filepath.Rel(root, path)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

var wantCreateCommands = []string{
	"/usr/sbin/groupadd -g 100001 v00001",
	"/usr/sbin/useradd -u 100001 -g 100001 -M -d /srv/www/v00001 -s /sbin/nologin -K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0 v00001",
	"/usr/sbin/xfs_quota -x -c project -s -p /srv/www/v00001 1 /srv/www",
	"/usr/sbin/xfs_quota -x -c limit -p bhard=10240m 1 /srv/www",
	"/usr/sbin/restorecon -RF /srv/www/v00001",
	"/usr/bin/systemd-tmpfiles --create /etc/tmpfiles.d/paddock-v00001.conf",
	"/usr/bin/setpriv --reuid=100001 --regid=100001 --clear-groups -- /opt/remi/php83/root/usr/sbin/php-fpm -t --fpm-config /etc/paddock/fpm/v00001.conf",
	"/usr/sbin/httpd -t -f /etc/paddock/httpd/v00001.conf",
	"/usr/bin/systemctl mask user@100001.service",
	"/usr/bin/systemctl daemon-reload",
	"/usr/bin/systemctl enable --now srv-jail-v00001-site.mount",
	"/usr/bin/systemctl enable --now paddock-php83-fpm@v00001.service",
	"/usr/bin/systemctl enable --now paddock-httpd@v00001.service",
	"/usr/sbin/apachectl configtest",
	"/usr/bin/systemctl reload httpd.service",
}

var wantVhostFiles = []string{
	"etc/httpd/conf.d/paddock-v00001.conf",
	"etc/paddock/fpm/v00001.conf",
	"etc/paddock/httpd/v00001.conf",
	"etc/systemd/system/paddock-httpd@v00001.service.d/10-sandbox.conf",
	"etc/systemd/system/paddock-owner-1.slice",
	"etc/systemd/system/paddock-php83-fpm@v00001.service.d/10-sandbox.conf",
	"etc/systemd/system/srv-jail-v00001-site.mount",
	"etc/systemd/system/user-100001.slice.d/limits.conf",
	"etc/tmpfiles.d/paddock-v00001.conf",
}

func TestVhostCreate(t *testing.T) {
	ctx := context.Background()
	e, web, owner, o := vhostEnv(t)

	v := runJob(t, web, "vhost.create", owner, createArgs(o))
	if v.Status != state.JobSucceeded || string(v.Result) != `{"vhost_id":"v00001"}` {
		t.Fatalf("job = %+v", v)
	}
	if got := e.run.Commands(); !slices.Equal(got, wantCreateCommands) {
		t.Errorf("commands:\n got %q\nwant %q", got, wantCreateCommands)
	}
	if got := regularFiles(t, filepath.Join(e.root, "etc")); !slices.Equal(prefixAll("etc/", got), wantVhostFiles) {
		t.Errorf("files:\n got %q\nwant %q", got, wantVhostFiles)
	}
	for dir, mode := range map[string]fs.FileMode{
		"srv/www/v00001": 0o700, "srv/www/v00001/public": 0o750, "srv/www/v00001/sessions": 0o700,
		"srv/jail/v00001": 0o755, "srv/jail/v00001/site": 0o755,
	} {
		fi, err := os.Stat(filepath.Join(e.root, dir))
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != mode {
			t.Errorf("%s: %v, %v", dir, fi, err)
		}
	}
	if !slices.Contains(*e.chowns, chownCall{"v00001/public", 100001, 100001}) ||
		!slices.Contains(*e.chowns, chownCall{"v00001/site", 0, 0}) {
		t.Errorf("chowns = %v", *e.chowns)
	}
	sv, err := e.store.GetVhost(ctx, 1)
	if err != nil || sv.Status != state.VhostActive || sv.OwnerID != o.ID {
		t.Errorf("state = %+v, %v", sv, err)
	}
	front, err := os.ReadFile(filepath.Join(e.root, "etc/httpd/conf.d/paddock-v00001.conf"))
	if err != nil || !strings.Contains(string(front), "MDomain shop.example.com www.shop.example.com") {
		t.Errorf("front = %q, %v", front, err)
	}
}

func prefixAll(prefix string, in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = prefix + s
	}
	return out
}

// undoOf maps a create command to the command that reverses it.
var undoOf = map[string]string{
	"/usr/sbin/groupadd -g 100001 v00001":                              "/usr/sbin/groupdel v00001",
	wantCreateCommands[1]:                                              "/usr/sbin/userdel v00001",
	wantCreateCommands[2]:                                              "/usr/sbin/xfs_quota -x -c project -C -p /srv/www/v00001 1 /srv/www",
	wantCreateCommands[3]:                                              "/usr/sbin/xfs_quota -x -c limit -p bhard=0 1 /srv/www",
	"/usr/bin/systemctl mask user@100001.service":                      "/usr/bin/systemctl unmask user@100001.service",
	"/usr/bin/systemctl enable --now srv-jail-v00001-site.mount":       "/usr/bin/systemctl disable --now srv-jail-v00001-site.mount",
	"/usr/bin/systemctl enable --now paddock-php83-fpm@v00001.service": "/usr/bin/systemctl disable --now paddock-php83-fpm@v00001.service",
	"/usr/bin/systemctl enable --now paddock-httpd@v00001.service":     "/usr/bin/systemctl disable --now paddock-httpd@v00001.service",
}

func assertRolledBack(t *testing.T, e *env, before []string) {
	t.Helper()
	ctx := context.Background()
	if got := regularFiles(t, e.root); !slices.Equal(got, before) {
		t.Errorf("files after rollback:\n got %q\nwant %q", got, before)
	}
	for _, dir := range []string{"srv/www/v00001", "srv/jail/v00001"} {
		if _, err := os.Stat(filepath.Join(e.root, dir)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left behind: %v", dir, err)
		}
	}
	if _, err := e.store.GetVhost(ctx, 1); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("vhost left in state: %v", err)
	}
}

func TestVhostCreateRollsBackEveryStep(t *testing.T) {
	for i, failing := range wantCreateCommands {
		t.Run(failing, func(t *testing.T) {
			e, web, owner, o := vhostEnv(t)
			before := regularFiles(t, e.root)
			e.run.OnFunc(func(argv []string) bool { return strings.Join(argv, " ") == failing }).Fail("boom").Times(1)

			v := runJob(t, web, "vhost.create", owner, createArgs(o))
			wantJobError(t, v, api.CodeApplyFailed)
			assertRolledBack(t, e, before)

			cmds := e.run.Commands()
			if !slices.Equal(cmds[:i+1], wantCreateCommands[:i+1]) {
				t.Fatalf("forward commands = %q", cmds[:i+1])
			}
			undone := cmds[i+1:]
			for _, done := range wantCreateCommands[:i] {
				if undo, ok := undoOf[done]; ok && !slices.Contains(undone, undo) {
					t.Errorf("%q not undone; rollback ran %q", done, undone)
				}
			}
			if i > slices.Index(wantCreateCommands, "/usr/bin/systemctl daemon-reload") &&
				!slices.Contains(undone, "/usr/bin/systemctl daemon-reload") {
				t.Error("rollback did not reload systemd")
			}
		})
	}
}

func TestVhostCreateRollsBackWhenSocketNeverAppears(t *testing.T) {
	e, web, owner, o := vhostEnv(t)
	before := regularFiles(t, e.root)
	e.socketErr = errors.New("FPM socket did not appear")
	v := runJob(t, web, "vhost.create", owner, createArgs(o))
	wantJobError(t, v, api.CodeApplyFailed)
	assertRolledBack(t, e, before)
	cmds := e.run.Commands()
	if slices.Contains(cmds, "/usr/bin/systemctl enable --now paddock-httpd@v00001.service") {
		t.Error("backend started without an FPM socket")
	}
	if !slices.Contains(cmds, "/usr/bin/systemctl disable --now paddock-php83-fpm@v00001.service") {
		t.Errorf("FPM not stopped: %q", cmds)
	}
}

func TestVhostCreateChecks(t *testing.T) {
	ctx := context.Background()
	e, web, owner, o := vhostEnv(t)
	l := state.DefaultLimits()
	l.PHPVersions = []string{"8.4"}
	restricted, err := e.store.CreateOwner(ctx, "restricted", l)
	if err != nil {
		t.Fatal(err)
	}
	other := &api.Actor{UserID: 8, Role: api.RoleOwner, OwnerID: restricted.ID}
	admin := &api.Actor{UserID: 1, Role: api.RoleAdmin}

	for _, tc := range []struct {
		name  string
		actor *api.Actor
		args  VhostCreateArgs
		want  api.Code
	}{
		{"another owner's account", other, createArgs(o), api.CodeForbidden},
		{"PHP not allowed", other, VhostCreateArgs{OwnerID: restricted.ID, PrimaryDomain: "r.example.com", PHPVersion: "8.3"}, api.CodeForbidden},
		{"PHP not installed", owner, VhostCreateArgs{OwnerID: o.ID, PrimaryDomain: "a.example.com", PHPVersion: "8.4"}, api.CodeInvalidArgument},
		{"bad domain", owner, VhostCreateArgs{OwnerID: o.ID, PrimaryDomain: "a.example.com\nInclude x", PHPVersion: "8.3"}, api.CodeInvalidArgument},
		{"alias repeats primary", owner, VhostCreateArgs{OwnerID: o.ID, PrimaryDomain: "a.example.com", Aliases: []string{"A.example.com"}, PHPVersion: "8.3"}, api.CodeInvalidArgument},
		{"missing owner", admin, VhostCreateArgs{OwnerID: 999, PrimaryDomain: "a.example.com", PHPVersion: "8.3"}, api.CodeNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantJobError(t, runJob(t, web, "vhost.create", tc.actor, tc.args), tc.want)
		})
	}
	if n := len(e.run.Calls()); n != 0 {
		t.Errorf("refused creates ran %d commands", n)
	}

	if v := runJob(t, web, "vhost.create", admin, createArgs(o)); v.Status != state.JobSucceeded {
		t.Fatalf("admin create for an owner: %+v", v)
	}
	dup := createArgs(o)
	dup.Aliases = nil
	wantJobError(t, runJob(t, web, "vhost.create", owner, dup), api.CodeConflict)

	l = state.DefaultLimits()
	l.MaxVhosts = 2
	if err := e.store.SetLimits(ctx, o.ID, l); err != nil {
		t.Fatal(err)
	}
	if v := runJob(t, web, "vhost.create", owner, VhostCreateArgs{OwnerID: o.ID, PrimaryDomain: "b.example.com", PHPVersion: "8.3"}); v.Status != state.JobSucceeded {
		t.Fatalf("second vhost: %+v", v)
	}
	wantJobError(t, runJob(t, web, "vhost.create", owner, VhostCreateArgs{OwnerID: o.ID, PrimaryDomain: "c.example.com", PHPVersion: "8.3"}), api.CodeLimitExceeded)
}

var wantDeleteCommands = []string{
	"/usr/bin/systemctl disable --now paddock-httpd@v00001.service",
	"/usr/bin/systemctl disable --now paddock-php83-fpm@v00001.service",
	"/usr/bin/systemctl disable --now srv-jail-v00001-site.mount",
	"/usr/sbin/apachectl configtest",
	"/usr/bin/systemctl reload httpd.service",
	"/usr/bin/systemctl unmask user@100001.service",
	"/usr/bin/systemctl daemon-reload",
	"/usr/bin/tar --create --gzip --numeric-owner --xattrs --selinux --acls --file /var/lib/paddock/agent/archive/v00001-20261117T120000Z.tar.gz --directory /srv/www v00001",
	"/usr/sbin/xfs_quota -x -c limit -p bhard=0 1 /srv/www",
	"/usr/sbin/xfs_quota -x -c project -C -p /srv/www/v00001 1 /srv/www",
	"/usr/sbin/userdel v00001",
	"/usr/sbin/groupdel v00001",
}

func TestVhostDelete(t *testing.T) {
	ctx := context.Background()
	e, web, owner, o := vhostEnv(t)
	before := regularFiles(t, filepath.Join(e.root, "etc"))
	if v := runJob(t, web, "vhost.create", owner, createArgs(o)); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	created := len(e.run.Calls())

	stranger := &api.Actor{UserID: 9, Role: api.RoleOwner, OwnerID: 999}
	wantJobError(t, runJob(t, web, "vhost.delete", stranger, VhostDeleteArgs{VhostID: "v00001", Confirm: "shop.example.com"}), api.CodeNotFound)
	wantJobError(t, runJob(t, web, "vhost.delete", owner, VhostDeleteArgs{VhostID: "v00001", Confirm: "v00001"}), api.CodeInvalidArgument)
	wantJobError(t, runJob(t, web, "vhost.delete", owner, VhostDeleteArgs{VhostID: "../etc", Confirm: "x"}), api.CodeInvalidArgument)
	if len(e.run.Calls()) != created {
		t.Fatal("refused deletes ran commands")
	}

	if v := runJob(t, web, "vhost.delete", owner, VhostDeleteArgs{VhostID: "v00001", Confirm: "shop.example.com"}); v.Status != state.JobSucceeded {
		t.Fatalf("delete: %+v", v)
	}
	if got := e.run.Commands()[created:]; !slices.Equal(got, wantDeleteCommands) {
		t.Errorf("commands:\n got %q\nwant %q", got, wantDeleteCommands)
	}
	// The owner slice is shared by the owner's vhosts and stays.
	want := append(slices.Clone(before), "systemd/system/paddock-owner-1.slice")
	sort.Strings(want)
	if got := regularFiles(t, filepath.Join(e.root, "etc")); !slices.Equal(got, want) {
		t.Errorf("files left:\n got %q\nwant %q", got, want)
	}
	for _, dir := range []string{"srv/www/v00001", "srv/jail/v00001", "run/paddock/fpm/v00001"} {
		if _, err := os.Stat(filepath.Join(e.root, dir)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left: %v", dir, err)
		}
	}
	if _, err := e.store.GetVhost(ctx, 1); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("vhost still in state: %v", err)
	}
}

func TestVhostDeleteResumesAfterFailure(t *testing.T) {
	ctx := context.Background()
	e, web, owner, o := vhostEnv(t)
	if v := runJob(t, web, "vhost.create", owner, createArgs(o)); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	e.run.On("/usr/sbin/userdel").Fail("userdel: user v00001 is currently used by process 4242").Times(1)
	args := VhostDeleteArgs{VhostID: "v00001", Confirm: "shop.example.com"}
	wantJobError(t, runJob(t, web, "vhost.delete", owner, args), api.CodeApplyFailed)
	if sv, err := e.store.GetVhost(ctx, 1); err != nil || sv.Status != state.VhostFailed {
		t.Fatalf("after failed delete: %+v, %v", sv, err)
	}

	// The rerun finds units, files, and the tree already gone.
	e.run.On("/usr/bin/systemctl", "disable").Fail("Unit file does not exist")
	e.run.On("/usr/bin/systemctl", "is-active").Return(system.Result{ExitCode: 3}, &system.ExitError{Program: "systemctl", ExitCode: 3})
	e.run.On("/usr/sbin/groupdel").Return(system.Result{ExitCode: 6}, &system.ExitError{Program: "groupdel", ExitCode: 6})
	mark := len(e.run.Calls())
	if v := runJob(t, web, "vhost.delete", owner, args); v.Status != state.JobSucceeded {
		t.Fatalf("rerun: %+v", v)
	}
	rerun := e.run.Commands()[mark:]
	for _, skipped := range []string{"/usr/bin/tar", "/usr/sbin/apachectl configtest"} {
		for _, c := range rerun {
			if strings.HasPrefix(c, skipped) {
				t.Errorf("rerun repeated %q", c)
			}
		}
	}
	if _, err := e.store.GetVhost(ctx, 1); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("vhost still in state: %v", err)
	}
}

func TestVhostDeleteRefusesRunningUnit(t *testing.T) {
	ctx := context.Background()
	e, web, owner, o := vhostEnv(t)
	if v := runJob(t, web, "vhost.create", owner, createArgs(o)); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	e.run.On("/usr/bin/systemctl", "disable", "--now", "paddock-httpd@v00001.service").Fail("Job failed")
	v := runJob(t, web, "vhost.delete", owner, VhostDeleteArgs{VhostID: "v00001", Confirm: "shop.example.com"})
	wantJobError(t, v, api.CodeApplyFailed)
	if _, err := os.Stat(filepath.Join(e.root, "srv/www/v00001")); err != nil {
		t.Errorf("tree removed while the backend still ran: %v", err)
	}
	if sv, _ := e.store.GetVhost(ctx, 1); sv.Status != state.VhostFailed {
		t.Errorf("status = %s", sv.Status)
	}
}
