package ops

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

func newSSHKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sp)), "\n") + " " + comment
}

func authorizedKeys(t *testing.T, e *env) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.root, "etc/ssh/authorized_keys/v00001"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func allowShell(t *testing.T, e *env, ownerID int64) {
	t.Helper()
	l := state.DefaultLimits()
	l.ShellAllowed = true
	if err := e.store.SetLimits(context.Background(), ownerID, l); err != nil {
		t.Fatal(err)
	}
}

func TestAccessSFTP(t *testing.T) {
	ctx := context.Background()
	e, web, owner, mark := activeVhost(t)
	key := newSSHKey(t, "laptop")
	if v := runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Kind: state.AccessSFTP, Keys: []string{key}}); v.Status != state.JobSucceeded {
		t.Fatalf("create: %+v", v)
	}
	if got, want := e.run.Commands()[mark:], []string{"/usr/sbin/usermod -s /sbin/nologin -G paddock-sftp v00001"}; !slices.Equal(got, want) {
		t.Errorf("commands = %q", got)
	}
	if got := authorizedKeys(t, e); got != key+"\n" {
		t.Errorf("authorized_keys = %q", got)
	}
	wantJobError(t, runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Kind: state.AccessSFTP, Password: "a long enough password"}), api.CodeConflict)

	second := newSSHKey(t, "desktop")
	var res AccessKeyResult
	if err := web.Call(ctx, "access.key.add", owner, "", AccessKeyArgs{Account: "v00001", PublicKey: second}, &res); err != nil || !strings.HasPrefix(res.Fingerprint, "SHA256:") {
		t.Fatalf("key.add = %+v, %v", res, err)
	}
	if got := authorizedKeys(t, e); got != key+"\n"+second+"\n" {
		t.Errorf("after add = %q", got)
	}
	wantCode(t, web.Call(ctx, "access.key.add", owner, "", AccessKeyArgs{Account: "v00001", PublicKey: second}, nil), api.CodeConflict)
	wantCode(t, web.Call(ctx, "access.key.add", owner, "", AccessKeyArgs{Account: "v00001", PublicKey: "ssh-rsa AAAA"}, nil), api.CodeInvalidArgument)
	if err := web.Call(ctx, "access.key.remove", owner, "", AccessKeyArgs{Account: "v00001", PublicKey: key}, nil); err != nil {
		t.Fatal(err)
	}
	if got := authorizedKeys(t, e); got != second+"\n" {
		t.Errorf("after remove = %q", got)
	}
	wantCode(t, web.Call(ctx, "access.key.remove", owner, "", AccessKeyArgs{Account: "v00001", PublicKey: key}, nil), api.CodeNotFound)
	stranger := &api.Actor{UserID: 9, Role: api.RoleOwner, OwnerID: 999}
	wantCode(t, web.Call(ctx, "access.key.add", stranger, "", AccessKeyArgs{Account: "v00001", PublicKey: key}, nil), api.CodeNotFound)

	mark = len(e.run.Calls())
	if v := runJob(t, web, "access.delete", owner, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatalf("delete: %+v", v)
	}
	want := []string{"/usr/sbin/usermod -s /sbin/nologin -G  -L v00001", "/usr/bin/pkill --uid 100001 --exact sshd"}
	if got := e.run.Commands()[mark:]; !slices.Equal(got, want) {
		t.Errorf("delete commands = %q", got)
	}
	if _, err := os.Stat(filepath.Join(e.root, "etc/ssh/authorized_keys/v00001")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("authorized_keys left behind")
	}
	if _, err := e.store.AccessAccountOf(ctx, 1); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("account still recorded: %v", err)
	}
}

func TestAccessChecks(t *testing.T) {
	e, web, owner, mark := activeVhost(t)
	for name, args := range map[string]AccessCreateArgs{
		"no credentials": {VhostID: "v00001", Kind: state.AccessSFTP},
		"short password": {VhostID: "v00001", Kind: state.AccessSFTP, Password: "short"},
		"bad kind":       {VhostID: "v00001", Kind: "ftp", Password: "a long enough password"},
		"bad key":        {VhostID: "v00001", Kind: state.AccessSFTP, Keys: []string{`command="sh" ` + newSSHKey(t, "x")}},
	} {
		t.Run(name, func(t *testing.T) {
			wantJobError(t, runJob(t, web, "access.create", owner, args), api.CodeInvalidArgument)
		})
	}
	wantJobError(t, runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Kind: state.AccessShell, Password: "a long enough password"}), api.CodeForbidden)
	if len(e.run.Calls()) != mark {
		t.Error("refused accounts ran commands")
	}
}

const shellJail = "srv/jail/v00001"

func TestAccessShell(t *testing.T) {
	ctx := context.Background()
	e, web, owner, mark := activeVhost(t)
	allowShell(t, e, owner.OwnerID)
	args := AccessCreateArgs{VhostID: "v00001", Kind: state.AccessShell, Password: "correct horse battery"}
	if v := runJob(t, web, "access.create", owner, args); v.Status != state.JobSucceeded {
		t.Fatalf("create: %+v", v)
	}
	want := []string{
		"/usr/bin/mknod -m 0666 /srv/jail/v00001/dev/null c 1 3",
		"/usr/bin/mknod -m 0666 /srv/jail/v00001/dev/zero c 1 5",
		"/usr/bin/mknod -m 0666 /srv/jail/v00001/dev/urandom c 1 9",
		"/usr/bin/mknod -m 0666 /srv/jail/v00001/dev/tty c 5 0",
		"/usr/bin/cp --archive --force /etc/resolv.conf /etc/ld.so.cache /etc/pki /srv/jail/v00001/etc/",
		"/usr/bin/systemctl daemon-reload",
		"/usr/bin/systemctl enable --now srv-jail-v00001-usr.mount",
		"/usr/bin/systemctl enable --now srv-jail-v00001-opt-remi.mount",
		"/usr/bin/systemctl enable --now srv-jail-v00001-proc.mount",
		"/usr/sbin/usermod -s /bin/bash -G paddock-shell v00001",
		"/usr/sbin/chpasswd",
	}
	if got := e.run.Commands()[mark:]; !slices.Equal(got, want) {
		t.Errorf("commands:\n got %q\nwant %q", got, want)
	}
	calls := e.run.Calls()
	if last := calls[len(calls)-1]; string(last.Stdin) != "v00001:correct horse battery\n" {
		t.Errorf("chpasswd stdin = %q", last.Stdin)
	}
	for _, c := range calls {
		if strings.Contains(strings.Join(c.Argv, " "), "correct horse") {
			t.Error("password in argv")
		}
	}
	if got, _ := os.Readlink(filepath.Join(e.root, shellJail, "opt/paddock/bin/php")); got != "/opt/remi/php83/root/usr/bin/php" {
		t.Errorf("php link = %q", got)
	}
	if got, _ := os.Readlink(filepath.Join(e.root, shellJail, "bin")); got != "usr/bin" {
		t.Errorf("bin link = %q", got)
	}
	fi, err := os.Stat(filepath.Join(e.root, shellJail, "tmp"))
	if err != nil || fi.Mode()&fs.ModeSticky == 0 || fi.Mode().Perm() != 0o777 {
		t.Errorf("tmp mode = %v, %v", fi.Mode(), err)
	}
	passwd, err := os.ReadFile(filepath.Join(e.root, shellJail, "etc/passwd"))
	if err != nil || string(passwd) != "v00001:x:100001:100001::/site:/bin/bash\n" {
		t.Errorf("jail passwd = %q, %v", passwd, err)
	}
	for _, unit := range []string{"srv-jail-v00001-usr.mount", "srv-jail-v00001-opt-remi.mount", "srv-jail-v00001-proc.mount"} {
		if !fileExists(e, "etc/systemd/system/"+unit) {
			t.Errorf("%s not written", unit)
		}
	}

	// The jail's php follows a PHP switch.
	if v := runJob(t, web, "vhost.php.switch", owner, VhostPHPSwitchArgs{VhostID: "v00001", Version: "8.4"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	if got, _ := os.Readlink(filepath.Join(e.root, shellJail, "opt/paddock/bin/php")); got != "/opt/remi/php84/root/usr/bin/php" {
		t.Errorf("php link after switch = %q", got)
	}

	mark = len(e.run.Calls())
	if v := runJob(t, web, "access.delete", owner, VhostIDArgs{VhostID: "v00001"}); v.Status != state.JobSucceeded {
		t.Fatalf("delete: %+v", v)
	}
	for _, c := range []string{
		"/usr/bin/systemctl disable --now srv-jail-v00001-proc.mount",
		"/usr/bin/systemctl disable --now srv-jail-v00001-opt-remi.mount",
		"/usr/bin/systemctl disable --now srv-jail-v00001-usr.mount",
	} {
		if !slices.Contains(e.run.Commands()[mark:], c) {
			t.Errorf("missing %q", c)
		}
	}
	entries, err := os.ReadDir(filepath.Join(e.root, shellJail))
	if err != nil || len(entries) != 1 || entries[0].Name() != "site" {
		t.Errorf("jail after delete = %v, %v", entries, err)
	}
	if fileExists(e, "etc/systemd/system/srv-jail-v00001-usr.mount") {
		t.Error("mount unit left behind")
	}
	if _, err := e.store.AccessAccountOf(ctx, 1); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("account still recorded: %v", err)
	}
}

func TestAccessShellRollsBack(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	allowShell(t, e, owner.OwnerID)
	e.run.On("/usr/sbin/usermod", "-s", "/bin/bash").Fail("usermod: group 'paddock-shell' does not exist").Times(1)
	wantJobError(t, runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Kind: state.AccessShell, Password: "correct horse battery"}), api.CodeApplyFailed)
	entries, err := os.ReadDir(filepath.Join(e.root, shellJail))
	if err != nil || len(entries) != 1 || entries[0].Name() != "site" {
		t.Errorf("jail after rollback = %v, %v", entries, err)
	}
	if fileExists(e, "etc/ssh/authorized_keys/v00001") || fileExists(e, "etc/systemd/system/srv-jail-v00001-proc.mount") {
		t.Error("files left after rollback")
	}
	if !slices.Contains(e.run.Commands(), "/usr/sbin/usermod -s /sbin/nologin -G  -L v00001") {
		t.Error("account not locked again")
	}
	if _, err := e.store.AccessAccountOf(ctx, 1); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("account recorded after rollback: %v", err)
	}
}

func TestVhostDeleteRemovesAccess(t *testing.T) {
	e, web, owner, _ := activeVhost(t)
	allowShell(t, e, owner.OwnerID)
	if v := runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Kind: state.AccessShell, Keys: []string{newSSHKey(t, "k")}}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	if v := runJob(t, web, "vhost.delete", owner, VhostDeleteArgs{VhostID: "v00001", Confirm: "shop.example.com"}); v.Status != state.JobSucceeded {
		t.Fatalf("delete: %+v", v)
	}
	for _, f := range []string{"etc/ssh/authorized_keys/v00001", "etc/systemd/system/srv-jail-v00001-usr.mount", shellJail} {
		if fileExists(e, f) {
			t.Errorf("%s left behind", f)
		}
	}
}
