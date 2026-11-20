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

func TestAccessSFTP(t *testing.T) {
	ctx := context.Background()
	e, web, owner, mark := activeVhost(t)
	key := newSSHKey(t, "laptop")
	if v := runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Keys: []string{key}}); v.Status != state.JobSucceeded {
		t.Fatalf("create: %+v", v)
	}
	if got, want := e.run.Commands()[mark:], []string{"/usr/sbin/usermod -s /sbin/nologin -G paddock-sftp v00001"}; !slices.Equal(got, want) {
		t.Errorf("commands = %q", got)
	}
	if got := authorizedKeys(t, e); got != key+"\n" {
		t.Errorf("authorized_keys = %q", got)
	}
	wantJobError(t, runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Password: "a long enough password"}), api.CodeConflict)

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
	want := []string{"/usr/sbin/usermod -s /sbin/nologin -G  -L v00001", "/usr/bin/pkill --uid 1000000001 --exact sshd"}
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
	for name, args := range map[string]any{
		"no credentials": AccessCreateArgs{VhostID: "v00001"},
		"short password": AccessCreateArgs{VhostID: "v00001", Password: "short"},
		"bad key":        AccessCreateArgs{VhostID: "v00001", Keys: []string{`command="sh" ` + newSSHKey(t, "x")}},
		"shell kind":     map[string]string{"vhost_id": "v00001", "kind": "shell", "password": "a long enough password"},
	} {
		t.Run(name, func(t *testing.T) {
			wantJobError(t, runJob(t, web, "access.create", owner, args), api.CodeInvalidArgument)
		})
	}
	if len(e.run.Calls()) != mark {
		t.Error("refused accounts ran commands")
	}
}

func TestAccessRollsBack(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	e.run.On("/usr/sbin/usermod", "-s", "/sbin/nologin", "-G", "paddock-sftp").Fail("usermod: group 'paddock-sftp' does not exist").Times(1)
	wantJobError(t, runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Keys: []string{newSSHKey(t, "k")}}), api.CodeApplyFailed)
	if fileExists(e, "etc/ssh/authorized_keys/v00001") {
		t.Error("authorized_keys left after rollback")
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
	if v := runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Keys: []string{newSSHKey(t, "k")}}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	if v := runJob(t, web, "vhost.delete", owner, VhostDeleteArgs{VhostID: "v00001", Confirm: "shop.example.com"}); v.Status != state.JobSucceeded {
		t.Fatalf("delete: %+v", v)
	}
	for _, f := range []string{"etc/ssh/authorized_keys/v00001", "etc/systemd/system/srv-jail-v00001-site.mount", "srv/jail/v00001"} {
		if fileExists(e, f) {
			t.Errorf("%s left behind", f)
		}
	}
}

func TestHostSSHKeys(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	dir := t.TempDir()
	e.host.SSHDir = dir
	var want []HostKeyView
	for _, name := range []string{"ed25519", "ecdsa"} {
		line := newSSHKey(t, "root@web2")
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ssh_host_"+name+"_key.pub"), []byte(line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		want = append(want, HostKeyView{Type: pub.Type(), Fingerprint: ssh.FingerprintSHA256(pub)})
	}
	for name, body := range map[string]string{"ssh_host_rsa_key.pub": "not a key\n", "ssh_host_ed25519_key": "PRIVATE"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	owner := &api.Actor{UserID: 7, Role: api.RoleOwner, OwnerID: 1}
	var got []HostKeyView
	if err := e.client(webUID).Call(ctx, "host.ssh.keys", owner, "", struct{}{}, &got); err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(got, func(a, b HostKeyView) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	slices.SortFunc(want, func(a, b HostKeyView) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	if !slices.Equal(got, want) {
		t.Errorf("host.ssh.keys = %+v, want %+v", got, want)
	}
}
