package setup

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/platform"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
	"github.com/mbevc1/paddock/internal/web/store"
)

type env struct {
	t       *testing.T
	root    string
	run     *system.Fake
	out     *bytes.Buffer
	deps    *Deps
	mounted bool
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"etc/httpd/conf.modules.d", "srv"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, modulesCfg), []byte("LoadModule dir_module modules/mod_dir.so\n"+statusLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, fstab), []byte("UUID=1111 / xfs defaults 0 0"), 0o644); err != nil {
		t.Fatal(err)
	}
	plat, err := platform.ForMajor(9)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, root: root, run: &system.Fake{}, out: &bytes.Buffer{}}
	files := render.Writer{Root: root}
	hostFS := &ops.HostFS{Root: root, Chown: func(*os.Root, string, int, int) error { return nil }}
	e.deps = &Deps{
		Run: e.run, Files: files, FS: hostFS, Out: e.out,
		Host:    &ops.Host{Run: e.run, Files: files, FS: hostFS, Platform: plat},
		Now:     func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) },
		WebUser: func() (int, int, error) { return os.Getuid(), os.Getgid(), nil },
		Chown:   func(string, int, int) error { return nil },
	}
	e.run = withMount(e)
	return e
}

// withMount rebuilds the fake so mount flips the mounted state and findmnt reports it.
func withMount(e *env) *system.Fake {
	f := &system.Fake{}
	e.deps.Run = f
	e.deps.Host.Run = f
	f.OnCall(func(c system.Call) bool { return c.Argv[0] == findmnt && !e.mounted }).
		Return(system.Result{ExitCode: 1}, &system.ExitError{Program: findmnt, ExitCode: 1})
	f.On(findmnt).Return(system.Result{Stdout: []byte("xfs rw,relatime,attr2,inode64,logbufs=8,prjquota\n")}, nil)
	f.On(blkid, "-o", "value", "-s", "TYPE").Return(system.Result{ExitCode: 2}, &system.ExitError{Program: blkid, ExitCode: 2}).Times(1)
	f.On(blkid, "-o", "value", "-s", "UUID").Return(system.Result{Stdout: []byte("8f6a2c1e-1234-4abc-9def-0123456789ab\n")}, nil)
	f.OnCall(func(c system.Call) bool {
		if c.Argv[0] == mount {
			e.mounted = true
		}
		return false
	}).Return(system.Result{}, nil)
	f.On("/usr/bin/mariadb").Return(system.Result{Stdout: []byte(`{"access":0,"plugin":"mysql_native_password","auth_or":[{},{"plugin":"unix_socket"}]}` + "\n")}, nil)
	return f
}

func defaultOptions() Options {
	return Options{Hostname: "panel.example.com", WWWDevice: "/dev/vdb", Format: true, PHPVersions: []string{"8.3"}, Email: "ops@example.com"}
}

func (e *env) read(rel string) string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.root, rel))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || strings.Contains(path, "/var/lib/paddock/") {
			return err
		}
		b, err := os.ReadFile(path)
		out[path] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFirstRunAndRerun(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if err := Run(ctx, defaultOptions(), e.deps); err != nil {
		t.Fatalf("first run: %v\n%s", err, e.out)
	}
	out := e.out.String()
	for _, want := range []string{"username:  admin", "password:  ", "TOTP URI:  otpauth://totp/Paddock:admin?", "SHA-256 fingerprint", "https://panel.example.com:8443/"} {
		if !strings.Contains(out, want) {
			t.Errorf("first run output lacks %q:\n%s", want, out)
		}
	}
	cmds := e.deps.Run.(*system.Fake).Commands()
	for _, want := range []string{
		"/usr/sbin/mkfs.xfs -q /dev/vdb",
		"/usr/bin/mount /srv/www",
		"/usr/sbin/semanage fcontext -a -t httpd_sys_rw_content_t /srv/www(/.*)?",
		"/usr/bin/firewall-cmd --reload",
		"/usr/sbin/sshd -t",
		"/usr/bin/systemctl enable --now paddock-agent.service paddock-web.service",
	} {
		if !slices.Contains(cmds, want) {
			t.Errorf("missing %q", want)
		}
	}
	if !strings.Contains(e.read(fstab), "UUID=8f6a2c1e-1234-4abc-9def-0123456789ab /srv/www xfs prjquota 0 0\n") {
		t.Errorf("fstab = %q", e.read(fstab))
	}
	if !strings.Contains(e.read(modulesCfg), "# Disabled by paddock setup: "+statusLine) {
		t.Error("mod_status still loaded")
	}
	for _, f := range []string{"etc/sysctl.d/90-paddock.conf", "etc/paddock/nftables.conf", "etc/ssh/sshd_config.d/50-paddock.conf",
		"etc/fail2ban/jail.d/paddock.conf", "etc/my.cnf.d/paddock.cnf", "etc/httpd/conf.d/paddock-00-global.conf",
		"etc/httpd/conf.d/paddock-01-panel.conf", "etc/paddock/web.env", "etc/systemd/system/paddock-php83-fpm@.service",
		"srv/www/.paddock", "var/lib/paddock/web/panel.crt", "var/lib/paddock/web/panel.key"} {
		if _, err := os.Stat(filepath.Join(e.root, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}

	ws, err := store.Open(ctx, filepath.Join(e.root, WebDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := ws.GetUserByName(ctx, "admin")
	_ = ws.Close()
	if err != nil || admin.Role != store.RoleAdmin {
		t.Fatalf("web admin = %+v, %v", admin, err)
	}
	st, err := state.Open(ctx, filepath.Join(e.root, StateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if a, err := st.GetAdmin(ctx, admin.ID); err != nil || a.Username != "admin" || len(a.TOTPSecret) != 20 {
		t.Errorf("state admin = %+v, %v", a, err)
	}
	if v, _ := st.ListPHPVersions(ctx); !slices.Equal(v, []string{"8.3"}) {
		t.Errorf("PHP versions = %v", v)
	}
	_ = st.Close()

	before := snapshot(t, e.root)
	e.out.Reset()
	e.deps.Run = withMount(e)
	e.deps.Host.Run = e.deps.Run
	if err := Run(ctx, defaultOptions(), e.deps); err != nil {
		t.Fatalf("rerun: %v\n%s", err, e.out)
	}
	if out := e.out.String(); strings.Contains(out, "password:") || strings.Contains(out, "otpauth://") || !strings.Contains(out, "no secrets printed") {
		t.Errorf("rerun output:\n%s", out)
	}
	if slices.Contains(e.deps.Run.(*system.Fake).Commands(), "/usr/sbin/mkfs.xfs -q /dev/vdb") {
		t.Error("rerun formatted the device")
	}
	after := snapshot(t, e.root)
	for path, content := range before {
		if after[path] != content {
			t.Errorf("rerun changed %s", path)
		}
	}
	if len(after) != len(before) {
		t.Errorf("rerun created files: %d before, %d after", len(before), len(after))
	}
}

func TestRefusesForeignData(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(filepath.Join(e.root, "srv/www/customer-site"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), defaultOptions(), e.deps)
	if err == nil || !strings.Contains(err.Error(), "did not create") {
		t.Fatalf("err = %v", err)
	}
	if slices.Contains(e.deps.Run.(*system.Fake).Commands(), "/usr/sbin/mkfs.xfs -q /dev/vdb") {
		t.Error("formatted despite foreign data")
	}
}

func TestDeviceChecks(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	opts := defaultOptions()
	opts.Format = false
	if err := Run(ctx, opts, e.deps); err == nil || !strings.Contains(err.Error(), "--format") {
		t.Errorf("empty device without --format: %v", err)
	}

	e = newEnv(t)
	f := &system.Fake{}
	f.OnCall(func(c system.Call) bool { return c.Argv[0] == findmnt }).Return(system.Result{ExitCode: 1}, &system.ExitError{Program: findmnt, ExitCode: 1})
	f.On(blkid, "-o", "value", "-s", "TYPE").Return(system.Result{Stdout: []byte("ext4\n")}, nil)
	e.deps.Run, e.deps.Host.Run = f, f
	if err := Run(ctx, defaultOptions(), e.deps); err == nil || !strings.Contains(err.Error(), "ext4") {
		t.Errorf("ext4 device: %v", err)
	}
	if slices.ContainsFunc(f.Commands(), func(c string) bool { return strings.HasPrefix(c, mkfsXFS) }) {
		t.Error("formatted an ext4 device")
	}
}

func TestPortsHeldByOthers(t *testing.T) {
	e := newEnv(t)
	g := &system.Fake{}
	g.OnFunc(func(argv []string) bool { return argv[0] == ss && argv[3] == "sport = :443" }).
		Return(system.Result{Stdout: []byte(`LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))` + "\n")}, nil)
	e.deps.Run, e.deps.Host.Run = g, g
	if err := Run(context.Background(), defaultOptions(), e.deps); err == nil || !strings.Contains(err.Error(), "port 443 is in use by nginx") {
		t.Errorf("err = %v", err)
	}
	h := &system.Fake{}
	h.OnFunc(func(argv []string) bool { return argv[0] == ss }).
		Return(system.Result{Stdout: []byte(`LISTEN 0 511 *:443 *:* users:(("httpd",pid=1,fd=4),("httpd",pid=2,fd=4))` + "\n")}, nil)
	h.OnFunc(func(argv []string) bool { return argv[0] == findmnt }).Return(system.Result{ExitCode: 1}, &system.ExitError{Program: findmnt, ExitCode: 1})
	e.deps.Run, e.deps.Host.Run = h, h
	err := Run(context.Background(), Options{Hostname: "panel.example.com"}, e.deps)
	if err == nil || !strings.Contains(err.Error(), "give --www-device") {
		t.Errorf("ports held by httpd should pass the port check: %v", err)
	}
}

func TestKeepsMarkedFiles(t *testing.T) {
	e := newEnv(t)
	path := filepath.Join(e.root, "etc/ssh/sshd_config.d/50-paddock.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	local := "# paddock: keep\nAuthorizedKeysFile /etc/ssh/authorized_keys/%u\n"
	if err := os.WriteFile(path, []byte(local), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), defaultOptions(), e.deps); err != nil {
		t.Fatalf("Run: %v\n%s", err, e.out)
	}
	if got := e.read("etc/ssh/sshd_config.d/50-paddock.conf"); got != local {
		t.Errorf("marked file overwritten: %q", got)
	}
}
