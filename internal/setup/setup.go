// Package setup configures a host for Paddock (§14.4). It runs as root, is safe to rerun, and
// prints secrets only on the first run.
package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mbevc1/paddock/internal/acme"
	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/mariadb"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
	"github.com/mbevc1/paddock/internal/validate"
	"github.com/mbevc1/paddock/internal/web/store"
)

// wp-cli is pinned by version and SHA-256, the checksum published with the release.
const (
	WPCLIVersion = "2.12.0"
	wpCLIURL     = "https://github.com/wp-cli/wp-cli/releases/download/v" + WPCLIVersion + "/wp-cli-" + WPCLIVersion + ".phar"
	wpCLIPath    = "/usr/local/bin/wp"
)

// wpCLISHA256 is a variable only so tests can pin their own download.
var wpCLISHA256 = "ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c"

// Paths and programs setup uses.
const (
	StateDir   = "/var/lib/paddock/agent"
	WebDir     = "/var/lib/paddock/web"
	markerName = ".paddock"
	keepMarker = "# paddock: keep"
	fstab      = "/etc/fstab"
	modulesCfg = "/etc/httpd/conf.modules.d/00-base.conf"
	statusLine = "LoadModule status_module modules/mod_status.so"

	ss          = "/usr/sbin/ss"
	blkid       = "/usr/sbin/blkid"
	mkfsXFS     = "/usr/sbin/mkfs.xfs"
	mount       = "/usr/bin/mount"
	findmnt     = "/usr/bin/findmnt"
	semanage    = "/usr/sbin/semanage"
	restorecon  = "/usr/sbin/restorecon"
	firewallCmd = "/usr/bin/firewall-cmd"
	sshd        = "/usr/sbin/sshd"
	sysctl      = "/usr/sbin/sysctl"
	systemctl   = "/usr/bin/systemctl"
	apachectl   = "/usr/sbin/apachectl"
	curl        = "/usr/bin/curl"
	// blkidNothing is blkid's exit code when the device has no recognized filesystem.
	blkidNothing = 2
	// findmntNotMounted is findmnt's exit code when the path is not a mount point.
	findmntNotMounted = 1
)

var requiredPorts = []int{80, 443, 8080, 8443}

// ownPrograms may hold the required ports when setup is rerun.
var ownPrograms = map[string]bool{"httpd": true, "paddock": true}

// Options are paddock setup's arguments.
type Options struct {
	Hostname    string
	WWWDevice   string
	Format      bool
	PHPVersions []string
	// Email is the ACME contact for vhost certificates and the panel's own; optional.
	Email     string
	AdminUser string
}

// Deps are the host setup changes.
type Deps struct {
	Run   system.Runner
	Files render.Writer
	FS    *ops.HostFS
	Host  *ops.Host
	Out   io.Writer
	Now   func() time.Time
	// WebUser returns the UID and GID of user paddock, which owns web.db.
	WebUser func() (uid, gid int, err error)
	// Chown sets ownership of web files; nil uses os.Lchown.
	Chown func(path string, uid, gid int) error
	// Download fetches url to a host path; nil runs curl.
	Download func(ctx context.Context, url, hostPath string) error
}

func (d *Deps) path(hostPath string) string {
	root := d.Files.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, hostPath)
}

func (d *Deps) run(ctx context.Context, argv ...string) (system.Result, error) {
	return d.Run.Run(ctx, argv, system.Opts{})
}

func (d *Deps) printf(format string, args ...any) { _, _ = fmt.Fprintf(d.Out, format, args...) }

// Run performs setup.
func Run(ctx context.Context, opts Options, d *Deps) error {
	host, err := validate.Domain(opts.Hostname)
	if err != nil {
		return fmt.Errorf("--hostname: %w", err)
	}
	opts.Hostname = host
	if opts.AdminUser == "" {
		opts.AdminUser = "admin"
	}
	if err := validate.Username(opts.AdminUser); err != nil {
		return fmt.Errorf("--admin: %w", err)
	}
	if len(opts.PHPVersions) == 0 {
		opts.PHPVersions = []string{"8.3", "8.4"}
	}
	for _, v := range opts.PHPVersions {
		if err := validate.PHPVersion(v); err != nil {
			return fmt.Errorf("--php: %w", err)
		}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Chown == nil {
		d.Chown = os.Lchown
	}

	steps := []struct {
		name string
		fn   func(context.Context, Options, *Deps) error
	}{
		{"checking ports", checkPorts},
		{"preparing /srv/www", prepareWWW},
		{"installing host configuration", installConfigs},
		{"configuring MariaDB", configureMariaDB},
	}
	for _, s := range steps {
		d.printf("==> %s\n", s.name)
		if err := s.fn(ctx, opts, d); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	if err := os.MkdirAll(d.path(StateDir), 0o700); err != nil {
		return err
	}
	st, err := state.Open(ctx, d.path(filepath.Join(StateDir, "state.db")))
	if err != nil {
		return err
	}
	defer st.Close()

	d.printf("==> installing PHP %s\n", strings.Join(opts.PHPVersions, ", "))
	for _, v := range opts.PHPVersions {
		if err := ops.InstallPHP(ctx, st, d.Host, v); err != nil {
			return fmt.Errorf("installing PHP %s: %w", v, err)
		}
	}
	for _, s := range []struct {
		name string
		fn   func(context.Context, Options, *Deps) error
	}{
		{"installing wp-cli " + WPCLIVersion, installWPCLI},
		{"enabling services and firewall", enableServices},
	} {
		d.printf("==> %s\n", s.name)
		if err := s.fn(ctx, opts, d); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	if err := firstRun(ctx, opts, d, st); err != nil {
		return fmt.Errorf("creating the first admin: %w", err)
	}
	d.printf("==> starting Paddock\n")
	if _, err := d.run(ctx, systemctl, "enable", "--now", "paddock-agent.service", "paddock-web.service"); err != nil {
		return err
	}
	d.printf("\nPaddock is ready at https://%s:8443/\n", opts.Hostname)
	return nil
}

var ssUsers = regexp.MustCompile(`\(\("([^"]+)"`)

// checkPorts refuses ports held by programs other than Apache or Paddock (§14.4 step 1).
func checkPorts(ctx context.Context, _ Options, d *Deps) error {
	for _, port := range requiredPorts {
		res, err := d.run(ctx, ss, "-H", "-ltnp", "sport = :"+strconv.Itoa(port))
		if err != nil {
			return err
		}
		for _, m := range ssUsers.FindAllStringSubmatch(string(res.Stdout), -1) {
			if !ownPrograms[m[1]] {
				return fmt.Errorf("port %d is in use by %s", port, m[1])
			}
		}
		if len(bytes.TrimSpace(res.Stdout)) > 0 && len(ssUsers.FindAllString(string(res.Stdout), -1)) == 0 {
			return fmt.Errorf("port %d is in use", port)
		}
	}
	return nil
}

// prepareWWW mounts /srv/www with project quotas (§14.4 step 2). It formats the device only
// when it is empty and --format is given, and refuses a /srv/www holding data it did not put
// there.
func prepareWWW(ctx context.Context, opts Options, d *Deps) error {
	if err := os.MkdirAll(d.path(ops.BaseWWW), 0o711); err != nil { // #nosec G301 -- §6: /srv/www is 0711 so vhost users can reach their own tree.
		return err
	}
	res, err := d.run(ctx, findmnt, "-n", "-o", "FSTYPE,OPTIONS", ops.BaseWWW)
	mounted := err == nil
	if err != nil && exitCode(err) != findmntNotMounted {
		return err
	}
	if !mounted {
		if err := checkForeignData(d, false); err != nil {
			return err
		}
		if opts.WWWDevice == "" {
			return errors.New("/srv/www is not mounted; give --www-device")
		}
		if err := formatDevice(ctx, opts, d); err != nil {
			return err
		}
		if res, err = d.run(ctx, findmnt, "-n", "-o", "FSTYPE,OPTIONS", ops.BaseWWW); err != nil {
			return fmt.Errorf("/srv/www did not mount: %w", err)
		}
	}
	fields := strings.Fields(string(res.Stdout))
	if len(fields) < 2 || fields[0] != "xfs" || !strings.Contains(fields[1], "prjquota") && !strings.Contains(fields[1], "pquota") {
		return fmt.Errorf("/srv/www must be XFS mounted with prjquota, found %q", strings.TrimSpace(string(res.Stdout)))
	}
	if err := checkForeignData(d, true); err != nil {
		return err
	}
	if err := os.Chmod(d.path(ops.BaseWWW), 0o711); err != nil { // #nosec G302 -- §6: /srv/www is 0711 so vhost users can reach their own tree.
		return err
	}
	if err := os.MkdirAll(d.path(ops.BaseJail), 0o755); err != nil { // #nosec G301 -- §6: jails are traversed by sshd and their users.
		return err
	}
	rules, err := d.run(ctx, semanage, "fcontext", "-l", "-C")
	if err != nil {
		return err
	}
	if !bytes.Contains(rules.Stdout, []byte("/srv/www(/.*)?")) {
		if _, err := d.run(ctx, semanage, "fcontext", "-a", "-t", "httpd_sys_rw_content_t", "/srv/www(/.*)?"); err != nil {
			return err
		}
	}
	_, err = d.run(ctx, restorecon, "-R", ops.BaseWWW)
	return err
}

var vhostDir = regexp.MustCompile(`^v[0-9]{5}$`)

// checkForeignData refuses a /srv/www whose content Paddock did not create. With markIt set,
// an empty tree gets the marker that later runs recognize.
func checkForeignData(d *Deps, markIt bool) error {
	dir := d.path(ops.BaseWWW)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	marker := false
	var foreign []string
	for _, e := range entries {
		switch {
		case e.Name() == markerName:
			marker = true
		case vhostDir.MatchString(e.Name()):
		default:
			foreign = append(foreign, e.Name())
		}
	}
	if !marker && len(entries) > 0 {
		return fmt.Errorf("/srv/www holds data Paddock did not create (%d entries); refusing to continue", len(entries))
	}
	if marker && len(foreign) > 0 {
		return fmt.Errorf("/srv/www holds unexpected entries: %s", strings.Join(foreign, ", "))
	}
	if !marker && markIt {
		return os.WriteFile(filepath.Join(dir, markerName), []byte("Created by paddock setup.\n"), 0o600)
	}
	return nil
}

func formatDevice(ctx context.Context, opts Options, d *Deps) error {
	dev := opts.WWWDevice
	if !strings.HasPrefix(dev, "/dev/") || strings.ContainsAny(dev, " \n\t") {
		return fmt.Errorf("--www-device %q must be a /dev path", dev)
	}
	typ, err := d.run(ctx, blkid, "-o", "value", "-s", "TYPE", dev)
	fsType := strings.TrimSpace(string(typ.Stdout))
	switch {
	case err != nil && exitCode(err) != blkidNothing:
		return err
	case fsType == "":
		if !opts.Format {
			return fmt.Errorf("%s is empty; rerun with --format to create XFS on it", dev)
		}
		if _, err := d.run(ctx, mkfsXFS, "-q", dev); err != nil {
			return err
		}
	case fsType != "xfs":
		return fmt.Errorf("%s holds %s, not XFS; refusing to format it", dev, fsType)
	}
	uuidRes, err := d.run(ctx, blkid, "-o", "value", "-s", "UUID", dev)
	if err != nil {
		return err
	}
	uuid := strings.TrimSpace(string(uuidRes.Stdout))
	if !regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`).MatchString(uuid) {
		return fmt.Errorf("%s has no usable UUID", dev)
	}
	tab, err := os.ReadFile(d.path(fstab))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !regexp.MustCompile(`(?m)^\S+\s+/srv/www\s`).Match(tab) {
		if len(tab) > 0 && !bytes.HasSuffix(tab, []byte("\n")) {
			tab = append(tab, '\n')
		}
		tab = append(tab, []byte("UUID="+uuid+" /srv/www xfs prjquota 0 0\n")...)
		if _, err := d.Files.Write(render.File{Path: fstab, Data: tab, Mode: 0o644}); err != nil {
			return err
		}
		if _, err := d.run(ctx, systemctl, "daemon-reload"); err != nil {
			return err
		}
	}
	_, err = d.run(ctx, mount, ops.BaseWWW)
	return err
}

// installConfigs writes the host configuration Paddock needs (§14.4 step 3), leaving files
// that contain "# paddock: keep" alone.
func installConfigs(ctx context.Context, opts Options, d *Deps) error {
	var files []render.File
	for _, fn := range []func() (render.File, error){
		render.Sysctl, render.NFTables, render.SSHDDropIn, render.Fail2ban, render.MariaDB,
		func() (render.File, error) { return render.FrontGlobal(opts.Email) },
		func() (render.File, error) { return render.PanelHTTP(opts.Hostname) },
		func() (render.File, error) { return render.WebEnv(opts.Hostname, opts.Email) },
	} {
		f, err := fn()
		if err != nil {
			return err
		}
		files = append(files, f)
	}
	for _, f := range files {
		existing, err := os.ReadFile(d.path(f.Path))
		if err == nil && bytes.Contains(existing, []byte(keepMarker)) {
			d.printf("    keeping local %s\n", f.Path)
			continue
		}
		if _, err := d.Files.Write(f); err != nil {
			return err
		}
	}
	if err := disableModStatus(d); err != nil {
		return err
	}
	_, err := d.run(ctx, sysctl, "-q", "-p", "/etc/sysctl.d/90-paddock.conf")
	return err
}

// disableModStatus comments out mod_status (§7.4), which would otherwise expose server
// internals.
func disableModStatus(d *Deps) error {
	data, err := os.ReadFile(d.path(modulesCfg))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	changed := false
	for i, l := range lines {
		if strings.TrimSpace(l) == statusLine {
			lines[i] = "# Disabled by paddock setup: " + statusLine
			changed = true
		}
	}
	if !changed {
		return nil
	}
	_, err = d.Files.Write(render.File{Path: modulesCfg, Data: []byte(strings.Join(lines, "\n")), Mode: 0o644})
	return err
}

// configureMariaDB starts MariaDB and checks that root logs in over unix_socket (§14.4 step
// 4), which the agent relies on.
func configureMariaDB(ctx context.Context, _ Options, d *Deps) error {
	if _, err := d.run(ctx, systemctl, "enable", "--now", "mariadb.service"); err != nil {
		return err
	}
	if _, err := d.run(ctx, systemctl, "restart", "mariadb.service"); err != nil {
		return err
	}
	rows, err := mariadb.Client{Run: d.Run}.Query(ctx, "SELECT Priv FROM mysql.global_priv WHERE User = 'root' AND Host = 'localhost';\n")
	if err != nil {
		return err
	}
	if len(rows) != 1 || !strings.Contains(rows[0][0], "unix_socket") {
		return errors.New("MariaDB root does not authenticate with unix_socket")
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- a fixed path below the setup root.
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// installWPCLI downloads wp-cli and keeps it only if it matches the pinned SHA-256 (§14.4
// step 6).
func installWPCLI(ctx context.Context, _ Options, d *Deps) error {
	dest := d.path(wpCLIPath)
	if sum, err := fileSHA256(dest); err == nil && sum == wpCLISHA256 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil { // #nosec G301 -- /usr/local/bin holds executables for every user.
		return err
	}
	tmp := wpCLIPath + ".download"
	download := d.Download
	if download == nil {
		download = func(ctx context.Context, url, path string) error {
			_, err := d.run(ctx, curl, "-fsSL", "--proto", "=https", "-o", path, url)
			return err
		}
	}
	if err := download(ctx, wpCLIURL, tmp); err != nil {
		return err
	}
	defer os.Remove(d.path(tmp))
	sum, err := fileSHA256(d.path(tmp))
	if err != nil {
		return err
	}
	if sum != wpCLISHA256 {
		return fmt.Errorf("wp-cli download has SHA-256 %s, want %s", sum, wpCLISHA256)
	}
	if err := os.Chmod(d.path(tmp), 0o755); err != nil { // #nosec G302 -- an executable for every user.
		return err
	}
	return os.Rename(d.path(tmp), dest)
}

// enableServices opens the firewall, starts the services, and reloads sshd and Apache after
// checking their configuration (§14.4 step 7).
func enableServices(ctx context.Context, _ Options, d *Deps) error {
	for _, argv := range [][]string{
		{systemctl, "enable", "--now", "firewalld.service"},
		{firewallCmd, "--permanent", "--add-service=http", "--add-service=https", "--add-port=8080/tcp", "--add-port=8443/tcp"},
		{firewallCmd, "--reload"},
		{systemctl, "enable", "--now", "paddock-nft.service", "fail2ban.service"},
		{systemctl, "restart", "paddock-nft.service", "fail2ban.service"},
		{apachectl, "configtest"},
		{systemctl, "enable", "--now", "httpd.service"},
		{systemctl, "reload", "httpd.service"},
		{sshd, "-t"},
		{systemctl, "reload", "sshd.service"},
	} {
		if _, err := d.run(ctx, argv...); err != nil {
			return err
		}
	}
	return nil
}

// firstRun creates the first admin, in web.db with a random password and in state.db with a
// TOTP secret, and the panel's self-signed certificate. It prints the secrets once; later runs
// find an admin and print none (§14.4 step 8).
func firstRun(ctx context.Context, opts Options, d *Deps, st *state.Store) error {
	uid, gid, err := d.WebUser()
	if err != nil {
		return err
	}
	webDir := d.path(WebDir)
	if err := os.MkdirAll(webDir, 0o700); err != nil {
		return err
	}
	if err := d.Chown(webDir, uid, gid); err != nil {
		return err
	}
	ws, err := store.Open(ctx, filepath.Join(webDir, "web.db"))
	if err != nil {
		return err
	}
	defer func() {
		_ = ws.Close()
		chownWebFiles(d, webDir, uid, gid)
	}()

	users, err := ws.ListUsers(ctx, 0)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(users, func(u store.User) bool { return u.Role == store.RoleAdmin }) {
		d.printf("==> an admin exists already; no secrets printed\n")
		return nil
	}

	d.printf("==> creating the first admin\n")
	password, err := auth.RandomPassword()
	if err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	u, err := ws.CreateUser(ctx, opts.AdminUser, store.RoleAdmin, 0, hash)
	if err != nil {
		return err
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return err
	}
	if err := st.AddAdmin(ctx, u.ID, u.Username, secret); err != nil {
		return err
	}
	certPEM, keyPEM, fingerprint, err := acme.SelfSigned(opts.Hostname, nil, d.Now())
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
		mode fs.FileMode
	}{{"panel.key", keyPEM, 0o600}, {"panel.crt", certPEM, 0o644}} {
		p := filepath.Join(webDir, f.name)
		if err := os.WriteFile(p, f.data, f.mode); err != nil {
			return err
		}
		if err := d.Chown(p, uid, gid); err != nil {
			return err
		}
	}
	d.printf("\nFirst admin, shown only now:\n")
	d.printf("  username:  %s\n", u.Username)
	d.printf("  password:  %s\n", password)
	d.printf("  TOTP URI:  %s\n", auth.TOTPURI(ops.TOTPIssuer, u.Username, secret))
	d.printf("Panel certificate SHA-256 fingerprint:\n  %s\n", fingerprint)
	return nil
}

func chownWebFiles(d *Deps, dir string, uid, gid int) { ChownWebFiles(d.Chown, dir, uid, gid) }

// ChownWebFiles gives web.db and its WAL files to the web user, so a command run as root never
// leaves files the panel cannot open.
func ChownWebFiles(chown func(string, int, int) error, dir string, uid, gid int) {
	for _, name := range []string{"web.db", "web.db-wal", "web.db-shm"} {
		p := filepath.Join(dir, name)
		if _, err := os.Lstat(p); err == nil {
			_ = chown(p, uid, gid)
		}
	}
}

func exitCode(err error) int {
	var e *system.ExitError
	if errors.As(err, &e) {
		return e.ExitCode
	}
	return -1
}
