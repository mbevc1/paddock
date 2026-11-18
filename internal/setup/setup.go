// Package setup creates Paddock's databases and its first admin. Host preparation belongs to
// bootstrap.sh, and the panel certificate to paddock web.
package setup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/validate"
	"github.com/mbevc1/paddock/internal/web/store"
)

// Directories holding state.db and web.db.
const (
	StateDir = "/var/lib/paddock/agent"
	WebDir   = "/var/lib/paddock/web"
)

// Options are paddock setup's arguments.
type Options struct {
	AdminUser string
}

// Deps are what setup touches on the host.
type Deps struct {
	// Root prefixes StateDir and WebDir; empty means /.
	Root string
	Out  io.Writer
	// WebUser returns the UID and GID of user paddock, which owns web.db.
	WebUser func() (uid, gid int, err error)
	// Chown sets ownership of web files; nil uses os.Lchown.
	Chown func(path string, uid, gid int) error
}

func (d *Deps) path(hostPath string) string {
	root := d.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, hostPath)
}

func (d *Deps) printf(format string, args ...any) { _, _ = fmt.Fprintf(d.Out, format, args...) }

// Run creates state.db and web.db and, when no admin exists, the first admin: a random password
// in web.db and a TOTP secret in state.db. It prints the secrets only when it creates them, so
// a rerun changes nothing.
func Run(ctx context.Context, opts Options, d *Deps) error {
	if opts.AdminUser == "" {
		opts.AdminUser = "admin"
	}
	if err := validate.Username(opts.AdminUser); err != nil {
		return fmt.Errorf("--admin: %w", err)
	}
	if d.Chown == nil {
		d.Chown = os.Lchown
	}
	uid, gid, err := d.WebUser()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(d.path(StateDir), 0o700); err != nil {
		return err
	}
	st, err := state.Open(ctx, d.path(filepath.Join(StateDir, "state.db")))
	if err != nil {
		return err
	}
	defer st.Close()

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
		ChownWebFiles(d.Chown, webDir, uid, gid)
	}()

	users, err := ws.ListUsers(ctx, 0)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(users, func(u store.User) bool { return u.Role == store.RoleAdmin }) {
		d.printf("An admin exists already; no secrets printed.\n")
		return nil
	}

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
	d.printf("First admin, shown only now:\n")
	d.printf("  username:  %s\n", u.Username)
	d.printf("  password:  %s\n", password)
	d.printf("  TOTP URI:  %s\n", auth.TOTPURI(ops.TOTPIssuer, u.Username, secret))
	return nil
}

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
