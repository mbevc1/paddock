package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/setup"
	"github.com/mbevc1/paddock/internal/validate"
	"github.com/mbevc1/paddock/internal/web/store"
)

const agentCallTimeout = 30 * time.Minute

var errAdminUsage = errors.New("usage: paddock admin add|totp-reset|reset-password USERNAME")

// adminEnv is what the admin commands touch; tests replace the web user and chown.
type adminEnv struct {
	webDir  string
	socket  string
	out     io.Writer
	webUser func() (int, int, error)
	chown   func(string, int, int) error
}

func runAdmin(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errAdminUsage
	}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", agent.SocketPath, "agent socket path")
	webDir := fs.String("web-dir", setup.WebDir, "directory holding web.db")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errAdminUsage
	}
	username := fs.Arg(0)
	if err := validate.Username(username); err != nil {
		return err
	}
	env := adminEnv{webDir: *webDir, socket: *socket, out: stdout, chown: os.Lchown,
		webUser: func() (int, int, error) {
			uid, gid, err := lookupUser("paddock")
			return int(uid), gid, err
		}}
	switch args[0] {
	case "add":
		return env.add(ctx, username)
	case "totp-reset":
		return env.totpReset(ctx, username)
	case "reset-password":
		return env.resetPassword(ctx, username)
	}
	return errAdminUsage
}

// withWebStore opens web.db as root and hands its files back to user paddock afterwards.
func (e adminEnv) withWebStore(ctx context.Context, fn func(*store.Store) error) error {
	uid, gid, err := e.webUser()
	if err != nil {
		return err
	}
	s, err := store.Open(ctx, filepath.Join(e.webDir, "web.db"))
	if err != nil {
		return err
	}
	err = fn(s)
	if cerr := s.Close(); err == nil {
		err = cerr
	}
	setup.ChownWebFiles(e.chown, e.webDir, uid, gid)
	return err
}

func (e adminEnv) agentCall(ctx context.Context, op string, args, result any) error {
	ctx, cancel := context.WithTimeout(ctx, agentCallTimeout)
	defer cancel()
	c, err := agent.Dial(ctx, e.socket)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Call(ctx, op, nil, "", args, result)
}

// add creates an admin in web.db and registers it with the agent, which holds its TOTP
// secret. If the agent refuses, the web.db user is removed again.
func (e adminEnv) add(ctx context.Context, username string) error {
	return e.withWebStore(ctx, func(s *store.Store) error {
		password, err := auth.RandomPassword()
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return err
		}
		u, err := s.CreateUser(ctx, username, store.RoleAdmin, 0, hash)
		if err != nil {
			return err
		}
		var enrolled ops.TOTPEnrollment
		if err := e.agentCall(ctx, "admin.add", ops.AdminAddArgs{UserID: u.ID, Username: username}, &enrolled); err != nil {
			if derr := s.DeleteUser(ctx, u.ID); derr != nil {
				return errors.Join(err, derr)
			}
			return err
		}
		_, err = fmt.Fprintf(e.out, "Admin %s created. Shown only now:\n  password:  %s\n  TOTP URI:  %s\n", username, password, enrolled.TOTPURI)
		return err
	})
}

func (e adminEnv) totpReset(ctx context.Context, username string) error {
	var id int64
	err := e.withWebStore(ctx, func(s *store.Store) error {
		u, err := s.GetUserByName(ctx, username)
		if err != nil {
			return err
		}
		if u.Role != store.RoleAdmin {
			return fmt.Errorf("%s is not an admin; owners reset their second factor in the panel", username)
		}
		id = u.ID
		return nil
	})
	if err != nil {
		return err
	}
	var enrolled ops.TOTPEnrollment
	if err := e.agentCall(ctx, "admin.totp.reset", ops.AdminUserArgs{UserID: id}, &enrolled); err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.out, "Add this TOTP secret to the admin's authenticator app. It is shown only once:\n%s\n", enrolled.TOTPURI)
	return err
}

// resetPassword sets a random password for any user and ends all their sessions.
func (e adminEnv) resetPassword(ctx context.Context, username string) error {
	return e.withWebStore(ctx, func(s *store.Store) error {
		u, err := s.GetUserByName(ctx, username)
		if err != nil {
			return err
		}
		password, err := auth.RandomPassword()
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return err
		}
		if err := s.SetPasswordHash(ctx, u.ID, hash); err != nil {
			return err
		}
		if err := s.DeleteUserSessions(ctx, u.ID, ""); err != nil {
			return err
		}
		_, err = fmt.Fprintf(e.out, "New password for %s, shown only now: %s\nAll of the user's sessions were ended.\n", username, password)
		return err
	})
}
