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
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/setup"
	"github.com/mbevc1/paddock/internal/validate"
	"github.com/mbevc1/paddock/internal/web/store"
)

const agentCallTimeout = 30 * time.Minute

var errAdminUsage = errors.New("usage: paddock admin add|remove|disable|enable|totp-reset|reset-password|login-totp-off|login-totp-on|lock USERNAME\n       paddock admin unlock -for DURATION USERNAME")

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
	window := fs.Duration("for", 0, "unlock only: how long the admin may act without a TOTP code (at most 24h)")
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
	case "remove":
		return env.remove(ctx, username)
	case "disable":
		return env.setDisabled(ctx, username, true)
	case "enable":
		return env.setDisabled(ctx, username, false)
	case "totp-reset":
		return env.totpReset(ctx, username)
	case "reset-password":
		return env.resetPassword(ctx, username)
	case "login-totp-off":
		return env.setLoginTOTP(ctx, username, false)
	case "login-totp-on":
		return env.setLoginTOTP(ctx, username, true)
	case "unlock":
		return env.unlock(ctx, username, *window)
	case "lock":
		return env.lock(ctx, username)
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

// adminID looks an admin's user ID up in web.db; why says what an owner should do instead.
func (e adminEnv) adminID(ctx context.Context, username, why string) (int64, error) {
	var id int64
	err := e.withWebStore(ctx, func(s *store.Store) error {
		u, err := s.GetUserByName(ctx, username)
		if err != nil {
			return err
		}
		if u.Role != store.RoleAdmin {
			return fmt.Errorf("%s is not an admin; %s", username, why)
		}
		id = u.ID
		return nil
	})
	return id, err
}

// remove takes an admin's rights in the agent first, then deletes their panel user and
// sessions. The agent already forgetting the admin means an earlier run got that far, so a
// rerun finishes the panel side.
func (e adminEnv) remove(ctx context.Context, username string) error {
	id, err := e.adminID(ctx, username, "owners are removed with their owner in the panel")
	if err != nil {
		return err
	}
	err = e.agentCall(ctx, "admin.remove", ops.AdminUserArgs{UserID: id}, nil)
	if apiErr := api.AsError(err); err != nil && (apiErr == nil || apiErr.Code != api.CodeNotFound) {
		return err
	}
	if err := e.withWebStore(ctx, func(s *store.Store) error { return s.DeleteUser(ctx, id) }); err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.out, "Admin %s removed; their sessions are ended.\n", username)
	return err
}

// setDisabled disables or enables an admin, in the agent first since it decides admin rights.
// Disabling also ends the admin's panel sessions; their account and TOTP secret stay.
func (e adminEnv) setDisabled(ctx context.Context, username string, disabled bool) error {
	id, err := e.adminID(ctx, username, "owners' users are managed in the panel")
	if err != nil {
		return err
	}
	op, done := "admin.enable", "enabled; they sign in as before"
	if disabled {
		op, done = "admin.disable", "disabled; their sessions are ended"
	}
	if err := e.agentCall(ctx, op, ops.AdminUserArgs{UserID: id}, nil); err != nil {
		return err
	}
	err = e.withWebStore(ctx, func(s *store.Store) error {
		if err := s.SetDisabled(ctx, id, disabled); err != nil {
			return err
		}
		if disabled {
			return s.DeleteUserSessions(ctx, id, "")
		}
		return nil
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.out, "Admin %s %s.\n", username, done)
	return err
}

func (e adminEnv) totpReset(ctx context.Context, username string) error {
	id, err := e.adminID(ctx, username, "owners reset their second factor in the panel")
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

// unlock lets an admin run admin operations without a TOTP code for d, on root's authority.
// The agent caps d at agent.MaxRootWindow and records the call in its audit log.
func (e adminEnv) unlock(ctx context.Context, username string, d time.Duration) error {
	if d <= 0 || d > agent.MaxRootWindow {
		return fmt.Errorf("-for must be longer than 0 and at most %s", agent.MaxRootWindow)
	}
	id, err := e.adminID(ctx, username, "owners have no admin window")
	if err != nil {
		return err
	}
	var v ops.TOTPVerified
	if err := e.agentCall(ctx, "admin.window.open", ops.AdminWindowArgs{UserID: id, Seconds: int64(d / time.Second)}, &v); err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.out, "%s may run admin actions without a TOTP code until %s. End it early with: paddock admin lock %s\n",
		username, v.WindowUntil.Local().Format("2006-01-02 15:04 MST"), username)
	return err
}

// lock closes an admin's window, so the next admin action asks for a TOTP code.
func (e adminEnv) lock(ctx context.Context, username string) error {
	id, err := e.adminID(ctx, username, "owners have no admin window")
	if err != nil {
		return err
	}
	if err := e.agentCall(ctx, "admin.window.close", ops.AdminUserArgs{UserID: id}, nil); err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.out, "%s's admin window is closed; the next admin action asks for a TOTP code.\n", username)
	return err
}

// setLoginTOTP sets whether an admin's login asks for a TOTP code. The agent asks for a code
// before admin operations either way. Turning it on ends the admin's sessions, which may have
// started without a code.
func (e adminEnv) setLoginTOTP(ctx context.Context, username string, on bool) error {
	return e.withWebStore(ctx, func(s *store.Store) error {
		u, err := s.GetUserByName(ctx, username)
		if err != nil {
			return err
		}
		if u.Role != store.RoleAdmin {
			return fmt.Errorf("%s is not an admin; admins require TOTP per owner in the panel", username)
		}
		if err := s.SetAdminLoginTOTP(ctx, u.ID, on); err != nil {
			return err
		}
		if !on {
			_, err = fmt.Fprintf(e.out, "%s now logs in with the password alone; admin actions still ask for a TOTP code.\n", username)
			return err
		}
		if err := s.DeleteUserSessions(ctx, u.ID, ""); err != nil {
			return err
		}
		_, err = fmt.Fprintf(e.out, "%s's login asks for a TOTP code again. All of the admin's sessions were ended.\n", username)
		return err
	})
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
