package agent

import (
	"context"
	"errors"
	"time"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/state"
)

// AdminWindow is how long an admin may run admin operations after a verified code.
const AdminWindow = 10 * time.Minute

// MaxRootWindow caps an admin window that root opens without a code.
const MaxRootWindow = 24 * time.Hour

// TOTPGate authorizes admin operations against the admins in state.db. A user is an admin
// only if state.db says so, whatever role the web process claims.
type TOTPGate struct {
	Store *state.Store
	// Now defaults to time.Now.
	Now func() time.Time
}

func (g *TOTPGate) now() time.Time {
	if g.Now == nil {
		return time.Now()
	}
	return g.Now()
}

func (g *TOTPGate) admin(ctx context.Context, userID int64) (state.Admin, error) {
	a, err := g.Store.GetAdmin(ctx, userID)
	if errors.Is(err, state.ErrNotFound) {
		return state.Admin{}, api.Errorf(api.CodeForbidden, "user %d is not an admin", userID)
	}
	return a, err
}

// Verify checks an admin's code, rejects a code from an already used step, and opens the
// admin window. It returns the window's end.
func (g *TOTPGate) Verify(ctx context.Context, userID int64, code string) (time.Time, error) {
	a, err := g.admin(ctx, userID)
	if err != nil {
		return time.Time{}, err
	}
	now := g.now()
	step, ok := auth.VerifyTOTP(a.TOTPSecret, code, now)
	if !ok {
		return time.Time{}, api.Errorf(api.CodeTOTPInvalid, "code rejected")
	}
	fresh, err := g.Store.UseTOTPStep(ctx, userID, step)
	if err != nil {
		return time.Time{}, err
	}
	if !fresh {
		return time.Time{}, api.Errorf(api.CodeTOTPInvalid, "code already used")
	}
	until := now.Add(AdminWindow)
	if err := g.Store.OpenAdminWindow(ctx, userID, until); err != nil {
		return time.Time{}, err
	}
	return until, nil
}

// OpenWindow opens an admin's window for d without a code, on root's authority.
func (g *TOTPGate) OpenWindow(ctx context.Context, userID int64, d time.Duration) (time.Time, error) {
	if d <= 0 || d > MaxRootWindow {
		return time.Time{}, api.Errorf(api.CodeInvalidArgument, "window must be longer than 0 and at most %s", MaxRootWindow)
	}
	if _, err := g.admin(ctx, userID); err != nil {
		return time.Time{}, err
	}
	until := g.now().Add(d)
	return until, g.Store.OpenAdminWindow(ctx, userID, until)
}

// CloseWindow ends an admin's window, so the next admin operation needs a code.
func (g *TOTPGate) CloseWindow(ctx context.Context, userID int64) error {
	if _, err := g.admin(ctx, userID); err != nil {
		return err
	}
	return g.Store.CloseAdminWindow(ctx, userID)
}

// Authorize implements AdminGate: a given code must verify; without one, the admin's window
// must still be open.
func (g *TOTPGate) Authorize(ctx context.Context, actor *api.Actor, code string) error {
	if actor == nil || actor.Role != api.RoleAdmin {
		return api.Errorf(api.CodeForbidden, "admin operations need an admin")
	}
	if code != "" {
		_, err := g.Verify(ctx, actor.UserID, code)
		return err
	}
	a, err := g.admin(ctx, actor.UserID)
	if err != nil {
		return err
	}
	if g.now().Before(a.WindowUntil) {
		return nil
	}
	return api.Errorf(api.CodeTOTPRequired, "admin code required")
}
