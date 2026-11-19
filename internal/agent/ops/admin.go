// Package ops registers the agent's operations, one file per group.
package ops

import (
	"context"
	"errors"
	"time"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/validate"
)

// TOTPIssuer names Paddock in authenticator apps.
const TOTPIssuer = "Paddock"

// AdminAddArgs are the arguments of admin.add.
type AdminAddArgs struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
}

// AdminUserArgs identify one admin.
type AdminUserArgs struct {
	UserID int64 `json:"user_id"`
}

// TOTPVerifyArgs are the arguments of admin.totp.verify.
type TOTPVerifyArgs struct {
	UserID int64  `json:"user_id"`
	Code   string `json:"code"`
}

// AdminWindowArgs are the arguments of admin.window.open.
type AdminWindowArgs struct {
	UserID  int64 `json:"user_id"`
	Seconds int64 `json:"seconds"`
}

// TOTPEnrollment carries a new secret's URI back to the root CLI, once.
type TOTPEnrollment struct {
	TOTPURI string `json:"totp_uri"`
}

// TOTPVerified reports an opened admin window.
type TOTPVerified struct {
	WindowUntil time.Time `json:"window_until"`
}

// RegisterAdmin adds admin.add, admin.totp.reset, admin.window.open and admin.window.close
// (root CLI) and admin.totp.verify (gate).
func RegisterAdmin(r *agent.Registry, store *state.Store, gate *agent.TOTPGate) {
	r.Register(agent.Op{Name: "admin.add", Class: agent.ClassRoot, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[AdminAddArgs](c)
		if err != nil {
			return nil, err
		}
		if args.UserID < 1 {
			return nil, api.Errorf(api.CodeInvalidArgument, "user_id must be positive")
		}
		if err := validate.Username(args.Username); err != nil {
			return nil, api.Errorf(api.CodeInvalidArgument, "%v", err)
		}
		secret, err := auth.NewTOTPSecret()
		if err != nil {
			return nil, err
		}
		if err := store.AddAdmin(ctx, args.UserID, args.Username, secret); err != nil {
			if errors.Is(err, state.ErrConflict) {
				return nil, api.Errorf(api.CodeConflict, "admin %d or username %q exists", args.UserID, args.Username)
			}
			return nil, err
		}
		return TOTPEnrollment{TOTPURI: auth.TOTPURI(TOTPIssuer, args.Username, secret)}, nil
	}})

	r.Register(agent.Op{Name: "admin.totp.reset", Class: agent.ClassRoot, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[AdminUserArgs](c)
		if err != nil {
			return nil, err
		}
		a, err := store.GetAdmin(ctx, args.UserID)
		if errors.Is(err, state.ErrNotFound) {
			return nil, api.Errorf(api.CodeNotFound, "admin %d not found", args.UserID)
		}
		if err != nil {
			return nil, err
		}
		secret, err := auth.NewTOTPSecret()
		if err != nil {
			return nil, err
		}
		if err := store.ResetAdminTOTP(ctx, a.UserID, secret); err != nil {
			return nil, err
		}
		return TOTPEnrollment{TOTPURI: auth.TOTPURI(TOTPIssuer, a.Username, secret)}, nil
	}})

	r.Register(agent.Op{Name: "admin.window.open", Class: agent.ClassRoot, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[AdminWindowArgs](c)
		if err != nil {
			return nil, err
		}
		until, err := gate.OpenWindow(ctx, args.UserID, time.Duration(args.Seconds)*time.Second)
		if err != nil {
			return nil, notFoundAdmin(err, args.UserID)
		}
		return TOTPVerified{WindowUntil: until.UTC()}, nil
	}})

	r.Register(agent.Op{Name: "admin.window.close", Class: agent.ClassRoot, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[AdminUserArgs](c)
		if err != nil {
			return nil, err
		}
		return nil, notFoundAdmin(gate.CloseWindow(ctx, args.UserID), args.UserID)
	}})

	r.Register(agent.Op{Name: "admin.totp.verify", Class: agent.ClassGate, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[TOTPVerifyArgs](c)
		if err != nil {
			return nil, err
		}
		until, err := gate.Verify(ctx, args.UserID, args.Code)
		if err != nil {
			return nil, err
		}
		return TOTPVerified{WindowUntil: until.UTC()}, nil
	}})
}

// notFoundAdmin reports an unknown admin to root as not found; the gate itself calls one
// forbidden, which is the right answer for the web process.
func notFoundAdmin(err error, userID int64) error {
	if e := api.AsError(err); e != nil && e.Code == api.CodeForbidden {
		return api.Errorf(api.CodeNotFound, "admin %d not found", userID)
	}
	return err
}
