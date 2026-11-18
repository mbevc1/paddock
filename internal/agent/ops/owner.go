package ops

import (
	"context"
	"errors"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/validate"
)

// Upper bounds that keep limits within what the host can express.
const (
	maxCount       = 65535
	maxDiskMB      = 1 << 30
	maxMemoryMB    = 1 << 22
	maxCPUQuotaPct = 100 * 1024
	maxTasks       = 1 << 22
)

// LimitsArgs carries limit changes; omitted fields keep their current (or default) value.
type LimitsArgs struct {
	MaxVhosts          *int      `json:"max_vhosts,omitempty"`
	DiskMB             *int      `json:"disk_mb,omitempty"`
	MaxDatabases       *int      `json:"max_databases,omitempty"`
	MaxDBUsers         *int      `json:"max_db_users,omitempty"`
	MaxAccessAccounts  *int      `json:"max_access_accounts,omitempty"`
	ShellAllowed       *bool     `json:"shell_allowed,omitempty"`
	PHPVersions        *[]string `json:"php_versions,omitempty"`
	MemoryMaxMB        *int      `json:"memory_max_mb,omitempty"`
	CPUQuotaPct        *int      `json:"cpu_quota_pct,omitempty"`
	TasksMax           *int      `json:"tasks_max,omitempty"`
	PMMaxChildren      *int      `json:"pm_max_children,omitempty"`
	MaxUserConnections *int      `json:"max_user_connections,omitempty"`
}

// OwnerCreateArgs are the arguments of owner.create.
type OwnerCreateArgs struct {
	Name   string     `json:"name"`
	Limits LimitsArgs `json:"limits"`
}

// OwnerUpdateArgs are the arguments of owner.update.
type OwnerUpdateArgs struct {
	OwnerID int64  `json:"owner_id"`
	Name    string `json:"name"`
}

// OwnerIDArgs identify one owner.
type OwnerIDArgs struct {
	OwnerID int64 `json:"owner_id"`
}

// OwnerLimitsArgs are the arguments of owner.limits.set.
type OwnerLimitsArgs struct {
	OwnerID int64      `json:"owner_id"`
	Limits  LimitsArgs `json:"limits"`
}

// OwnerCreated is owner.create's result.
type OwnerCreated struct {
	OwnerID int64 `json:"owner_id"`
}

type bound struct {
	name     string
	src      *int
	dst      *int
	min, max int
}

// apply merges a onto base and validates the result.
func (a LimitsArgs) apply(base state.Limits) (state.Limits, error) {
	out := base
	for _, b := range []bound{
		{"max_vhosts", a.MaxVhosts, &out.MaxVhosts, 0, maxCount},
		{"disk_mb", a.DiskMB, &out.DiskMB, 0, maxDiskMB},
		{"max_databases", a.MaxDatabases, &out.MaxDatabases, 0, maxCount},
		{"max_db_users", a.MaxDBUsers, &out.MaxDBUsers, 0, maxCount},
		{"max_access_accounts", a.MaxAccessAccounts, &out.MaxAccessAccounts, 0, maxCount},
		{"memory_max_mb", a.MemoryMaxMB, &out.MemoryMaxMB, 1, maxMemoryMB},
		{"cpu_quota_pct", a.CPUQuotaPct, &out.CPUQuotaPct, 1, maxCPUQuotaPct},
		{"tasks_max", a.TasksMax, &out.TasksMax, 1, maxTasks},
		{"pm_max_children", a.PMMaxChildren, &out.PMMaxChildren, 1, maxCount},
		{"max_user_connections", a.MaxUserConnections, &out.MaxUserConnections, 1, maxCount},
	} {
		if b.src == nil {
			continue
		}
		if *b.src < b.min || *b.src > b.max {
			return state.Limits{}, api.Errorf(api.CodeInvalidArgument, "%s must be between %d and %d", b.name, b.min, b.max)
		}
		*b.dst = *b.src
	}
	if a.ShellAllowed != nil {
		out.ShellAllowed = *a.ShellAllowed
	}
	if a.PHPVersions != nil {
		seen := map[string]bool{}
		for _, v := range *a.PHPVersions {
			if err := validate.PHPVersion(v); err != nil || seen[v] {
				return state.Limits{}, api.Errorf(api.CodeInvalidArgument, "php_versions must list distinct versions from 8.2, 8.3, 8.4")
			}
			seen[v] = true
		}
		out.PHPVersions = append([]string(nil), *a.PHPVersions...)
	}
	return out, nil
}

func ownerID(id int64) error {
	if err := validate.OwnerID(id); err != nil {
		return api.Errorf(api.CodeInvalidArgument, "owner_id must be positive")
	}
	return nil
}

func displayName(name string) error {
	if err := validate.DisplayName(name); err != nil {
		return api.Errorf(api.CodeInvalidArgument, "%v", err)
	}
	return nil
}

// RegisterOwners adds owner.create, owner.update, owner.delete, and owner.limits.set.
//
// Limit changes are recorded here; rendering them into owner slices and FPM pools happens
// when vhosts are applied or reconciled.
func RegisterOwners(r *agent.Registry, store *state.Store) {
	r.Register(agent.Op{Name: "owner.create", Class: agent.ClassAdmin, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[OwnerCreateArgs](c)
		if err != nil {
			return nil, err
		}
		if err := displayName(args.Name); err != nil {
			return nil, err
		}
		limits, err := args.Limits.apply(state.DefaultLimits())
		if err != nil {
			return nil, err
		}
		o, err := store.CreateOwner(ctx, args.Name, limits)
		if errors.Is(err, state.ErrConflict) {
			return nil, api.Errorf(api.CodeConflict, "owner %q exists", args.Name)
		}
		if err != nil {
			return nil, err
		}
		return OwnerCreated{OwnerID: o.ID}, nil
	}})

	r.Register(agent.Op{Name: "owner.update", Class: agent.ClassAdmin, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[OwnerUpdateArgs](c)
		if err != nil {
			return nil, err
		}
		if err := ownerID(args.OwnerID); err != nil {
			return nil, err
		}
		if err := displayName(args.Name); err != nil {
			return nil, err
		}
		return nil, store.RenameOwner(ctx, args.OwnerID, args.Name)
	}})

	r.Register(agent.Op{Name: "owner.delete", Class: agent.ClassAdmin, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[OwnerIDArgs](c)
		if err != nil {
			return nil, err
		}
		if err := ownerID(args.OwnerID); err != nil {
			return nil, err
		}
		err = store.DeleteOwner(ctx, args.OwnerID)
		if errors.Is(err, state.ErrConflict) {
			return nil, api.Errorf(api.CodeConflict, "owner %d still has vhosts", args.OwnerID)
		}
		return nil, err
	}})

	r.Register(agent.Op{Name: "owner.limits.set", Class: agent.ClassAdmin, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[OwnerLimitsArgs](c)
		if err != nil {
			return nil, err
		}
		if err := ownerID(args.OwnerID); err != nil {
			return nil, err
		}
		current, err := store.GetLimits(ctx, args.OwnerID)
		if err != nil {
			return nil, err
		}
		limits, err := args.Limits.apply(current)
		if err != nil {
			return nil, err
		}
		return nil, store.SetLimits(ctx, args.OwnerID, limits)
	}})
}
