package ops

import (
	"context"
	"errors"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/mariadb"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/validate"
)

// DBArgs name a database or extra DB user of a vhost by suffix.
type DBArgs struct {
	VhostID string `json:"vhost_id"`
	Suffix  string `json:"suffix"`
}

// DBUserCreateArgs are the arguments of dbuser.create.
type DBUserCreateArgs struct {
	VhostID string             `json:"vhost_id"`
	Suffix  string             `json:"suffix"`
	Grants  mariadb.Privileges `json:"grants"`
}

// DatabaseResult names a database.
type DatabaseResult struct {
	Database string `json:"database"`
}

// DBCredentials carry a DB user's new password back to its owner, once.
type DBCredentials struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func (h *Host) db() mariadb.Client { return mariadb.Client{Run: h.Run} }

// registerDatabases adds db.create, db.delete, dbuser.create, dbuser.delete, and
// dbuser.password.reset.
func registerDatabases(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "db.create", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[DBArgs](c)
		if err != nil {
			return nil, err
		}
		return createDatabase(ctx, store, h, c.Actor, args)
	}})
	r.Register(agent.Op{Name: "db.delete", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[DBArgs](c)
		if err != nil {
			return nil, err
		}
		return nil, deleteDatabase(ctx, store, h, c.Actor, args)
	}})
	r.Register(agent.Op{Name: "dbuser.create", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[DBUserCreateArgs](c)
		if err != nil {
			return nil, err
		}
		return createDBUser(ctx, store, h, c.Actor, args)
	}})
	r.Register(agent.Op{Name: "dbuser.delete", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[DBArgs](c)
		if err != nil {
			return nil, err
		}
		return nil, deleteDBUser(ctx, store, h, c.Actor, args)
	}})
	r.Register(agent.Op{Name: "dbuser.password.reset", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[DBArgs](c)
		if err != nil {
			return nil, err
		}
		return resetDBPassword(ctx, store, h, c.Actor, args)
	}})
}

// usableVhost loads a vhost the actor may change and takes the host lock; the caller must
// unlock. Vhosts being created or deleted are refused.
func usableVhost(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, vhostID string) (state.Vhost, error) {
	sv, err := loadVhost(ctx, store, actor, vhostID)
	if err != nil {
		return state.Vhost{}, err
	}
	sv, err = lockedVhost(ctx, store, h, sv.N)
	if err != nil {
		return state.Vhost{}, err
	}
	if sv.Status != state.VhostActive && sv.Status != state.VhostSuspended {
		h.mu.Unlock()
		return state.Vhost{}, api.Errorf(api.CodeConflict, "vhost %s is %s", sv.ID, sv.Status)
	}
	return sv, nil
}

func invalidArg(err error) error {
	if err == nil {
		return nil
	}
	return api.Errorf(api.CodeInvalidArgument, "%v", err)
}

func createDatabase(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args DBArgs) (any, error) {
	name, err := validate.DatabaseName(args.VhostID, args.Suffix)
	if err != nil {
		return nil, invalidArg(err)
	}
	sql, err := mariadb.CreateDatabase(name, args.VhostID)
	if err != nil {
		return nil, invalidArg(err)
	}
	sv, err := usableVhost(ctx, store, h, actor, args.VhostID)
	if err != nil {
		return nil, err
	}
	defer h.mu.Unlock()
	if err := store.CreateDatabase(ctx, sv.N, name); err != nil {
		if errors.Is(err, state.ErrConflict) {
			return nil, api.Errorf(api.CodeConflict, "database %s exists", name)
		}
		return nil, err
	}
	if _, err := h.db().Exec(ctx, sql); err != nil {
		if drop, derr := mariadb.DropDatabase(name); derr == nil {
			if _, derr := h.db().Exec(ctx, drop); derr != nil {
				h.logger().Error("dropping a half-created database failed", "err", derr)
			}
		}
		if derr := store.DeleteDatabase(ctx, name); derr != nil {
			h.logger().Error("forgetting a failed database failed", "err", derr)
		}
		return nil, h.applyFailed("creating database "+name, err)
	}
	return DatabaseResult{Database: name}, nil
}

func deleteDatabase(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args DBArgs) error {
	name, err := validate.DatabaseName(args.VhostID, args.Suffix)
	if err != nil {
		return invalidArg(err)
	}
	drop, err := mariadb.DropDatabase(name)
	if err != nil {
		return invalidArg(err)
	}
	revoke, err := mariadb.RevokeDatabase(name, args.VhostID)
	if err != nil {
		return invalidArg(err)
	}
	sv, err := usableVhost(ctx, store, h, actor, args.VhostID)
	if err != nil {
		return err
	}
	defer h.mu.Unlock()
	if n, err := store.DatabaseVhost(ctx, name); err != nil || n != sv.N {
		return api.Errorf(api.CodeNotFound, "database %s not found", name)
	}
	if _, err := h.db().Exec(ctx, drop); err != nil {
		return h.applyFailed("dropping database "+name, err)
	}
	if err := h.db().ExecEach(ctx, revoke, mariadb.NoSuchGrant, mariadb.NoSuchTableGrant); err != nil {
		return h.applyFailed("revoking grants on "+name, err)
	}
	return store.DeleteDatabase(ctx, name)
}

func createDBUser(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args DBUserCreateArgs) (any, error) {
	name, err := validate.DBUserName(args.VhostID, args.Suffix)
	if err != nil {
		return nil, invalidArg(err)
	}
	password, err := mariadb.NewPassword()
	if err != nil {
		return nil, err
	}
	sv, err := usableVhost(ctx, store, h, actor, args.VhostID)
	if err != nil {
		return nil, err
	}
	defer h.mu.Unlock()
	limits, err := store.GetLimits(ctx, sv.OwnerID)
	if err != nil {
		return nil, err
	}
	sql, err := mariadb.CreateUser(name, sv.ID, password, args.Grants, limits.MaxUserConnections)
	if err != nil {
		return nil, api.Errorf(api.CodeInvalidArgument, "grants must be %q or %q", mariadb.PrivilegesAll, mariadb.PrivilegesRead)
	}
	if err := store.CreateDBUser(ctx, sv.N, name, string(args.Grants)); err != nil {
		if errors.Is(err, state.ErrConflict) {
			return nil, api.Errorf(api.CodeConflict, "DB user %s exists", name)
		}
		return nil, err
	}
	if _, err := h.db().Exec(ctx, sql); err != nil {
		if drop, derr := mariadb.DropUsers(name); derr == nil {
			if _, derr := h.db().Exec(ctx, drop); derr != nil {
				h.logger().Error("dropping a half-created DB user failed", "err", derr)
			}
		}
		if derr := store.DeleteDBUser(ctx, name); derr != nil {
			h.logger().Error("forgetting a failed DB user failed", "err", derr)
		}
		return nil, h.applyFailed("creating DB user "+name, err)
	}
	return DBCredentials{User: name, Password: password}, nil
}

func deleteDBUser(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args DBArgs) error {
	name, err := validate.DBUserName(args.VhostID, args.Suffix)
	if err != nil {
		return invalidArg(err)
	}
	drop, err := mariadb.DropUsers(name)
	if err != nil {
		return invalidArg(err)
	}
	sv, err := usableVhost(ctx, store, h, actor, args.VhostID)
	if err != nil {
		return err
	}
	defer h.mu.Unlock()
	if u, err := store.GetDBUser(ctx, name); err != nil || u.VhostN != sv.N {
		return api.Errorf(api.CodeNotFound, "DB user %s not found", name)
	}
	if _, err := h.db().Exec(ctx, drop); err != nil {
		return h.applyFailed("dropping DB user "+name, err)
	}
	return store.DeleteDBUser(ctx, name)
}

// resetDBPassword sets a new password for an extra DB user, or for the vhost's primary user
// when the suffix is empty.
func resetDBPassword(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args DBArgs) (any, error) {
	name := args.VhostID
	if args.Suffix != "" {
		var err error
		if name, err = validate.DBUserName(args.VhostID, args.Suffix); err != nil {
			return nil, invalidArg(err)
		}
	} else if _, err := validate.VhostID(args.VhostID); err != nil {
		return nil, invalidArg(err)
	}
	password, err := mariadb.NewPassword()
	if err != nil {
		return nil, err
	}
	var sql string
	if args.Suffix == "" {
		sql, err = mariadb.SetPrimaryPassword(name, password)
	} else {
		sql, err = mariadb.SetPassword(name, password)
	}
	if err != nil {
		return nil, invalidArg(err)
	}
	sv, err := usableVhost(ctx, store, h, actor, args.VhostID)
	if err != nil {
		return nil, err
	}
	defer h.mu.Unlock()
	if args.Suffix != "" {
		if u, err := store.GetDBUser(ctx, name); err != nil || u.VhostN != sv.N {
			return nil, api.Errorf(api.CodeNotFound, "DB user %s not found", name)
		}
	}
	if _, err := h.db().Exec(ctx, sql); err != nil {
		return nil, h.applyFailed("setting the password of "+name, err)
	}
	return DBCredentials{User: name, Password: password}, nil
}

// createPrimaryDBUser creates the vhost's primary DB user during vhost.create. Its password
// is discarded; the owner gets one through dbuser.password.reset.
func createPrimaryDBUser(ctx context.Context, h *Host, undo *rollback, vhostID string, maxConnections int) error {
	password, err := mariadb.NewPassword()
	if err != nil {
		return err
	}
	sql, err := mariadb.CreatePrimaryUser(vhostID, password, maxConnections)
	if err != nil {
		return err
	}
	drop, err := mariadb.DropUsers(vhostID)
	if err != nil {
		return err
	}
	undo.add(func(ctx context.Context) error {
		_, err := h.db().Exec(ctx, drop)
		return err
	})
	if _, err := h.db().Exec(ctx, sql); err != nil {
		return h.applyFailed("creating the primary DB user", err)
	}
	return nil
}

// dropVhostDatabases drops every database and DB user of a vhost during vhost.delete. Each
// statement tolerates objects already gone, so a rerun is harmless.
func dropVhostDatabases(ctx context.Context, store *state.Store, h *Host, sv state.Vhost) error {
	dbs, err := store.ListDatabases(ctx, sv.N)
	if err != nil {
		return err
	}
	users, err := store.ListDBUsers(ctx, sv.N)
	if err != nil {
		return err
	}
	names := []string{sv.ID}
	for _, u := range users {
		names = append(names, u.Name)
	}
	sql, err := mariadb.DropUsers(names...)
	if err != nil {
		return err
	}
	if len(dbs) > 0 {
		dropDBs, err := mariadb.DropDatabases(dbs...)
		if err != nil {
			return err
		}
		sql = dropDBs + sql
	}
	if _, err := h.db().Exec(ctx, sql); err != nil {
		return h.applyFailed("dropping databases and DB users", err)
	}
	return nil
}

// createVhostDatabase creates the empty database a vhost asked for at creation, within the
// owner's limit. The vhost's rollback drops it again; its state row goes with the vhost.
func createVhostDatabase(ctx context.Context, store *state.Store, h *Host, undo *rollback, sv state.Vhost, suffix string) error {
	name, err := validate.DatabaseName(sv.ID, suffix)
	if err != nil {
		return invalidArg(err)
	}
	sql, err := mariadb.CreateDatabase(name, sv.ID)
	if err != nil {
		return invalidArg(err)
	}
	drop, err := mariadb.DropDatabase(name)
	if err != nil {
		return err
	}
	if err := store.CreateDatabase(ctx, sv.N, name); err != nil {
		return err
	}
	undo.add(func(ctx context.Context) error {
		_, err := h.db().Exec(ctx, drop)
		return err
	})
	if _, err := h.db().Exec(ctx, sql); err != nil {
		return h.applyFailed("creating database "+name, err)
	}
	return nil
}
