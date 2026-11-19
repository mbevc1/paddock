package ops

import (
	"context"
	"errors"
	"time"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

// VhostView is how the panel sees a vhost.
type VhostView struct {
	ID         string            `json:"id"`
	OwnerID    int64             `json:"owner_id"`
	PHPVersion string            `json:"php_version"`
	Status     state.VhostStatus `json:"status"`
	Primary    string            `json:"primary"`
	Aliases    []string          `json:"aliases"`
	CreatedAt  time.Time         `json:"created_at"`
}

// VhostDetail adds what the vhost detail page shows.
type VhostDetail struct {
	VhostView
	Cert      CertStatus   `json:"cert"`
	Access    *AccessView  `json:"access,omitempty"`
	Databases []string     `json:"databases"`
	DBUsers   []DBUserView `json:"db_users"`
}

// AccessView is a vhost's SFTP account.
type AccessView struct {
	Account string    `json:"account"`
	Keys    []KeyView `json:"keys"`
}

// KeyView is one authorized key.
type KeyView struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
}

// DBUserView is one extra DB user.
type DBUserView struct {
	Name   string `json:"name"`
	Grants string `json:"grants"`
}

// OwnerView is an owner with limits.
type OwnerView struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	Limits    LimitsView `json:"limits"`
}

// LimitsView mirrors state.Limits for the panel.
type LimitsView struct {
	MaxVhosts          int      `json:"max_vhosts"`
	DiskMB             int      `json:"disk_mb"`
	MaxDatabases       int      `json:"max_databases"`
	MaxDBUsers         int      `json:"max_db_users"`
	MaxAccessAccounts  int      `json:"max_access_accounts"`
	PHPVersions        []string `json:"php_versions"`
	MemoryMaxMB        int      `json:"memory_max_mb"`
	CPUQuotaPct        int      `json:"cpu_quota_pct"`
	TasksMax           int      `json:"tasks_max"`
	PMMaxChildren      int      `json:"pm_max_children"`
	MaxUserConnections int      `json:"max_user_connections"`
}

// VhostListArgs filter vhost.list; admins may name an owner, owners see their own.
type VhostListArgs struct {
	OwnerID int64 `json:"owner_id,omitempty"`
}

// AuditListArgs page through the audit log, newest first.
type AuditListArgs struct {
	Before int64 `json:"before,omitempty"`
	Limit  int   `json:"limit,omitempty"`
}

// VhostUpdateArgs are the arguments of vhost.update.
type VhostUpdateArgs struct {
	VhostID string   `json:"vhost_id"`
	Aliases []string `json:"aliases"`
}

func limitsView(l state.Limits) LimitsView {
	php := l.PHPVersions
	if php == nil {
		php = []string{}
	}
	return LimitsView{l.MaxVhosts, l.DiskMB, l.MaxDatabases, l.MaxDBUsers, l.MaxAccessAccounts, php,
		l.MemoryMaxMB, l.CPUQuotaPct, l.TasksMax, l.PMMaxChildren, l.MaxUserConnections}
}

func vhostView(ctx context.Context, store *state.Store, sv state.Vhost) (VhostView, error) {
	domains, err := store.Domains(ctx, sv.N)
	if err != nil {
		return VhostView{}, err
	}
	v := VhostView{ID: sv.ID, OwnerID: sv.OwnerID, PHPVersion: sv.PHPVersion, Status: sv.Status, Aliases: []string{}, CreatedAt: sv.CreatedAt}
	for _, d := range domains {
		if d.Primary {
			v.Primary = d.Name
		} else {
			v.Aliases = append(v.Aliases, d.Name)
		}
	}
	return v, nil
}

func registerReads(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "vhost.list", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[VhostListArgs](c)
		if err != nil {
			return nil, err
		}
		owner := args.OwnerID
		if c.Actor.Role == api.RoleOwner {
			owner = c.Actor.OwnerID
		}
		vhosts, err := store.ListVhosts(ctx, owner)
		if err != nil {
			return nil, err
		}
		out := []VhostView{}
		for _, sv := range vhosts {
			v, err := vhostView(ctx, store, sv)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}})

	r.Register(agent.Op{Name: "vhost.get", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[VhostIDArgs](c)
		if err != nil {
			return nil, err
		}
		sv, err := loadVhost(ctx, store, c.Actor, args.VhostID)
		if err != nil {
			return nil, err
		}
		view, err := vhostView(ctx, store, sv)
		if err != nil {
			return nil, err
		}
		d := VhostDetail{VhostView: view, Databases: []string{}, DBUsers: []DBUserView{}}
		cert, err := store.GetCert(ctx, sv.N)
		if err != nil {
			return nil, err
		}
		d.Cert = CertStatus{Source: cert.Source}
		if !cert.NotAfter.IsZero() {
			d.Cert.NotAfter = &cert.NotAfter
		}
		if dbs, err := store.ListDatabases(ctx, sv.N); err != nil {
			return nil, err
		} else if dbs != nil {
			d.Databases = dbs
		}
		users, err := store.ListDBUsers(ctx, sv.N)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			d.DBUsers = append(d.DBUsers, DBUserView{Name: u.Name, Grants: u.Grants})
		}
		acct, err := store.AccessAccountOf(ctx, sv.N)
		switch {
		case err == nil:
			keys, err := store.ListSSHKeys(ctx, acct.Name)
			if err != nil {
				return nil, err
			}
			av := &AccessView{Account: acct.Name, Keys: []KeyView{}}
			for _, k := range keys {
				av.Keys = append(av.Keys, KeyView{Fingerprint: k.Fingerprint, PublicKey: k.PublicKey})
			}
			d.Access = av
		case !errors.Is(err, state.ErrNotFound):
			return nil, err
		}
		return d, nil
	}})

	r.Register(agent.Op{Name: "php.version.list", Class: agent.ClassOwner, Handler: func(ctx context.Context, _ *agent.Call) (any, error) {
		v, err := store.ListPHPVersions(ctx)
		if v == nil {
			v = []string{}
		}
		return v, err
	}})

	r.Register(agent.Op{Name: "owner.get", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[OwnerIDArgs](c)
		if err != nil {
			return nil, err
		}
		if c.Actor.Role == api.RoleOwner && args.OwnerID != c.Actor.OwnerID {
			return nil, api.Errorf(api.CodeNotFound, "owner %d not found", args.OwnerID)
		}
		return ownerView(ctx, store, args.OwnerID)
	}})

	r.Register(agent.Op{Name: "owner.list", Class: agent.ClassAdmin, Handler: func(ctx context.Context, _ *agent.Call) (any, error) {
		owners, err := store.ListOwners(ctx)
		if err != nil {
			return nil, err
		}
		out := []OwnerView{}
		for _, o := range owners {
			v, err := ownerView(ctx, store, o.ID)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}})

	r.Register(agent.Op{Name: "audit.list", Class: agent.ClassAdmin, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[AuditListArgs](c)
		if err != nil {
			return nil, err
		}
		limit := args.Limit
		if limit <= 0 || limit > maxEventsPage {
			limit = defaultEventsPg
		}
		entries, err := store.ListAudit(ctx, args.Before, limit)
		if entries == nil {
			entries = []state.AuditEntry{}
		}
		return entries, err
	}})

	r.Register(agent.Op{Name: "vhost.update", Class: agent.ClassOwner, Long: true, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[VhostUpdateArgs](c)
		if err != nil {
			return nil, err
		}
		return VhostResult{VhostID: args.VhostID}, updateAliases(ctx, store, h, c.Actor, args)
	}})
}

func ownerView(ctx context.Context, store *state.Store, id int64) (OwnerView, error) {
	o, err := store.GetOwner(ctx, id)
	if err != nil {
		return OwnerView{}, err
	}
	l, err := store.GetLimits(ctx, id)
	if err != nil {
		return OwnerView{}, err
	}
	return OwnerView{ID: o.ID, Name: o.Name, CreatedAt: o.CreatedAt, Limits: limitsView(l)}, nil
}

// updateAliases replaces a vhost's alias domains and re-renders its front vhost; mod_md then
// requests a certificate covering the new names.
func updateAliases(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args VhostUpdateArgs) error {
	sv, err := loadVhost(ctx, store, actor, args.VhostID)
	if err != nil {
		return err
	}
	sv, err = lockedVhost(ctx, store, h, sv.N)
	if err != nil {
		return err
	}
	defer h.mu.Unlock()
	if sv.Status != state.VhostActive && sv.Status != state.VhostSuspended {
		return api.Errorf(api.CodeConflict, "vhost %s is %s", sv.ID, sv.Status)
	}
	old, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return err
	}
	primary, aliases, err := canonicalDomains(old.Primary(), args.Aliases)
	if err != nil {
		return err
	}
	limits, err := store.GetLimits(ctx, sv.OwnerID)
	if err != nil {
		return err
	}
	v, _, err := renderInputs(sv, primary, aliases, limits)
	if err != nil {
		return err
	}
	if err := store.SetAliases(ctx, sv.N, aliases); err != nil {
		if errors.Is(err, state.ErrConflict) {
			return api.Errorf(api.CodeConflict, "a domain is already in use")
		}
		return err
	}
	opts, err := frontOptions(ctx, store, sv.N, sv.Status == state.VhostSuspended)
	if err != nil {
		return err
	}
	undo := &rollback{h: h}
	if err := applyFront(ctx, h, undo, v, opts); err != nil {
		if rerr := store.SetAliases(ctx, sv.N, old.Aliases()); rerr != nil {
			h.logger().Error("restoring aliases failed", "err", rerr)
		}
		return err
	}
	return nil
}
