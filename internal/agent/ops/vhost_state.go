package ops

import (
	"context"
	"strconv"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/validate"
)

// VhostPHPSwitchArgs are the arguments of vhost.php.switch.
type VhostPHPSwitchArgs struct {
	VhostID string `json:"vhost_id"`
	Version string `json:"version"`
}

// VhostIDArgs identify one vhost.
type VhostIDArgs struct {
	VhostID string `json:"vhost_id"`
}

// registerVhostState adds vhost.php.switch (owner), vhost.suspend, and vhost.resume (admin).
func registerVhostState(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "vhost.php.switch", Class: agent.ClassOwner, Long: true,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[VhostPHPSwitchArgs](c)
			if err != nil {
				return nil, err
			}
			if err := switchPHP(ctx, store, h, c.Actor, args); err != nil {
				return nil, err
			}
			return VhostResult{VhostID: args.VhostID}, nil
		}})

	for name, fn := range map[string]func(context.Context, *state.Store, *Host, state.Vhost) error{
		"vhost.suspend": suspendVhost,
		"vhost.resume":  resumeVhost,
	} {
		r.Register(agent.Op{Name: name, Class: agent.ClassAdmin, Long: true,
			Handler: func(ctx context.Context, c *agent.Call) (any, error) {
				args, err := agent.DecodeArgs[VhostIDArgs](c)
				if err != nil {
					return nil, err
				}
				sv, err := loadVhost(ctx, store, c.Actor, args.VhostID)
				if err != nil {
					return nil, err
				}
				if err := fn(ctx, store, h, sv); err != nil {
					return nil, err
				}
				return VhostResult(args), nil
			}})
	}
}

// lockedVhost takes the host lock and rereads the vhost, so its status cannot change
// between the check and the work. The caller must unlock.
func lockedVhost(ctx context.Context, store *state.Store, h *Host, n int) (state.Vhost, error) {
	h.mu.Lock()
	sv, err := store.GetVhost(ctx, n)
	if err != nil {
		h.mu.Unlock()
		return state.Vhost{}, err
	}
	return sv, nil
}

// switchPHP moves a vhost to another PHP version per §8: the new FPM starts on the same
// socket path before the old one stops, so requests keep being served.
func switchPHP(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args VhostPHPSwitchArgs) error {
	sv, err := loadVhost(ctx, store, actor, args.VhostID)
	if err != nil {
		return err
	}
	if err := validate.PHPVersion(args.Version); err != nil {
		return api.Errorf(api.CodeInvalidArgument, "%v", err)
	}
	limits, err := store.GetLimits(ctx, sv.OwnerID)
	if err != nil {
		return err
	}
	if err := checkPHPAllowed(ctx, store, limits, args.Version); err != nil {
		return err
	}

	sv, err = lockedVhost(ctx, store, h, sv.N)
	if err != nil {
		return err
	}
	defer h.mu.Unlock()
	if sv.PHPVersion == args.Version {
		return nil
	}
	if sv.Status != state.VhostActive {
		return api.Errorf(api.CodeConflict, "vhost %s is %s; only an active vhost can switch PHP", sv.ID, sv.Status)
	}
	oldV, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return err
	}
	next := sv
	next.PHPVersion = args.Version
	newV, err := renderedVhost(ctx, store, next)
	if err != nil {
		return err
	}
	fpm, err := h.Platform.PHPFPMBinary(args.Version)
	if err != nil {
		return err
	}

	undo := &rollback{h: h}
	fail := func(err error) error {
		undo.run(ctx)
		return err
	}
	step := func(what string, argv ...string) error {
		if err := h.run(ctx, argv...); err != nil {
			return h.applyFailed(what, err)
		}
		return nil
	}

	write := func(f render.File, err error) (*render.Change, error) {
		if err != nil {
			return nil, err
		}
		change, err := h.Files.Write(f)
		if err != nil {
			return nil, h.applyFailed("writing "+f.Path, err)
		}
		return change, nil
	}

	dropIns, err := render.SandboxDropIns(newV)
	if err != nil {
		return err
	}
	dropIn, err := write(dropIns[1], nil)
	if err != nil {
		return err
	}
	undo.add(func(ctx context.Context) error {
		if err := dropIn.Restore(); err != nil {
			return err
		}
		return h.run(ctx, systemctl, "daemon-reload")
	})
	// The running master read its config at start, so rewriting the file leaves it serving.
	fpmConf, err := write(render.FPM(newV))
	if err != nil {
		return fail(err)
	}
	undo.add(func(context.Context) error { return fpmConf.Restore() })
	if err := step("reloading systemd", systemctl, "daemon-reload"); err != nil {
		return fail(err)
	}
	uid := strconv.Itoa(sv.UID)
	if err := step("checking the FPM config", setpriv, "--reuid="+uid, "--regid="+uid, "--clear-groups", "--",
		fpm, "-t", "--fpm-config", "/etc/paddock/fpm/"+sv.ID+".conf"); err != nil {
		return fail(err)
	}
	// A failed enable --now can leave the unit enabled, and a failed stop can leave it half
	// down, so each undo is registered before its command runs.
	undo.add(func(ctx context.Context) error { return h.run(ctx, systemctl, "disable", "--now", newV.FPMUnit()) })
	if err := step("starting "+newV.FPMUnit(), systemctl, "enable", "--now", newV.FPMUnit()); err != nil {
		return fail(err)
	}
	if err := h.waitSocket(ctx, newV); err != nil {
		return fail(h.applyFailed("starting "+newV.FPMUnit(), err))
	}

	// A graceful reload lets requests in flight finish on the old master.
	backend, err := write(render.BackendHTTPD(newV))
	if err != nil {
		return fail(err)
	}
	undo.add(func(ctx context.Context) error {
		if err := backend.Restore(); err != nil {
			return err
		}
		return h.run(ctx, systemctl, "reload", newV.HTTPDUnit())
	})
	if err := step("checking the backend config", httpd, "-t", "-f", "/etc/paddock/httpd/"+sv.ID+".conf"); err != nil {
		return fail(err)
	}
	if err := step("reloading "+newV.HTTPDUnit(), systemctl, "reload", newV.HTTPDUnit()); err != nil {
		return fail(err)
	}

	undo.add(func(ctx context.Context) error { return h.run(ctx, systemctl, "enable", "--now", oldV.FPMUnit()) })
	if err := step("stopping "+oldV.FPMUnit(), systemctl, "disable", "--now", oldV.FPMUnit()); err != nil {
		return fail(err)
	}

	oldDropIns, err := render.SandboxDropIns(oldV)
	if err != nil {
		return fail(err)
	}
	removed, err := h.Files.Remove(oldDropIns[1].Path)
	if err != nil {
		return fail(h.applyFailed("removing "+oldDropIns[1].Path, err))
	}
	undo.add(func(context.Context) error { return removed.Restore() })
	if err := step("reloading systemd", systemctl, "daemon-reload"); err != nil {
		return fail(err)
	}
	if err := store.SetVhostPHP(ctx, sv.N, args.Version); err != nil {
		return fail(err)
	}
	return nil
}

// suspendVhost makes the front answer 503, then stops and disables the vhost's units.
func suspendVhost(ctx context.Context, store *state.Store, h *Host, sv state.Vhost) error {
	sv, err := lockedVhost(ctx, store, h, sv.N)
	if err != nil {
		return err
	}
	defer h.mu.Unlock()
	switch sv.Status {
	case state.VhostSuspended:
		return nil
	case state.VhostActive:
	default:
		return api.Errorf(api.CodeConflict, "vhost %s is %s", sv.ID, sv.Status)
	}
	v, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return err
	}
	opts, err := frontOptions(ctx, store, sv.N, true)
	if err != nil {
		return err
	}
	undo := &rollback{h: h}
	if err := applyFront(ctx, h, undo, v, opts); err != nil {
		return err
	}
	for _, unit := range []string{v.HTTPDUnit(), v.FPMUnit()} {
		undo.add(func(ctx context.Context) error { return h.run(ctx, systemctl, "enable", "--now", unit) })
		if err := h.run(ctx, systemctl, "disable", "--now", unit); err != nil {
			undo.run(ctx)
			return h.applyFailed("stopping "+unit, err)
		}
	}
	if err := store.SetVhostStatus(ctx, sv.N, state.VhostSuspended); err != nil {
		undo.run(ctx)
		return err
	}
	return nil
}

// resumeVhost starts the vhost's units again, then points the front back at the backend.
func resumeVhost(ctx context.Context, store *state.Store, h *Host, sv state.Vhost) error {
	sv, err := lockedVhost(ctx, store, h, sv.N)
	if err != nil {
		return err
	}
	defer h.mu.Unlock()
	switch sv.Status {
	case state.VhostActive:
		return nil
	case state.VhostSuspended:
	default:
		return api.Errorf(api.CodeConflict, "vhost %s is %s", sv.ID, sv.Status)
	}
	v, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return err
	}
	undo := &rollback{h: h}
	// A vhost suspended before PHP versions had their own sockets still has configs naming the
	// old shared one, so both are written again before the units start.
	for _, build := range []func(render.Vhost) (render.File, error){render.FPM, render.BackendHTTPD} {
		f, err := build(v)
		if err != nil {
			undo.run(ctx)
			return err
		}
		change, err := h.Files.Write(f)
		if err != nil {
			undo.run(ctx)
			return h.applyFailed("writing "+f.Path, err)
		}
		undo.add(func(context.Context) error { return change.Restore() })
	}
	undo.add(func(ctx context.Context) error { return h.run(ctx, systemctl, "disable", "--now", v.FPMUnit()) })
	if err := h.run(ctx, systemctl, "enable", "--now", v.FPMUnit()); err != nil {
		undo.run(ctx)
		return h.applyFailed("starting "+v.FPMUnit(), err)
	}
	if err := h.waitSocket(ctx, v); err != nil {
		undo.run(ctx)
		return h.applyFailed("starting "+v.FPMUnit(), err)
	}
	undo.add(func(ctx context.Context) error { return h.run(ctx, systemctl, "disable", "--now", v.HTTPDUnit()) })
	if err := h.run(ctx, systemctl, "enable", "--now", v.HTTPDUnit()); err != nil {
		undo.run(ctx)
		return h.applyFailed("starting "+v.HTTPDUnit(), err)
	}
	opts, err := frontOptions(ctx, store, sv.N, false)
	if err != nil {
		undo.run(ctx)
		return err
	}
	if err := applyFront(ctx, h, undo, v, opts); err != nil {
		undo.run(ctx)
		return err
	}
	if err := store.SetVhostStatus(ctx, sv.N, state.VhostActive); err != nil {
		undo.run(ctx)
		return err
	}
	return nil
}
