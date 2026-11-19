package ops

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
)

// ReconcileResult reports what a reconcile changed and what it could not fix.
type ReconcileResult struct {
	Vhosts  int      `json:"vhosts"`
	Changed []string `json:"changed"`
	Errors  []string `json:"errors"`
}

// registerReconcile adds reconcile.all for admins, run as a job, and reconcile.run for the
// root CLI (paddock reconcile -all), which waits for the answer on its connection.
func registerReconcile(r *agent.Registry, store *state.Store, h *Host) {
	handler := func(ctx context.Context, _ *agent.Call) (any, error) {
		res, err := Reconcile(ctx, store, h)
		if err != nil {
			return nil, err
		}
		if len(res.Errors) > 0 {
			return nil, api.Errorf(api.CodeApplyFailed, "reconcile left %d problems: %s", len(res.Errors), strings.Join(res.Errors, "; "))
		}
		return res, nil
	}
	r.Register(agent.Op{Name: "reconcile.all", Class: agent.ClassAdmin, Long: true, Handler: handler})
	r.Register(agent.Op{Name: "reconcile.run", Class: agent.ClassRoot, Handler: handler})
}

// reconciler collects one reconcile's file changes.
type reconciler struct {
	h       *Host
	res     *ReconcileResult
	changed []*render.Change
}

func (r *reconciler) write(f render.File) (bool, error) {
	c, err := r.h.Files.Write(f)
	if err != nil {
		return false, err
	}
	if c.Changed() {
		r.changed = append(r.changed, c)
		r.res.Changed = append(r.res.Changed, f.Path)
	}
	return c.Changed(), nil
}

// Reconcile re-renders and re-applies everything in state.db. It repairs files,
// directories, and unit states; it does not recreate Linux users or databases, which it
// reports instead. A vhost that cannot be repaired does not stop the others.
func Reconcile(ctx context.Context, store *state.Store, h *Host) (ReconcileResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	res := ReconcileResult{Changed: []string{}, Errors: []string{}}
	rc := &reconciler{h: h, res: &res}
	fail := func(what string, err error) {
		h.logger().Error("reconcile: "+what, "err", err)
		res.Errors = append(res.Errors, what)
	}

	versions, err := store.ListPHPVersions(ctx)
	if err != nil {
		return res, err
	}
	for _, ver := range versions {
		p, err := render.NewPHP(ver)
		if err != nil {
			return res, err
		}
		unit, err := render.FPMUnit(p)
		if err != nil {
			return res, err
		}
		if _, err := rc.write(unit); err != nil {
			fail("writing "+unit.Path, err)
		}
	}

	vhosts, err := store.ListVhosts(ctx, 0)
	if err != nil {
		return res, err
	}
	type plan struct {
		sv      state.Vhost
		v       render.Vhost
		restart bool
	}
	var plans []plan
	frontStart := 0
	var frontChanges []*render.Change
	for _, sv := range vhosts {
		if sv.Status != state.VhostActive && sv.Status != state.VhostSuspended {
			fail(fmt.Sprintf("vhost %s is %s; resolve it before reconciling", sv.ID, sv.Status), errors.New(string(sv.Status)))
			continue
		}
		res.Vhosts++
		v, restart, err := reconcileVhostFiles(ctx, store, rc, sv)
		if err != nil {
			fail("vhost "+sv.ID, err)
			continue
		}
		frontStart = len(rc.changed)
		opts, err := frontOptions(ctx, store, sv.N, sv.Status == state.VhostSuspended)
		if err != nil {
			fail("vhost "+sv.ID, err)
			continue
		}
		front, err := render.Front(v, opts)
		if err != nil {
			fail("vhost "+sv.ID, err)
			continue
		}
		if _, err := rc.write(front); err != nil {
			fail("writing "+front.Path, err)
			continue
		}
		frontChanges = append(frontChanges, rc.changed[frontStart:]...)
		plans = append(plans, plan{sv: sv, v: v, restart: restart})
	}

	if len(rc.changed) > 0 {
		if err := h.run(ctx, systemctl, "daemon-reload"); err != nil {
			return res, h.applyFailed("reloading systemd", err)
		}
	}
	if len(plans) > 0 {
		argv := []string{systemdTmpfiles, "--create"}
		for _, p := range plans {
			argv = append(argv, "/etc/tmpfiles.d/paddock-"+p.sv.ID+".conf")
		}
		if err := h.run(ctx, argv...); err != nil {
			fail("creating FPM socket directories", err)
		}
	}

	for _, p := range plans {
		if err := reconcileUnits(ctx, h, p.sv, p.v, p.restart); err != nil {
			fail("units of "+p.sv.ID, err)
		}
	}

	if len(frontChanges) > 0 {
		if err := h.run(ctx, apachectl, "configtest"); err != nil {
			for i := len(frontChanges) - 1; i >= 0; i-- {
				if rerr := frontChanges[i].Restore(); rerr != nil {
					h.logger().Error("restoring a front config failed", "err", rerr)
				}
			}
			fail("front config failed apachectl configtest; front changes were restored", err)
		} else if err := h.run(ctx, systemctl, "reload", "httpd.service"); err != nil {
			fail("reloading the front Apache", err)
		}
	}
	return res, nil
}

// reconcileVhostFiles restores a vhost's directories and files. restart reports a changed
// backend or FPM config, which running units must pick up.
func reconcileVhostFiles(ctx context.Context, store *state.Store, rc *reconciler, sv state.Vhost) (render.Vhost, bool, error) {
	h := rc.h
	limits, err := store.GetLimits(ctx, sv.OwnerID)
	if err != nil {
		return render.Vhost{}, false, err
	}
	v, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return render.Vhost{}, false, err
	}
	l, err := render.NewLimits(sv.OwnerID, limits.MemoryMaxMB, limits.CPUQuotaPct, limits.TasksMax)
	if err != nil {
		return render.Vhost{}, false, err
	}

	if err := h.FS.Mkdir(BaseWWW, sv.ID, 0o700, sv.UID, sv.UID); err != nil {
		return v, false, err
	}
	for _, d := range vhostSubdirs {
		if err := h.FS.Mkdir(BaseWWW, sv.ID+"/"+d.name, d.mode, sv.UID, sv.UID); err != nil {
			return v, false, err
		}
	}
	for _, rel := range []string{sv.ID, sv.ID + "/site"} {
		if err := h.FS.Mkdir(BaseJail, rel, 0o755, 0, 0); err != nil {
			return v, false, err
		}
	}

	files, err := vhostFiles(v, l)
	if err != nil {
		return v, false, err
	}
	restartOn := []string{"/etc/paddock/httpd/" + sv.ID + ".conf", "/etc/paddock/fpm/" + sv.ID + ".conf"}
	restart := false
	for _, f := range files {
		changed, err := rc.write(f)
		if err != nil {
			return v, false, err
		}
		restart = restart || changed && (slices.Contains(restartOn, f.Path) || strings.HasSuffix(f.Path, "/10-sandbox.conf"))
	}

	acct, err := store.AccessAccountOf(ctx, sv.N)
	if errors.Is(err, state.ErrNotFound) {
		return v, restart, nil
	}
	if err != nil {
		return v, restart, err
	}
	keys, err := store.ListSSHKeys(ctx, acct.Name)
	if err != nil {
		return v, restart, err
	}
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = k.PublicKey
	}
	ak, err := render.AuthorizedKeys(v, lines)
	if err != nil {
		return v, restart, err
	}
	if _, err := rc.write(ak); err != nil {
		return v, restart, err
	}
	return v, restart, nil
}

// reconcileUnits brings a vhost's units to the state its status calls for.
func reconcileUnits(ctx context.Context, h *Host, sv state.Vhost, v render.Vhost, restart bool) error {
	if err := h.run(ctx, systemctl, "enable", "--now", render.MountUnitName(BaseJail+"/"+sv.ID+"/site")); err != nil {
		return err
	}
	if sv.Status == state.VhostSuspended {
		for _, u := range []string{v.HTTPDUnit(), v.FPMUnit()} {
			if err := h.run(ctx, systemctl, "disable", "--now", u); err != nil {
				return err
			}
		}
		return nil
	}
	for _, u := range []string{v.FPMUnit(), v.HTTPDUnit()} {
		if err := h.run(ctx, systemctl, "enable", "--now", u); err != nil {
			return err
		}
		if restart {
			if err := h.run(ctx, systemctl, "restart", u); err != nil {
				return err
			}
		}
	}
	return nil
}
