package ops

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

func (r *reconciler) write(f render.File) (*render.Change, error) {
	c, err := r.h.Files.Write(f)
	if err != nil {
		return nil, err
	}
	if c.Changed() {
		r.changed = append(r.changed, c)
		r.res.Changed = append(r.res.Changed, f.Path)
	}
	return c, nil
}

// unitRefresh is how a running vhost picks up rewritten files: a changed config is checked
// and reloaded gracefully, so requests in flight finish; a changed unit or drop-in needs a
// restart. A nil config change means the file is unchanged.
type unitRefresh struct {
	httpdConf, fpmConf       *render.Change
	restartHTTPD, restartFPM bool
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
	fpmUnitChanged := map[string]bool{}
	for _, ver := range versions {
		p, err := render.NewPHP(ver)
		if err != nil {
			return res, err
		}
		unit, err := render.FPMUnit(p)
		if err != nil {
			return res, err
		}
		c, err := rc.write(unit)
		if err != nil {
			fail("writing "+unit.Path, err)
			continue
		}
		fpmUnitChanged[ver] = c.Changed()
	}

	vhosts, err := store.ListVhosts(ctx, 0)
	if err != nil {
		return res, err
	}
	type plan struct {
		sv      state.Vhost
		v       render.Vhost
		refresh unitRefresh
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
		v, refresh, err := reconcileVhostFiles(ctx, store, rc, sv)
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
		refresh.restartFPM = refresh.restartFPM || fpmUnitChanged[sv.PHPVersion]
		plans = append(plans, plan{sv: sv, v: v, refresh: refresh})
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
		if err := reconcileUnits(ctx, h, p.sv, p.v, p.refresh); err != nil {
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

// reconcileVhostFiles restores a vhost's directories and files, and reports what its running
// units must do to pick them up.
func reconcileVhostFiles(ctx context.Context, store *state.Store, rc *reconciler, sv state.Vhost) (render.Vhost, unitRefresh, error) {
	h := rc.h
	limits, err := store.GetLimits(ctx, sv.OwnerID)
	if err != nil {
		return render.Vhost{}, unitRefresh{}, err
	}
	v, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return render.Vhost{}, unitRefresh{}, err
	}
	l, err := render.NewLimits(sv.OwnerID, limits.MemoryMaxMB, limits.CPUQuotaPct, limits.TasksMax)
	if err != nil {
		return render.Vhost{}, unitRefresh{}, err
	}

	if err := h.FS.Mkdir(BaseWWW, sv.ID, 0o700, sv.UID, sv.UID); err != nil {
		return v, unitRefresh{}, err
	}
	for _, d := range vhostSubdirs {
		if err := h.FS.Mkdir(BaseWWW, sv.ID+"/"+d.name, d.mode, sv.UID, sv.UID); err != nil {
			return v, unitRefresh{}, err
		}
	}
	for _, rel := range []string{sv.ID, sv.ID + "/site"} {
		if err := h.FS.Mkdir(BaseJail, rel, 0o755, 0, 0); err != nil {
			return v, unitRefresh{}, err
		}
	}

	files, err := vhostFiles(v, l)
	if err != nil {
		return v, unitRefresh{}, err
	}
	var ref unitRefresh
	for _, f := range files {
		c, err := rc.write(f)
		if err != nil {
			return v, unitRefresh{}, err
		}
		if !c.Changed() {
			continue
		}
		switch f.Path {
		case "/etc/paddock/httpd/" + sv.ID + ".conf":
			ref.httpdConf = c
		case "/etc/paddock/fpm/" + sv.ID + ".conf":
			ref.fpmConf = c
		case dropInPath(v.HTTPDUnit()):
			ref.restartHTTPD = true
		case dropInPath(v.FPMUnit()):
			ref.restartFPM = true
		}
	}

	acct, err := store.AccessAccountOf(ctx, sv.N)
	if errors.Is(err, state.ErrNotFound) {
		return v, ref, nil
	}
	if err != nil {
		return v, ref, err
	}
	keys, err := store.ListSSHKeys(ctx, acct.Name)
	if err != nil {
		return v, ref, err
	}
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = k.PublicKey
	}
	ak, err := render.AuthorizedKeys(v, lines)
	if err != nil {
		return v, ref, err
	}
	if _, err := rc.write(ak); err != nil {
		return v, ref, err
	}
	return v, ref, nil
}

func dropInPath(unit string) string { return "/etc/systemd/system/" + unit + ".d/10-sandbox.conf" }

// reconcileUnits brings a vhost's units to the state its status calls for. A rewritten config
// that fails its check is restored, so the running unit keeps serving the previous one.
func reconcileUnits(ctx context.Context, h *Host, sv state.Vhost, v render.Vhost, ref unitRefresh) error {
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
	var problems []error
	if ref.fpmConf != nil {
		fpm, err := h.Platform.PHPFPMBinary(sv.PHPVersion)
		if err != nil {
			return err
		}
		uid := strconv.Itoa(sv.UID)
		// php-fpm -t refuses to test a pool without a user when run as root.
		if err := h.run(ctx, setpriv, "--reuid="+uid, "--regid="+uid, "--clear-groups", "--",
			fpm, "-t", "--fpm-config", "/etc/paddock/fpm/"+sv.ID+".conf"); err != nil {
			problems = append(problems, restoreConfig(h, ref.fpmConf, "checking the FPM config of "+sv.ID, err))
			ref.fpmConf = nil
		}
	}
	if ref.httpdConf != nil {
		if err := h.run(ctx, httpd, "-t", "-f", "/etc/paddock/httpd/"+sv.ID+".conf"); err != nil {
			problems = append(problems, restoreConfig(h, ref.httpdConf, "checking the backend config of "+sv.ID, err))
			ref.httpdConf = nil
		}
	}
	for _, u := range []struct {
		unit    string
		conf    *render.Change
		restart bool
	}{
		{v.FPMUnit(), ref.fpmConf, ref.restartFPM},
		{v.HTTPDUnit(), ref.httpdConf, ref.restartHTTPD},
	} {
		if err := h.run(ctx, systemctl, "enable", "--now", u.unit); err != nil {
			return errors.Join(append(problems, err)...)
		}
		var err error
		switch {
		case u.restart:
			err = h.run(ctx, systemctl, "restart", u.unit)
		case u.conf != nil:
			err = h.run(ctx, systemctl, "reload", u.unit)
		}
		if err != nil {
			return errors.Join(append(problems, err)...)
		}
	}
	return errors.Join(problems...)
}

// restoreConfig puts back a config that failed its check and returns the check's error.
func restoreConfig(h *Host, c *render.Change, what string, err error) error {
	if rerr := c.Restore(); rerr != nil {
		h.logger().Error("restoring a config that failed its check failed", "err", rerr)
	}
	return h.applyFailed(what, err)
}

// ReconcileOnVersionChange reconciles once per agent version, so files a new release renders
// differently reach every vhost after an upgrade. Problems become an event for admins; a
// reconcile that stops early is retried at the next start.
func ReconcileOnVersionChange(ctx context.Context, store *state.Store, h *Host, version string) error {
	last, err := store.ReconciledVersion(ctx)
	if err != nil || last == version {
		return err
	}
	res, err := Reconcile(ctx, store, h)
	if err != nil {
		msg := fmt.Sprintf("Reconciling vhosts for version %s stopped: %v. The agent retries at its next start.", version, err)
		if _, eerr := store.AppendEvent(ctx, state.Event{Kind: state.EventApplyFailed, Message: msg}); eerr != nil {
			return errors.Join(err, eerr)
		}
		return err
	}
	if len(res.Errors) > 0 {
		msg := fmt.Sprintf("Reconciling vhosts for version %s left %d problems: %s", version, len(res.Errors), strings.Join(res.Errors, "; "))
		if _, err := store.AppendEvent(ctx, state.Event{Kind: state.EventApplyFailed, Message: msg}); err != nil {
			return err
		}
	}
	h.logger().Info("reconciled for a new version", "version", version, "previous", last,
		"vhosts", res.Vhosts, "changed", len(res.Changed), "problems", len(res.Errors))
	return store.SetReconciledVersion(ctx, version)
}
