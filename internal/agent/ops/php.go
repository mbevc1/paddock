package ops

import (
	"context"
	"errors"
	"slices"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
)

// PHPVersionArgs are the arguments of php.version.install and php.version.remove.
type PHPVersionArgs struct {
	Version string `json:"version"`
}

// PHPVersionResult reports the version an operation acted on.
type PHPVersionResult struct {
	Version string `json:"version"`
}

func phpArgs(c *agent.Call) (render.PHP, error) {
	args, err := agent.DecodeArgs[PHPVersionArgs](c)
	if err != nil {
		return render.PHP{}, err
	}
	p, err := render.NewPHP(args.Version)
	if err != nil {
		return render.PHP{}, api.Errorf(api.CodeInvalidArgument, "version must be 8.2, 8.3, or 8.4")
	}
	return p, nil
}

// RegisterPHP adds php.version.install and php.version.remove. Both run as jobs because
// dnf can take minutes.
func RegisterPHP(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "php.version.install", Class: agent.ClassAdmin, Long: true,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			p, err := phpArgs(c)
			if err != nil {
				return nil, err
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if err := installPHP(ctx, store, h, p); err != nil {
				return nil, err
			}
			return PHPVersionResult{Version: p.Version()}, nil
		}})

	r.Register(agent.Op{Name: "php.version.remove", Class: agent.ClassAdmin, Long: true,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			p, err := phpArgs(c)
			if err != nil {
				return nil, err
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if err := removePHP(ctx, store, h, p); err != nil {
				return nil, err
			}
			return PHPVersionResult{Version: p.Version()}, nil
		}})
}

// installPHP installs the Remi packages, writes the FPM unit template, checks the binary,
// and records the version. Rerunning it repairs a partial install and adds packages the list
// gained since; it then reloads the version's running FPM masters, which load extensions only
// at start. On failure it undoes what it changed, including packages it installed itself,
// except on a version already recorded, whose packages running vhosts may use.
func installPHP(ctx context.Context, store *state.Store, h *Host, p render.PHP) error {
	versions, err := store.ListPHPVersions(ctx)
	if err != nil {
		return err
	}
	recorded := slices.Contains(versions, p.Version())
	pkgs, err := h.Platform.PHPPackages(p.Version())
	if err != nil {
		return err
	}
	fpm, err := h.Platform.PHPFPMBinary(p.Version())
	if err != nil {
		return err
	}
	unit, err := render.FPMUnit(p)
	if err != nil {
		return err
	}
	undo := &rollback{h: h}
	fail := func(what string, err error) error {
		undo.run(ctx)
		return h.applyFailed(what, err)
	}

	added := false
	if err := h.run(ctx, h.Platform.InstalledArgv(pkgs)...); err != nil {
		if err := h.run(ctx, h.Platform.InstallArgv(pkgs)...); err != nil {
			return h.applyFailed("installing PHP "+p.Version(), err)
		}
		added = true
		if !recorded {
			undo.add(func(ctx context.Context) error { return h.run(ctx, h.Platform.RemoveArgv(pkgs)...) })
		}
	}

	change, err := h.Files.Write(unit)
	if err != nil {
		return fail("writing "+p.FPMUnitName(), err)
	}
	undo.add(func(ctx context.Context) error {
		if err := change.Restore(); err != nil {
			return err
		}
		return h.run(ctx, systemctl, "daemon-reload")
	})
	if err := h.run(ctx, systemctl, "daemon-reload"); err != nil {
		return fail("reloading systemd", err)
	}
	if err := h.run(ctx, fpm, "-v"); err != nil {
		return fail("checking "+fpm, err)
	}
	if err := store.AddPHPVersion(ctx, p.Version()); err != nil {
		undo.run(ctx)
		return err
	}
	if added && recorded {
		return reloadPHPMasters(ctx, store, h, p)
	}
	return nil
}

// reloadPHPMasters gracefully reloads the FPM master of every active vhost on the version, so
// it loads newly installed extensions. It tries every master before reporting a failure.
func reloadPHPMasters(ctx context.Context, store *state.Store, h *Host, p render.PHP) error {
	vhosts, err := store.ListVhosts(ctx, 0)
	if err != nil {
		return err
	}
	var failed error
	for _, sv := range vhosts {
		if sv.Status != state.VhostActive || sv.PHPVersion != p.Version() {
			continue
		}
		v, err := renderedVhost(ctx, store, sv)
		if err != nil {
			return err
		}
		if err := h.run(ctx, systemctl, "reload", v.FPMUnit()); err != nil && failed == nil {
			failed = h.applyFailed("reloading "+v.FPMUnit(), err)
		}
	}
	return failed
}

// removePHP forgets the version, then removes its unit template and packages. The state row
// goes first: its foreign key refuses removal while any vhost uses the version, and once it
// is gone no new vhost can pick the version. A version unknown to state.db is still cleaned
// from the host, so a failed removal can be rerun.
func removePHP(ctx context.Context, store *state.Store, h *Host, p render.PHP) error {
	pkgs, err := h.Platform.PHPPackages(p.Version())
	if err != nil {
		return err
	}
	if n, err := store.CountVhostsUsingPHP(ctx, p.Version()); err != nil {
		return err
	} else if n > 0 {
		return api.Errorf(api.CodeConflict, "PHP %s is used by %d vhosts", p.Version(), n)
	}
	err = store.RemovePHPVersion(ctx, p.Version())
	switch {
	case errors.Is(err, state.ErrConflict):
		return api.Errorf(api.CodeConflict, "PHP %s is in use", p.Version())
	case err != nil && !errors.Is(err, state.ErrNotFound):
		return err
	}

	unit, err := render.FPMUnit(p)
	if err != nil {
		return err
	}
	if _, err := h.Files.Remove(unit.Path); err != nil {
		return h.applyFailed("removing "+p.FPMUnitName(), err)
	}
	if err := h.run(ctx, systemctl, "daemon-reload"); err != nil {
		return h.applyFailed("reloading systemd", err)
	}
	if err := h.run(ctx, h.Platform.RemoveArgv(pkgs)...); err != nil {
		return h.applyFailed("removing PHP "+p.Version(), err)
	}
	return nil
}
