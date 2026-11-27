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

// VhostPHPSettingsArgs are the arguments of vhost.php.settings.
type VhostPHPSettingsArgs struct {
	VhostID       string `json:"vhost_id"`
	MemoryLimitMB int    `json:"memory_limit_mb"`
	UploadMaxMB   int    `json:"upload_max_mb"`
	MaxExecutionS int    `json:"max_execution_s"`
}

// PHPSettingsView is a vhost's PHP limits as its pool applies them; MemoryCapMB is the most
// the memory limit may be set to.
type PHPSettingsView struct {
	MemoryLimitMB int `json:"memory_limit_mb"`
	UploadMaxMB   int `json:"upload_max_mb"`
	MaxExecutionS int `json:"max_execution_s"`
	MemoryCapMB   int `json:"memory_cap_mb"`
}

// phpMemoryCap is the most a vhost's PHP memory limit may be: the owner's memory limit, but
// never below PHP's smallest accepted limit.
func phpMemoryCap(l state.Limits) int { return max(l.MemoryMaxMB, validate.MinPHPMemoryMB) }

func phpSettingsView(sv state.Vhost, l state.Limits) PHPSettingsView {
	memCap := phpMemoryCap(l)
	return PHPSettingsView{MemoryLimitMB: min(sv.PHP.MemoryLimitMB, memCap), UploadMaxMB: sv.PHP.UploadMaxMB,
		MaxExecutionS: sv.PHP.MaxExecutionS, MemoryCapMB: memCap}
}

func registerPHPSettings(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "vhost.php.settings", Class: agent.ClassOwner, Long: true, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[VhostPHPSettingsArgs](c)
		if err != nil {
			return nil, err
		}
		return VhostResult{VhostID: args.VhostID}, setPHPSettings(ctx, store, h, c.Actor, args)
	}})
}

// setPHPSettings rewrites the vhost's FPM pool with new PHP limits, checks it, and reloads a
// running master, which lets requests in flight finish. A failure restores the old pool.
func setPHPSettings(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args VhostPHPSettingsArgs) error {
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
	limits, err := store.GetLimits(ctx, sv.OwnerID)
	if err != nil {
		return err
	}
	settings := state.PHPSettings{MemoryLimitMB: args.MemoryLimitMB, UploadMaxMB: args.UploadMaxMB, MaxExecutionS: args.MaxExecutionS}
	if err := validate.PHPLimits(settings.MemoryLimitMB, settings.UploadMaxMB, settings.MaxExecutionS, phpMemoryCap(limits)); err != nil {
		return invalidArg(err)
	}
	next := sv
	next.PHP = settings
	v, err := renderedVhost(ctx, store, next)
	if err != nil {
		return err
	}
	fpm, err := h.Platform.PHPFPMBinary(sv.PHPVersion)
	if err != nil {
		return err
	}
	f, err := render.FPM(v)
	if err != nil {
		return err
	}
	conf, err := h.Files.Write(f)
	if err != nil {
		return h.applyFailed("writing "+f.Path, err)
	}
	running := sv.Status == state.VhostActive
	restore := func(err error) error {
		if rerr := conf.Restore(); rerr != nil {
			h.logger().Error("restoring the FPM config failed", "vhost", sv.ID, "err", rerr)
		} else if running {
			if rerr := h.run(ctx, systemctl, "reload", v.FPMUnit()); rerr != nil {
				h.logger().Error("reloading the restored FPM config failed", "vhost", sv.ID, "err", rerr)
			}
		}
		return err
	}
	uid := strconv.Itoa(sv.UID)
	if err := h.run(ctx, setpriv, "--reuid="+uid, "--regid="+uid, "--clear-groups", "--",
		fpm, "-t", "--fpm-config", "/etc/paddock/fpm/"+sv.ID+".conf"); err != nil {
		if rerr := conf.Restore(); rerr != nil {
			h.logger().Error("restoring the FPM config failed", "vhost", sv.ID, "err", rerr)
		}
		return h.applyFailed("checking the FPM config", err)
	}
	if running {
		if err := h.run(ctx, systemctl, "reload", v.FPMUnit()); err != nil {
			return restore(h.applyFailed("reloading "+v.FPMUnit(), err))
		}
	}
	if err := store.SetVhostPHPSettings(ctx, sv.N, settings); err != nil {
		return restore(err)
	}
	return nil
}
