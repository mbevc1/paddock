package ops

import (
	"context"
	"errors"
	"log/slog"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/platform"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/system"
)

const systemctl = "/usr/bin/systemctl"

// Host bundles what operations need to change the machine.
type Host struct {
	Run      system.Runner
	Files    render.Writer
	Platform platform.Platform
	// Log receives command failures in full; callers see a short message.
	Log *slog.Logger
}

func (h *Host) logger() *slog.Logger {
	if h.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return h.Log
}

func (h *Host) run(ctx context.Context, argv ...string) error {
	_, err := h.Run.Run(ctx, argv, system.Opts{})
	return err
}

// applyFailed logs a host failure and returns the caller-facing error.
func (h *Host) applyFailed(what string, err error) error {
	h.logger().Error(what+" failed", "err", err)
	var exitErr *system.ExitError
	if errors.As(err, &exitErr) {
		return api.Errorf(api.CodeApplyFailed, "%s failed: %s exited with code %d", what, exitErr.Program, exitErr.ExitCode)
	}
	return api.Errorf(api.CodeApplyFailed, "%s failed", what)
}

// rollback undoes steps in reverse order and logs, rather than returns, undo failures: the
// caller already reports the original error.
type rollback struct {
	h     *Host
	steps []func(context.Context) error
}

func (r *rollback) add(step func(context.Context) error) { r.steps = append(r.steps, step) }

func (r *rollback) run(ctx context.Context) {
	for i := len(r.steps) - 1; i >= 0; i-- {
		if err := r.steps[i](ctx); err != nil {
			r.h.logger().Error("rollback step failed", "err", err)
		}
	}
}
