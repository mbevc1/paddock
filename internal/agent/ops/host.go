package ops

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/platform"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/system"
)

// Programs the operations run. Paths are the same on every supported release.
const (
	systemctl       = "/usr/bin/systemctl"
	systemdTmpfiles = "/usr/bin/systemd-tmpfiles"
	setpriv         = "/usr/bin/setpriv"
	tar             = "/usr/bin/tar"
	groupadd        = "/usr/sbin/groupadd"
	groupdel        = "/usr/sbin/groupdel"
	useradd         = "/usr/sbin/useradd"
	userdel         = "/usr/sbin/userdel"
	xfsQuota        = "/usr/sbin/xfs_quota"
	restorecon      = "/usr/sbin/restorecon"
	httpd           = "/usr/sbin/httpd"
	apachectl       = "/usr/sbin/apachectl"
)

// Host bundles what operations need to change the machine.
type Host struct {
	Run      system.Runner
	Files    render.Writer
	FS       *HostFS
	Platform platform.Platform
	// Log receives command failures in full; callers see a short message.
	Log *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
	// WaitSocket waits for a socket in a vhost's FPM run directory; nil polls the file system.
	WaitSocket func(ctx context.Context, vhostID, socket string) error
	// MDStatus reports mod_md's managed domains; nil reads md-status from the front Apache.
	MDStatus func(ctx context.Context) ([]MDDomain, error)
	// SSHDir holds sshd's host keys; empty means /etc/ssh.
	SSHDir string

	// mu serializes host changes, so two operations never interleave edits and reloads of
	// shared services such as the front Apache.
	mu sync.Mutex
	// activated holds the renewal each managed domain last had activated; guarded by mu.
	activated map[string]string
}

func (h *Host) now() time.Time {
	if h.Now == nil {
		return time.Now()
	}
	return h.Now()
}

const socketTimeout = 15 * time.Second

// waitSocket waits for the FPM socket of the vhost's PHP version.
func (h *Host) waitSocket(ctx context.Context, v render.Vhost) error {
	if h.WaitSocket != nil {
		return h.WaitSocket(ctx, v.ID(), v.FPMSocketName())
	}
	ctx, cancel := context.WithTimeout(ctx, socketTimeout)
	defer cancel()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if ok, err := h.FS.Exists(BaseFPMRun, v.ID()+"/"+v.FPMSocketName()); err != nil || ok {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("FPM socket did not appear")
		case <-tick.C:
		}
	}
}

// exitCode returns the exit code of a command that ran and failed, or -1.
func exitCode(err error) int {
	var exitErr *system.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode
	}
	return -1
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
