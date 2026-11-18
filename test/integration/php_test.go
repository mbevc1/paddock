//go:build integration

// Package integration holds tests that change a real AlmaLinux host. Run them as root on a
// disposable VM only: PADDOCK_INTEGRATION=1 go test -tags integration ./test/integration/...
package integration

import (
	"context"
	"encoding/base32"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/platform"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

// agentHarness runs an in-process agent with the real host behind it and a temporary
// state.db, reached over a socketpair as root.
type agentHarness struct {
	t      *testing.T
	store  *state.Store
	client *agent.Client
	admin  *api.Actor
	secret []byte
	host   *ops.Host
}

func newAgent(t *testing.T) *agentHarness {
	t.Helper()
	if os.Getenv("PADDOCK_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("integration tests change the host: run them as root on a test VM with PADDOCK_INTEGRATION=1")
	}
	ctx := context.Background()
	f, err := os.Open("/etc/os-release")
	if err != nil {
		t.Fatal(err)
	}
	plat, err := platform.Detect(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	gate := &agent.TOTPGate{Store: store}
	srv := &agent.Server{WebUID: 0, Registry: agent.NewRegistry(), Store: store, Gate: gate, Log: log}
	srv.RegisterJobGet()
	ops.RegisterAdmin(srv.Registry, store, gate)
	ops.RegisterOwners(srv.Registry, store)
	host := &ops.Host{Run: system.Exec{}, Files: render.Writer{}, FS: &ops.HostFS{}, Platform: plat, Log: log}
	ops.RegisterPHP(srv.Registry, store, host)
	ops.RegisterVhosts(srv.Registry, store, host)

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) net.Conn {
		file := os.NewFile(uintptr(fd), "agent")
		c, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	server, client := conn(fds[0]).(*net.UnixConn), conn(fds[1])
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		srv.ServeConn(runCtx, server)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		<-done
	})

	h := &agentHarness{t: t, store: store, client: agent.NewClient(client), admin: &api.Actor{UserID: 1, Role: api.RoleAdmin}, host: host}
	var enrolled ops.TOTPEnrollment
	if err := h.client.Call(ctx, "admin.add", nil, "", ops.AdminAddArgs{UserID: 1, Username: "itest"}, &enrolled); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(enrolled.TOTPURI)
	if err != nil {
		t.Fatal(err)
	}
	if h.secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret")); err != nil {
		t.Fatal(err)
	}
	code := auth.TOTPCode(h.secret, auth.TOTPStep(time.Now()))
	if err := h.client.Call(ctx, "admin.totp.verify", nil, "", ops.TOTPVerifyArgs{UserID: 1, Code: code}, nil); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *agentHarness) job(op string, args any, timeout time.Duration) agent.JobView {
	h.t.Helper()
	ctx := context.Background()
	var job api.JobResult
	if err := h.client.Call(ctx, op, h.admin, "", args, &job); err != nil {
		h.t.Fatalf("%s: %v", op, err)
	}
	deadline := time.Now().Add(timeout)
	for {
		var v agent.JobView
		if err := h.client.Call(ctx, "job.get", h.admin, "", map[string]string{"job_id": job.JobID}, &v); err != nil {
			h.t.Fatal(err)
		}
		if v.Status == state.JobSucceeded || v.Status == state.JobFailed {
			return v
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%s still %s after %v", op, v.Status, timeout)
		}
		time.Sleep(time.Second)
	}
}

func TestPHPVersionInstall(t *testing.T) {
	h := newAgent(t)
	const unit = "/etc/systemd/system/paddock-php84-fpm@.service"
	_, err := os.Stat(unit)
	hadUnit := err == nil

	if v := h.job("php.version.install", ops.PHPVersionArgs{Version: "8.4"}, 15*time.Minute); v.Status != state.JobSucceeded {
		t.Fatalf("install: %+v", v)
	}
	if _, err := os.Stat("/opt/remi/php84/root/usr/sbin/php-fpm"); err != nil {
		t.Errorf("php-fpm missing: %v", err)
	}
	if _, err := os.Stat(unit); err != nil {
		t.Errorf("unit missing: %v", err)
	}
	if hadUnit {
		t.Log("PHP 8.4 was present before the test; leaving it installed")
		return
	}
	if v := h.job("php.version.remove", ops.PHPVersionArgs{Version: "8.4"}, 15*time.Minute); v.Status != state.JobSucceeded {
		t.Fatalf("remove: %+v", v)
	}
	if _, err := os.Stat(unit); !os.IsNotExist(err) {
		t.Errorf("unit left after removal: %v", err)
	}
}
