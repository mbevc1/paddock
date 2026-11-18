//go:build integration

// Package integration holds tests that change a real AlmaLinux host. Run them as root on a
// disposable VM only: PADDOCK_INTEGRATION=1 make integration.
//
// The tests drive an in-process agent against the host's own state.db, so vhost numbers never
// collide with vhosts the panel created. The installed paddock-agent and paddock-web are stopped
// for the run and started again afterwards, so only one agent changes the host at a time.
package integration

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

const (
	statePath = "/var/lib/paddock/agent/state.db"
	// testAdminID is far above any web.db user ID, so the test admin never matches a panel login.
	testAdminID   = 1 << 40
	testAdminName = "itest"
)

// paddockUnits are stopped while the tests run, web first so it never calls a missing agent.
var paddockUnits = []string{"paddock-web.service", "paddock-agent.service"}

func enabled() bool { return os.Getenv("PADDOCK_INTEGRATION") == "1" && os.Geteuid() == 0 }

func TestMain(m *testing.M) {
	if !enabled() {
		os.Exit(m.Run())
	}
	var stopped []string
	for _, unit := range paddockUnits {
		if _, err := run(context.Background(), "/usr/bin/systemctl", "is-active", "--quiet", unit); err == nil {
			if _, err := run(context.Background(), "/usr/bin/systemctl", "stop", unit); err != nil {
				fmt.Fprintf(os.Stderr, "stopping %s: %v\n", unit, err)
				os.Exit(1)
			}
			stopped = append(stopped, unit)
		}
	}
	code := m.Run()
	shared.close()
	for i := len(stopped) - 1; i >= 0; i-- {
		if _, err := run(context.Background(), "/usr/bin/systemctl", "start", stopped[i]); err != nil {
			fmt.Fprintf(os.Stderr, "starting %s: %v\n", stopped[i], err)
			code = 1
		}
	}
	os.Exit(code)
}

// agentHarness is an in-process agent with the real host behind it, reached over a socketpair
// as root, and an admin whose TOTP secret the harness holds.
type agentHarness struct {
	store  *state.Store
	client *agent.Client
	admin  *api.Actor
	host   *ops.Host
	secret []byte

	mu         sync.Mutex
	lastStep   int64
	windowEnds time.Time

	stop func()
}

type sharedHarness struct {
	once sync.Once
	h    *agentHarness
	err  error
}

func (s *sharedHarness) close() {
	if s.h != nil {
		s.h.stop()
	}
}

var shared sharedHarness

// newAgent returns the shared harness, skipping the test unless integration tests are enabled.
func newAgent(t *testing.T) *agentHarness {
	t.Helper()
	if !enabled() {
		t.Skip("integration tests change the host: run them as root on a test VM with PADDOCK_INTEGRATION=1")
	}
	shared.once.Do(func() { shared.h, shared.err = startAgent() })
	if shared.err != nil {
		t.Fatalf("starting the agent: %v", shared.err)
	}
	return shared.h
}

func startAgent() (*agentHarness, error) {
	ctx := context.Background()
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, err
	}
	plat, err := platform.Detect(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return nil, err
	}
	store, err := state.Open(ctx, statePath)
	if err != nil {
		return nil, err
	}

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
		_ = store.Close()
		return nil, err
	}
	var conns [2]net.Conn
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "agent")
		conns[i], err = net.FileConn(file)
		_ = file.Close()
		if err != nil {
			_ = store.Close()
			return nil, err
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		srv.ServeConn(runCtx, conns[0].(*net.UnixConn))
		close(done)
	}()
	h := &agentHarness{
		store: store, client: agent.NewClient(conns[1]), host: host,
		admin: &api.Actor{UserID: testAdminID, Role: api.RoleAdmin},
		stop: func() {
			cancel()
			_ = conns[1].Close()
			<-done
			_ = store.Close()
		},
	}

	// A rerun finds the admin from the last run and gives it a new secret.
	op, args := "admin.add", any(ops.AdminAddArgs{UserID: testAdminID, Username: testAdminName})
	if _, err := store.GetAdmin(ctx, testAdminID); err == nil {
		op, args = "admin.totp.reset", ops.AdminUserArgs{UserID: testAdminID}
	} else if !errors.Is(err, state.ErrNotFound) {
		h.stop()
		return nil, err
	}
	var enrolled ops.TOTPEnrollment
	if err := h.client.Call(ctx, op, nil, "", args, &enrolled); err != nil {
		h.stop()
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	u, err := url.Parse(enrolled.TOTPURI)
	if err != nil {
		h.stop()
		return nil, err
	}
	if h.secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret")); err != nil {
		h.stop()
		return nil, err
	}
	return h, nil
}

// ensureWindow keeps the admin window open for at least two more minutes, waiting for the next
// TOTP step when this one's code is spent.
func (h *agentHarness) ensureWindow(t *testing.T) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Until(h.windowEnds) > 2*time.Minute {
		return
	}
	step := auth.TOTPStep(time.Now())
	for step <= h.lastStep {
		time.Sleep(time.Second)
		step = auth.TOTPStep(time.Now())
	}
	var verified ops.TOTPVerified
	err := h.client.Call(context.Background(), "admin.totp.verify", nil, "",
		ops.TOTPVerifyArgs{UserID: testAdminID, Code: auth.TOTPCode(h.secret, step)}, &verified)
	if err != nil {
		t.Fatalf("admin.totp.verify: %v", err)
	}
	h.lastStep, h.windowEnds = step, verified.WindowUntil
}

// call runs an operation as the test admin.
func (h *agentHarness) call(t *testing.T, op string, args, out any) error {
	t.Helper()
	h.ensureWindow(t)
	return h.client.Call(context.Background(), op, h.admin, "", args, out)
}

// mustCall runs an operation as the test admin and fails the test on error.
func (h *agentHarness) mustCall(t *testing.T, op string, args, out any) {
	t.Helper()
	if err := h.call(t, op, args, out); err != nil {
		t.Fatalf("%s: %v", op, err)
	}
}

// job starts a long operation and waits for it to finish.
func (h *agentHarness) job(t *testing.T, op string, args any, timeout time.Duration) agent.JobView {
	t.Helper()
	var job api.JobResult
	h.mustCall(t, op, args, &job)
	deadline := time.Now().Add(timeout)
	for {
		var v agent.JobView
		h.mustCall(t, "job.get", map[string]string{"job_id": job.JobID}, &v)
		if v.Status == state.JobSucceeded || v.Status == state.JobFailed {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still %s after %v", op, v.Status, timeout)
		}
		time.Sleep(time.Second)
	}
}

// mustJob runs a long operation and fails the test unless it succeeds.
func (h *agentHarness) mustJob(t *testing.T, op string, args any, timeout time.Duration) agent.JobView {
	t.Helper()
	v := h.job(t, op, args, timeout)
	if v.Status != state.JobSucceeded {
		t.Fatalf("%s: %+v", op, v)
	}
	return v
}

func (h *agentHarness) installPHP(t *testing.T, versions ...string) {
	t.Helper()
	for _, v := range versions {
		h.mustJob(t, "php.version.install", ops.PHPVersionArgs{Version: v}, 15*time.Minute)
	}
}

// newOwner creates an owner and deletes it when the test ends, after the test's vhosts.
func (h *agentHarness) newOwner(t *testing.T, limits ops.LimitsArgs) int64 {
	t.Helper()
	var owner ops.OwnerCreated
	name := "itest " + strings.ReplaceAll(t.Name(), "/", " ") + " " + randomHex(t, 3)
	h.mustCall(t, "owner.create", ops.OwnerCreateArgs{Name: name, Limits: limits}, &owner)
	t.Cleanup(func() {
		if err := h.call(t, "owner.delete", ops.OwnerIDArgs(owner), nil); err != nil {
			t.Errorf("owner.delete %d: %v", owner.OwnerID, err)
		}
	})
	return owner.OwnerID
}

// createVhost creates a vhost that serves the PHP version from index.php, and deletes it when
// the test ends. A missing primary domain gets a random .test name.
func (h *agentHarness) createVhost(t *testing.T, args ops.VhostCreateArgs) (id, domain string) {
	t.Helper()
	if args.PrimaryDomain == "" {
		args.PrimaryDomain = "itest-" + randomHex(t, 4) + ".test"
	}
	domain = args.PrimaryDomain
	job := h.mustJob(t, "vhost.create", args, 5*time.Minute)
	var created struct {
		VhostID string `json:"vhost_id"`
	}
	if err := json.Unmarshal(job.Result, &created); err != nil || created.VhostID == "" {
		t.Fatalf("vhost.create result %s: %v", job.Result, err)
	}
	id = created.VhostID
	t.Cleanup(func() {
		if v := h.job(t, "vhost.delete", ops.VhostDeleteArgs{VhostID: id, Confirm: domain}, 5*time.Minute); v.Status != state.JobSucceeded {
			t.Errorf("vhost.delete %s: %+v", id, v)
		}
	})
	writeAs(t, id, "public/index.php", "<?php echo PHP_MAJOR_VERSION, '.', PHP_MINOR_VERSION;\n", 0o640)
	return id, domain
}

// newVhost installs the PHP versions and creates a vhost on the first, for a new owner.
func newVhost(t *testing.T, h *agentHarness, versions ...string) (id, domain string) {
	t.Helper()
	h.installPHP(t, versions...)
	return h.createVhost(t, ops.VhostCreateArgs{OwnerID: h.newOwner(t, ops.LimitsArgs{}), PHPVersion: versions[0]})
}

func mustVhost(t *testing.T, h *agentHarness, id string) state.Vhost {
	t.Helper()
	vs, err := h.store.ListVhosts(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vhost %s not in state", id)
	return state.Vhost{}
}

func ptrTo[T any](v T) *T { return &v }
