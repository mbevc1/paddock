package ops

import (
	"context"
	"encoding/base32"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/platform"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

const webUID = 990

type env struct {
	t     *testing.T
	store *state.Store
	now   time.Time
	reg   *agent.Registry
	gate  *agent.TOTPGate
	run   *system.Fake
	root  string
	host  *Host
	// chowns records ownership changes HostFS made.
	chowns *[]chownCall
	// socketErr is what waiting for an FPM socket returns.
	socketErr error
}

func newEnv(t *testing.T) *env {
	t.Helper()
	store, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	e := &env{t: t, store: store, now: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}
	e.gate = &agent.TOTPGate{Store: store, Now: func() time.Time { return e.now }}
	e.reg = agent.NewRegistry()
	(&agent.Server{Registry: e.reg, Store: store}).RegisterJobGet()
	RegisterAdmin(e.reg, store, e.gate)
	RegisterOwners(e.reg, store)
	plat, err := platform.ForMajor(9)
	if err != nil {
		t.Fatal(err)
	}
	e.run = &system.Fake{}
	hfs, chowns := testFS(t)
	e.root, e.chowns = hfs.Root, chowns
	e.host = &Host{Run: e.run, Files: render.Writer{Root: e.root}, FS: hfs, Platform: plat,
		Now:        func() time.Time { return e.now },
		WaitSocket: func(context.Context, string) error { return e.socketErr }}
	RegisterPHP(e.reg, store, e.host)
	RegisterVhosts(e.reg, store, e.host)
	return e
}

// client connects as a caller with the given UID.
func (e *env) client(uid uint32) *agent.Client {
	e.t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	conn := func(fd int) net.Conn {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			e.t.Fatal(err)
		}
		return c
	}
	server, client := conn(fds[0]).(*net.UnixConn), conn(fds[1])
	srv := &agent.Server{WebUID: webUID, Registry: e.reg, Store: e.store, Gate: e.gate,
		PeerUID: func(*net.UnixConn) (uint32, error) { return uid, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.ServeConn(ctx, server)
		close(done)
	}()
	e.t.Cleanup(func() {
		cancel()
		_ = client.Close()
		<-done
	})
	return agent.NewClient(client)
}

func secretFromURI(t *testing.T, uri string) []byte {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func wantCode(t *testing.T, err error, code api.Code) {
	t.Helper()
	var apiErr *api.Error
	if !errors.As(err, &apiErr) || apiErr.Code != code {
		t.Errorf("err = %v, want %s", err, code)
	}
}

func ownerArgs(name string) OwnerCreateArgs { return OwnerCreateArgs{Name: name} }

func TestAdminTOTPGate(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	root := e.client(0)
	web := e.client(webUID)

	var enrolled TOTPEnrollment
	if err := root.Call(ctx, "admin.add", nil, "", AdminAddArgs{UserID: 1, Username: "admin"}, &enrolled); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enrolled.TOTPURI, "otpauth://totp/Paddock:admin?") {
		t.Errorf("URI = %q", enrolled.TOTPURI)
	}
	secret := secretFromURI(t, enrolled.TOTPURI)
	names := 0
	nextName := func() string {
		names++
		return "owner " + string(rune('a'+names))
	}
	code := auth.TOTPCode(secret, auth.TOTPStep(e.now))
	admin := &api.Actor{UserID: 1, Role: api.RoleAdmin}

	wantCode(t, web.Call(ctx, "admin.add", nil, "", AdminAddArgs{UserID: 2, Username: "sneaky"}, nil), api.CodeForbidden)
	wantCode(t, root.Call(ctx, "admin.add", nil, "", AdminAddArgs{UserID: 1, Username: "admin"}, nil), api.CodeConflict)
	wantCode(t, root.Call(ctx, "admin.add", nil, "", AdminAddArgs{UserID: 3, Username: "Bad Name"}, nil), api.CodeInvalidArgument)

	t.Run("no code and no window", func(t *testing.T) {
		wantCode(t, web.Call(ctx, "owner.create", admin, "", ownerArgs(nextName()), nil), api.CodeTOTPRequired)
	})
	t.Run("wrong code", func(t *testing.T) {
		wantCode(t, web.Call(ctx, "owner.create", admin, "000000", ownerArgs(nextName()), nil), api.CodeTOTPInvalid)
	})
	t.Run("valid code", func(t *testing.T) {
		if err := web.Call(ctx, "owner.create", admin, code, ownerArgs(nextName()), nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("replayed code", func(t *testing.T) {
		wantCode(t, web.Call(ctx, "owner.create", admin, code, ownerArgs(nextName()), nil), api.CodeTOTPInvalid)
	})
	t.Run("open window", func(t *testing.T) {
		e.now = e.now.Add(9 * time.Minute)
		if err := web.Call(ctx, "owner.create", admin, "", ownerArgs(nextName()), nil); err != nil {
			t.Errorf("within the window: %v", err)
		}
	})
	t.Run("expired window", func(t *testing.T) {
		e.now = e.now.Add(2 * time.Minute)
		wantCode(t, web.Call(ctx, "owner.create", admin, "", ownerArgs(nextName()), nil), api.CodeTOTPRequired)
	})
	t.Run("admin only in web.db", func(t *testing.T) {
		fake := &api.Actor{UserID: 42, Role: api.RoleAdmin}
		wantCode(t, web.Call(ctx, "owner.create", fake, "123456", ownerArgs(nextName()), nil), api.CodeForbidden)
		wantCode(t, web.Call(ctx, "owner.create", fake, "", ownerArgs(nextName()), nil), api.CodeForbidden)
	})
	t.Run("owner caller", func(t *testing.T) {
		owner := &api.Actor{UserID: 1, Role: api.RoleOwner, OwnerID: 5}
		next := auth.TOTPCode(secret, auth.TOTPStep(e.now))
		wantCode(t, web.Call(ctx, "owner.create", owner, next, ownerArgs(nextName()), nil), api.CodeForbidden)
	})
	t.Run("gate op opens the window", func(t *testing.T) {
		e.now = e.now.Add(time.Minute)
		var v TOTPVerified
		next := auth.TOTPCode(secret, auth.TOTPStep(e.now))
		if err := web.Call(ctx, "admin.totp.verify", nil, "", TOTPVerifyArgs{UserID: 1, Code: next}, &v); err != nil {
			t.Fatal(err)
		}
		if !v.WindowUntil.Equal(e.now.Add(agent.AdminWindow)) {
			t.Errorf("window until %v", v.WindowUntil)
		}
		if err := web.Call(ctx, "owner.create", admin, "", ownerArgs(nextName()), nil); err != nil {
			t.Errorf("after admin.totp.verify: %v", err)
		}
		wantCode(t, web.Call(ctx, "admin.totp.verify", nil, "", TOTPVerifyArgs{UserID: 1, Code: next}, nil), api.CodeTOTPInvalid)
	})
	t.Run("reset", func(t *testing.T) {
		var again TOTPEnrollment
		wantCode(t, web.Call(ctx, "admin.totp.reset", nil, "", AdminUserArgs{UserID: 1}, nil), api.CodeForbidden)
		if err := root.Call(ctx, "admin.totp.reset", nil, "", AdminUserArgs{UserID: 1}, &again); err != nil {
			t.Fatal(err)
		}
		wantCode(t, root.Call(ctx, "admin.totp.reset", nil, "", AdminUserArgs{UserID: 9}, nil), api.CodeNotFound)
		wantCode(t, web.Call(ctx, "owner.create", admin, "", ownerArgs(nextName()), nil), api.CodeTOTPRequired)
		e.now = e.now.Add(time.Minute)
		old := auth.TOTPCode(secret, auth.TOTPStep(e.now))
		wantCode(t, web.Call(ctx, "owner.create", admin, old, ownerArgs(nextName()), nil), api.CodeTOTPInvalid)
		fresh := auth.TOTPCode(secretFromURI(t, again.TOTPURI), auth.TOTPStep(e.now))
		if err := web.Call(ctx, "owner.create", admin, fresh, ownerArgs(nextName()), nil); err != nil {
			t.Errorf("new secret: %v", err)
		}
	})

	entries, err := e.store.ListAudit(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if strings.Contains(en.Args, code) || strings.Contains(en.Args, "otpauth") {
			t.Errorf("audit entry leaks a secret: %+v", en)
		}
	}
}

func TestRootOpensAndClosesAdminWindow(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	root := e.client(0)
	web := e.client(webUID)
	if err := root.Call(ctx, "admin.add", nil, "", AdminAddArgs{UserID: 1, Username: "admin"}, nil); err != nil {
		t.Fatal(err)
	}
	admin := &api.Actor{UserID: 1, Role: api.RoleAdmin}
	n := 0
	create := func() error {
		n++
		return web.Call(ctx, "owner.create", admin, "", ownerArgs("owner "+string(rune('a'+n))), nil)
	}
	hours := func(h float64) AdminWindowArgs {
		return AdminWindowArgs{UserID: 1, Seconds: int64(h * 3600)}
	}

	wantCode(t, web.Call(ctx, "admin.window.open", nil, "", hours(8), nil), api.CodeForbidden)
	wantCode(t, root.Call(ctx, "admin.window.open", nil, "", hours(24.01), nil), api.CodeInvalidArgument)
	wantCode(t, root.Call(ctx, "admin.window.open", nil, "", hours(0), nil), api.CodeInvalidArgument)
	wantCode(t, root.Call(ctx, "admin.window.open", nil, "", AdminWindowArgs{UserID: 9, Seconds: 60}, nil), api.CodeNotFound)

	var v TOTPVerified
	if err := root.Call(ctx, "admin.window.open", nil, "", hours(8), &v); err != nil {
		t.Fatal(err)
	}
	if !v.WindowUntil.Equal(e.now.Add(8 * time.Hour)) {
		t.Errorf("window until %v", v.WindowUntil)
	}
	e.now = e.now.Add(8*time.Hour - time.Minute)
	if err := create(); err != nil {
		t.Errorf("inside a root-opened window: %v", err)
	}
	e.now = e.now.Add(2 * time.Minute)
	wantCode(t, create(), api.CodeTOTPRequired)

	if err := root.Call(ctx, "admin.window.open", nil, "", hours(1), nil); err != nil {
		t.Fatal(err)
	}
	wantCode(t, web.Call(ctx, "admin.window.close", nil, "", AdminUserArgs{UserID: 1}, nil), api.CodeForbidden)
	if err := root.Call(ctx, "admin.window.close", nil, "", AdminUserArgs{UserID: 1}, nil); err != nil {
		t.Fatal(err)
	}
	wantCode(t, create(), api.CodeTOTPRequired)
}
