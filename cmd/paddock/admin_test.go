package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/web/store"
)

type chownLog []string

func testAdminEnv(t *testing.T) (adminEnv, *bytes.Buffer, *chownLog) {
	t.Helper()
	out := &bytes.Buffer{}
	log := &chownLog{}
	return adminEnv{
		webDir:  t.TempDir(),
		socket:  filepath.Join(t.TempDir(), "missing.sock"),
		out:     out,
		webUser: func() (int, int, error) { return os.Getuid(), os.Getgid(), nil },
		chown: func(p string, _, _ int) error {
			*log = append(*log, filepath.Base(p))
			return nil
		},
	}, out, log
}

func TestResetPasswordEndsSessions(t *testing.T) {
	ctx := context.Background()
	env, out, chowns := testAdminEnv(t)
	s, err := store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("violet sparrow ledger")
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser(ctx, "alice", store.RoleOwner, 3, hash)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, tok := range []string{"a", "b"} {
		if err := s.CreateSession(ctx, store.Session{TokenHash: tok, UserID: u.ID, CreatedAt: now, LastSeen: now, AuthAt: now, CSRFToken: "c"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if err := env.resetPassword(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`shown only now: (\S+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("output = %q", out.String())
	}
	s, err = store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, _ := s.GetUser(ctx, u.ID)
	if !got.MustChangePassword {
		t.Error("a reset password does not have to be changed at the next sign-in")
	}
	if ok, _, _ := auth.VerifyPassword(m[1], got.PasswordHash); !ok {
		t.Error("printed password does not work")
	}
	for _, tok := range []string{"a", "b"} {
		if _, err := s.GetSession(ctx, tok); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("session %s survived the reset", tok)
		}
	}
	if len(*chowns) == 0 || (*chowns)[0] != "web.db" {
		t.Errorf("web.db not handed back to the web user: %v", *chowns)
	}
	if err := env.resetPassword(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
}

func TestLoginTOTPOffAndOn(t *testing.T) {
	ctx := context.Background()
	env, out, _ := testAdminEnv(t)
	s, err := store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.CreateUser(ctx, "root-admin", store.RoleAdmin, 0, "hash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "alice", store.RoleOwner, 3, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	loginTOTP := func() bool {
		t.Helper()
		s, err := store.Open(ctx, filepath.Join(env.webDir, "web.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		u, err := s.GetUser(ctx, admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		return u.AdminLoginTOTP
	}

	if err := env.setLoginTOTP(ctx, "root-admin", false); err != nil {
		t.Fatal(err)
	}
	if loginTOTP() {
		t.Error("login-totp-off left login TOTP on")
	}
	now := time.Now()
	s, err = store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, store.Session{TokenHash: "a", UserID: admin.ID, CreatedAt: now, LastSeen: now, AuthAt: now, CSRFToken: "c"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := env.setLoginTOTP(ctx, "root-admin", true); err != nil {
		t.Fatal(err)
	}
	if !loginTOTP() {
		t.Error("login-totp-on left login TOTP off")
	}
	s, err = store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetSession(ctx, "a"); !errors.Is(err, store.ErrNotFound) {
		t.Error("a session opened without TOTP survived login-totp-on")
	}
	if !strings.Contains(out.String(), "root-admin") {
		t.Errorf("output = %q", out.String())
	}
	if err := env.setLoginTOTP(ctx, "alice", false); err == nil || !strings.Contains(err.Error(), "not an admin") {
		t.Errorf("owner: %v", err)
	}
}

func TestUnlockChecksBeforeCallingTheAgent(t *testing.T) {
	ctx := context.Background()
	env, _, _ := testAdminEnv(t)
	s, err := store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "alice", store.RoleOwner, 3, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, -time.Hour, 25 * time.Hour} {
		if err := env.unlock(ctx, "alice", d); err == nil || !strings.Contains(err.Error(), "-for") {
			t.Errorf("unlock -for %v: %v", d, err)
		}
	}
	if err := env.unlock(ctx, "alice", time.Hour); err == nil || !strings.Contains(err.Error(), "not an admin") {
		t.Errorf("unlock an owner: %v", err)
	}
	if err := env.lock(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("lock an unknown user: %v", err)
	}
}

func TestRemoveAdminChecks(t *testing.T) {
	ctx := context.Background()
	env, _, _ := testAdminEnv(t)
	s, err := store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "alice", store.RoleOwner, 3, "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "ops", store.RoleAdmin, 0, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := env.remove(ctx, "alice"); err == nil || !strings.Contains(err.Error(), "not an admin") {
		t.Errorf("remove an owner: %v", err)
	}
	if err := env.remove(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("remove an unknown user: %v", err)
	}
	// The agent decides first: without it, the panel user stays.
	if err := env.remove(ctx, "ops"); err == nil {
		t.Fatal("remove succeeded without an agent")
	}
	s, err = store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetUserByName(ctx, "ops"); err != nil {
		t.Errorf("panel user removed although the agent was not reached: %v", err)
	}
}

func TestDisableAdminChecks(t *testing.T) {
	ctx := context.Background()
	env, _, _ := testAdminEnv(t)
	s, err := store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "alice", store.RoleOwner, 3, "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "ops", store.RoleAdmin, 0, "hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, disabled := range []bool{true, false} {
		if err := env.setDisabled(ctx, "alice", disabled); err == nil || !strings.Contains(err.Error(), "not an admin") {
			t.Errorf("disabled=%v on an owner: %v", disabled, err)
		}
		if err := env.setDisabled(ctx, "nobody", disabled); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("disabled=%v on an unknown user: %v", disabled, err)
		}
	}
	if err := env.setDisabled(ctx, "ops", true); err == nil {
		t.Fatal("disable succeeded without an agent")
	}
	s, err = store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if u, err := s.GetUserByName(ctx, "ops"); err != nil || u.Disabled {
		t.Errorf("panel user disabled although the agent was not reached: %+v, %v", u, err)
	}
}

func TestAdminAddRollsBackWithoutAgent(t *testing.T) {
	ctx := context.Background()
	env, _, _ := testAdminEnv(t)
	if err := env.add(ctx, "ops"); err == nil {
		t.Fatal("add succeeded without an agent")
	}
	s, err := store.Open(ctx, filepath.Join(env.webDir, "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetUserByName(ctx, "ops"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("web.db user left after the agent refused: %v", err)
	}
}
