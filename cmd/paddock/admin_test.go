package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
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
