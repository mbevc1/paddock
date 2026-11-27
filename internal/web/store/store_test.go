package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "web.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("web.db mode = %v, %v", fi.Mode().Perm(), err)
	}
	again, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = again.Close()
	return s
}

func TestUsers(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	o, err := s.CreateUser(ctx, "alice", RoleOwner, 3, "hash")
	if err != nil || o.Role != RoleOwner || o.OwnerID != 3 {
		t.Fatalf("CreateUser = %+v, %v", o, err)
	}
	if _, err := s.CreateUser(ctx, "alice", RoleOwner, 3, "x"); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := s.CreateUser(ctx, "bob", RoleOwner, 0, "x"); !errors.Is(err, ErrConflict) {
		t.Errorf("owner without owner ID: %v", err)
	}
	a, err := s.CreateUser(ctx, "root-admin", RoleAdmin, 99, "hash")
	if err != nil || a.OwnerID != 0 {
		t.Fatalf("admin = %+v, %v", a, err)
	}
	if err := s.SetTOTPSecret(ctx, a.ID, []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Errorf("admin TOTP secret stored in web.db: %v", err)
	}
	if err := s.SetTOTPSecret(ctx, o.ID, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UseTOTPStep(ctx, o.ID, 10); !ok {
		t.Error("first step refused")
	}
	if ok, _ := s.UseTOTPStep(ctx, o.ID, 10); ok {
		t.Error("step reused")
	}
	if err := s.ReplaceRecoveryCodes(ctx, o.ID, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UseRecoveryCode(ctx, o.ID, "h1"); !ok {
		t.Error("code refused")
	}
	if ok, _ := s.UseRecoveryCode(ctx, o.ID, "h1"); ok {
		t.Error("code reused")
	}
	if n, _ := s.RecoveryCodesLeft(ctx, o.ID); n != 1 {
		t.Errorf("codes left = %d", n)
	}
	got, err := s.GetUserByName(ctx, "alice")
	if err != nil || string(got.TOTPSecret) != "secret" {
		t.Errorf("GetUserByName = %+v, %v", got, err)
	}
	if users, _ := s.ListUsers(ctx, 3); len(users) != 1 {
		t.Errorf("ListUsers(3) = %v", users)
	}
}

func TestAdminLoginTOTP(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	admin, err := s.CreateUser(ctx, "root-admin", RoleAdmin, 0, "hash")
	if err != nil {
		t.Fatal(err)
	}
	if !admin.AdminLoginTOTP {
		t.Error("a new admin signs in without TOTP")
	}
	if err := s.SetAdminLoginTOTP(ctx, admin.ID, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUser(ctx, admin.ID); got.AdminLoginTOTP {
		t.Error("login TOTP still on after turning it off")
	}
	owner, err := s.CreateUser(ctx, "alice", RoleOwner, 3, "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAdminLoginTOTP(ctx, owner.ID, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("turning off an owner's admin login TOTP: %v", err)
	}
}

func TestLastLogins(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	now := t0
	s.SetClock(func() time.Time { return now })
	for _, e := range []struct {
		user int64
		ip   string
		ok   bool
	}{{1, "192.0.2.1", true}, {2, "192.0.2.2", true}, {1, "192.0.2.3", true}, {1, "192.0.2.4", false}} {
		if err := s.AddLoginEvent(ctx, e.user, "u", e.ip, e.ok); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	got, err := s.LastLogins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if l := got[1]; l.IP != "192.0.2.3" || !l.Time.Equal(t0.Add(2*time.Minute)) {
		t.Errorf("user 1's last successful sign-in = %+v", l)
	}
	if l := got[2]; l.IP != "192.0.2.2" {
		t.Errorf("user 2's last successful sign-in = %+v", l)
	}
	if _, ok := got[3]; ok {
		t.Error("a user who never signed in has a last sign-in")
	}
}

func TestSessionsAndNotifications(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u, err := s.CreateUser(ctx, "alice", RoleOwner, 3, "hash")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	se := Session{TokenHash: "h1", UserID: u.ID, CreatedAt: now, LastSeen: now, IP: "192.0.2.1", UserAgent: "test",
		AuthAt: now, CSRFToken: "csrf"}
	if err := s.CreateSession(ctx, se); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx, "h1")
	if err != nil || !got.MFAAt.IsZero() || got.CSRFToken != "csrf" || !got.AuthAt.Equal(now) {
		t.Fatalf("GetSession = %+v, %v", got, err)
	}
	if err := s.SetImpersonating(ctx, "h1", 7); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSession(ctx, "h1"); got.Impersonating != 7 {
		t.Errorf("impersonating = %d", got.Impersonating)
	}
	se.TokenHash = "h2"
	if err := s.CreateSession(ctx, se); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserSessions(ctx, u.ID, "h2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "h1"); !errors.Is(err, ErrNotFound) {
		t.Error("other session survived")
	}
	if _, err := s.GetSession(ctx, "h2"); err != nil {
		t.Error("kept session removed")
	}

	for _, m := range []string{"one", "two", "three"} {
		if _, err := s.AddNotification(ctx, u.ID, "info", m); err != nil {
			t.Fatal(err)
		}
	}
	recent, err := s.RecentNotifications(ctx, u.ID, 2)
	if err != nil || len(recent) != 2 || recent[0].Message != "three" {
		t.Errorf("RecentNotifications = %+v, %v", recent, err)
	}
	if after, _ := s.ListNotifications(ctx, u.ID, recent[1].ID, 10); len(after) != 1 || after[0].Message != "three" {
		t.Errorf("ListNotifications after = %+v", after)
	}
	if err := s.MarkNotificationsRead(ctx, u.ID, recent[0].ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.UnreadCount(ctx, u.ID); n != 2 {
		t.Errorf("unread = %d", n)
	}
	if err := s.MarkNotificationsRead(ctx, u.ID, 0); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.UnreadCount(ctx, u.ID); n != 0 {
		t.Errorf("unread after all = %d", n)
	}

	if err := s.AddLoginEvent(ctx, u.ID, "alice", "192.0.2.1", true); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.KnownIP(ctx, u.ID, "192.0.2.1"); !ok {
		t.Error("IP not known after a login")
	}
	if ok, _ := s.KnownIP(ctx, u.ID, "198.51.100.9"); ok {
		t.Error("unknown IP reported as known")
	}
	if err := s.SetMeta(ctx, "events.cursor", "42"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Meta(ctx, "events.cursor"); v != "42" {
		t.Errorf("meta = %q", v)
	}
}

func TestMustChangePassword(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	u, err := s.CreateUser(ctx, "alice", RoleOwner, 3, "hash")
	if err != nil {
		t.Fatal(err)
	}
	if u.MustChangePassword {
		t.Error("a new user must change their password before anyone asked")
	}
	if err := s.SetMustChangePassword(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUser(ctx, u.ID); !got.MustChangePassword {
		t.Error("flag not stored")
	}
	if err := s.SetPasswordHash(ctx, u.ID, "rehashed"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUser(ctx, u.ID); !got.MustChangePassword {
		t.Error("storing a new hash cleared the flag; a login-time rehash must not")
	}
	if err := s.SetMustChangePassword(ctx, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUser(ctx, u.ID); got.MustChangePassword {
		t.Error("flag not cleared")
	}
}
