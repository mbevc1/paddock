package state

import (
	"context"
	"errors"
	"testing"
)

func wantLimit(t *testing.T, err error, r Resource, limit int) {
	t.Helper()
	var le *LimitError
	if !errors.As(err, &le) || le.Resource != r || le.Limit != limit {
		t.Errorf("err = %v, want %s limit %d", err, r, limit)
	}
}

func TestQuotas(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	l := DefaultLimits()
	l.MaxVhosts, l.MaxDatabases, l.MaxDBUsers, l.MaxAccessAccounts = 2, 1, 1, 1
	o, err := s.CreateOwner(ctx, "acme", l)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateOwner(ctx, "other", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	v1, err := s.CreateVhost(ctx, o.ID, "8.3", "a.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVhost(ctx, o.ID, "8.3", "b.example.com", nil); err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateVhost(ctx, o.ID, "8.3", "c.example.com", nil)
	wantLimit(t, err, ResourceVhosts, 2)
	if _, err := s.CreateVhost(ctx, other.ID, "8.3", "c.example.com", nil); err != nil {
		t.Errorf("another owner's quota is separate: %v", err)
	}
	if _, err := s.CreateVhost(ctx, 999, "8.3", "d.example.com", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("vhost for missing owner: %v", err)
	}

	if err := s.CreateDatabase(ctx, v1.N, "v00001_wp"); err != nil {
		t.Fatal(err)
	}
	wantLimit(t, s.CreateDatabase(ctx, v1.N, "v00001_shop"), ResourceDatabases, 1)
	if err := s.CreateDBUser(ctx, v1.N, "v00001_ro", "SELECT"); err != nil {
		t.Fatal(err)
	}
	wantLimit(t, s.CreateDBUser(ctx, v1.N, "v00001_rw", "ALL"), ResourceDBUsers, 1)

	if err := s.CreateAccessAccount(ctx, v1.N, "v00001", AccessShell); !errors.Is(err, ErrShellNotAllowed) {
		t.Errorf("shell without shell_allowed: %v", err)
	}
	if err := s.CreateAccessAccount(ctx, v1.N, "v00001", AccessSFTP); err != nil {
		t.Fatal(err)
	}
	wantLimit(t, s.CreateAccessAccount(ctx, v1.N, "v00001_b", AccessSFTP), ResourceAccessAccounts, 1)
	if err := s.CreateDatabase(ctx, 999, "v00999_x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("database for missing vhost: %v", err)
	}

	usage, err := s.Usage(ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	if usage[ResourceVhosts] != 2 || usage[ResourceDatabases] != 1 || usage[ResourceDBUsers] != 1 || usage[ResourceAccessAccounts] != 1 {
		t.Errorf("Usage = %v", usage)
	}

	l.MaxVhosts = 3
	if err := s.SetLimits(ctx, o.ID, l); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVhost(ctx, o.ID, "8.3", "e.example.com", nil); err != nil {
		t.Errorf("after raising the limit: %v", err)
	}
}
