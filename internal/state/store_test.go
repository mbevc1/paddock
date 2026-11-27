package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestMigrationsApplyAndAreIdempotent(t *testing.T) {
	ctx := context.Background()
	s, path := openTemp(t)
	all, err := migrations()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s.SchemaVersion(ctx); err != nil || v != len(all) {
		t.Fatalf("SchemaVersion = %d, %v; want %d", v, err, len(all))
	}
	if _, err := s.CreateOwner(ctx, "acme", DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	if v, err := again.SchemaVersion(ctx); err != nil || v != len(all) {
		t.Errorf("SchemaVersion after reopen = %d, %v", v, err)
	}
	if owners, err := again.ListOwners(ctx); err != nil || len(owners) != 1 {
		t.Errorf("owners after reopen = %v, %v", owners, err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state.db mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestOwnersAndLimits(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)

	o, err := s.CreateOwner(ctx, "acme", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOwner(ctx, "acme", DefaultLimits()); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate owner: %v", err)
	}
	got, err := s.GetLimits(ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxVhosts != 5 || got.DiskMB != 10240 || got.PHPVersions != nil {
		t.Errorf("default limits = %+v", got)
	}

	l := DefaultLimits()
	l.MaxVhosts, l.PHPVersions = 9, []string{"8.3", "8.4"}
	if err := s.SetLimits(ctx, o.ID, l); err != nil {
		t.Fatal(err)
	}
	if got, err = s.GetLimits(ctx, o.ID); err != nil || got.MaxVhosts != 9 ||
		!slices.Equal(got.PHPVersions, []string{"8.3", "8.4"}) {
		t.Errorf("updated limits = %+v, %v", got, err)
	}
	l.MemoryMaxMB = 0
	if err := s.SetLimits(ctx, o.ID, l); !errors.Is(err, ErrConflict) {
		t.Errorf("zero memory limit: %v", err)
	}
	if err := s.SetLimits(ctx, 999, DefaultLimits()); !errors.Is(err, ErrNotFound) {
		t.Errorf("limits for missing owner: %v", err)
	}
	if err := s.RenameOwner(ctx, o.ID, "acme-2"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetOwner(ctx, o.ID); err != nil || got.Name != "acme-2" {
		t.Errorf("GetOwner = %+v, %v", got, err)
	}
	if err := s.DeleteOwner(ctx, o.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetLimits(ctx, o.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("limits survive owner deletion: %v", err)
	}
}

func TestVhosts(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	o, err := s.CreateOwner(ctx, "acme", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVhost(ctx, o.ID, "8.3", "a.example.com", nil); !errors.Is(err, ErrConflict) {
		t.Errorf("vhost with uninstalled PHP: %v", err)
	}
	if err := s.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Errorf("adding a PHP version twice: %v", err)
	}

	v1, err := s.CreateVhost(ctx, o.ID, "8.3", "a.example.com", []string{"www.a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if v1.N != 1 || v1.ID != "v00001" || v1.UID != 1000000001 || v1.Status != VhostCreating {
		t.Errorf("first vhost = %+v", v1)
	}
	if _, err := s.CreateVhost(ctx, o.ID, "8.3", "www.a.example.com", nil); !errors.Is(err, ErrConflict) {
		t.Errorf("domain reuse: %v", err)
	}
	v2, err := s.CreateVhost(ctx, o.ID, "8.3", "b.example.com", nil)
	if err != nil || v2.N != 2 {
		t.Fatalf("second vhost = %+v, %v", v2, err)
	}
	if err := s.DeleteVhost(ctx, v2.N); err != nil {
		t.Fatal(err)
	}
	v3, err := s.CreateVhost(ctx, o.ID, "8.3", "b.example.com", nil)
	if err != nil || v3.N != 3 {
		t.Errorf("vhost after deletion = %+v, %v; want number 3", v3, err)
	}

	if err := s.SetAliases(ctx, v1.N, []string{"x.example.com", "y.example.com"}); err != nil {
		t.Fatal(err)
	}
	domains, err := s.Domains(ctx, v1.N)
	want := []Domain{{"a.example.com", true}, {"x.example.com", false}, {"y.example.com", false}}
	if err != nil || !slices.Equal(domains, want) {
		t.Errorf("Domains = %v, %v; want %v", domains, err, want)
	}

	if err := s.SetVhostStatus(ctx, v1.N, VhostActive); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVhostStatus(ctx, v1.N, "bogus"); !errors.Is(err, ErrConflict) {
		t.Errorf("bogus status: %v", err)
	}
	if err := s.SetVhostPHP(ctx, v1.N, "8.4"); !errors.Is(err, ErrConflict) {
		t.Errorf("switch to uninstalled PHP: %v", err)
	}
	got, err := s.GetVhost(ctx, v1.N)
	if err != nil || got.Status != VhostActive || got.PHPVersion != "8.3" {
		t.Errorf("GetVhost = %+v, %v", got, err)
	}
	if _, err := s.GetVhost(ctx, 2); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted vhost: %v", err)
	}
	if n, err := s.CountVhosts(ctx, o.ID); err != nil || n != 2 {
		t.Errorf("CountVhosts = %d, %v", n, err)
	}
	if list, err := s.ListVhosts(ctx, 0); err != nil || len(list) != 2 {
		t.Errorf("ListVhosts = %v, %v", list, err)
	}

	if err := s.RemovePHPVersion(ctx, "8.3"); !errors.Is(err, ErrConflict) {
		t.Errorf("removing PHP in use: %v", err)
	}
	if err := s.DeleteOwner(ctx, o.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("deleting owner with vhosts: %v", err)
	}
}

func TestVhostNumbersExhausted(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	o, err := s.CreateOwner(ctx, "acme", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVhost(ctx, o.ID, "8.3", "a.example.com", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE sqlite_sequence SET seq = 65535 WHERE name = 'vhosts'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVhost(ctx, o.ID, "8.3", "b.example.com", nil); !errors.Is(err, ErrVhostNumbersExhausted) {
		t.Errorf("err = %v, want ErrVhostNumbersExhausted", err)
	}
}

func TestAdmins(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.AddAdmin(ctx, 1, "root-admin", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAdmin(ctx, 1, "other", []byte("x")); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate admin: %v", err)
	}
	if ok, err := s.UseTOTPStep(ctx, 1, 100); err != nil || !ok {
		t.Errorf("first use of step 100: %v, %v", ok, err)
	}
	for _, step := range []int64{100, 99} {
		if ok, err := s.UseTOTPStep(ctx, 1, step); err != nil || ok {
			t.Errorf("reuse of step %d accepted: %v, %v", step, ok, err)
		}
	}
	if ok, _ := s.UseTOTPStep(ctx, 2, 500); ok {
		t.Error("unknown admin accepted a step")
	}
	until := time.Date(2026, 11, 17, 12, 10, 0, 0, time.UTC)
	if err := s.OpenAdminWindow(ctx, 1, until); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetAdmin(ctx, 1)
	if err != nil || !a.WindowUntil.Equal(until) || a.LastUsedStep != 100 || string(a.TOTPSecret) != "secret" {
		t.Errorf("GetAdmin = %+v, %v", a, err)
	}
	if err := s.ResetAdminTOTP(ctx, 1, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if a, err = s.GetAdmin(ctx, 1); err != nil || !a.WindowUntil.IsZero() || a.LastUsedStep != 0 {
		t.Errorf("after reset = %+v, %v", a, err)
	}
	if _, err := s.GetAdmin(ctx, 2); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing admin: %v", err)
	}
}

func TestAuditAndJobs(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for _, op := range []string{"owner.create", "vhost.create", "vhost.delete"} {
		if _, err := s.AppendAudit(ctx, `{"user_id":1}`, op, `{}`, "ok"); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := s.ListAudit(ctx, 0, 2)
	if err != nil || len(entries) != 2 || entries[0].Op != "vhost.delete" || entries[1].Op != "vhost.create" {
		t.Fatalf("ListAudit = %+v, %v", entries, err)
	}
	if older, err := s.ListAudit(ctx, entries[1].ID, 10); err != nil || len(older) != 1 || older[0].Op != "owner.create" {
		t.Errorf("older entries = %+v, %v", older, err)
	}

	if err := s.CreateJob(ctx, "job-1", "php.version.install", 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateJob(ctx, "job-1", "x", 1, 0); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate job: %v", err)
	}
	if err := s.UpdateJob(ctx, "job-1", JobFailed, "", "apply_failed", "dnf failed"); err != nil {
		t.Fatal(err)
	}
	j, err := s.GetJob(ctx, "job-1")
	if err != nil || j.Status != JobFailed || j.ErrorCode != "apply_failed" || j.ActorUserID != 1 {
		t.Errorf("GetJob = %+v, %v", j, err)
	}
	if _, err := s.GetJob(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing job: %v", err)
	}
}

func TestCerts(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	o, err := s.CreateOwner(ctx, "acme", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	v, err := s.CreateVhost(ctx, o.ID, "8.3", "a.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := s.GetCert(ctx, v.N); err != nil || c.Source != CertACME {
		t.Errorf("default cert = %+v, %v", c, err)
	}
	until := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	if err := s.SetCert(ctx, v.N, Cert{Source: CertUpload, NotAfter: until, Fingerprint: "ab:cd"}); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCert(ctx, v.N)
	if err != nil || c.Source != CertUpload || !c.NotAfter.Equal(until) || c.Fingerprint != "ab:cd" {
		t.Errorf("GetCert = %+v, %v", c, err)
	}
	if err := s.SetCert(ctx, v.N, Cert{Source: "self"}); !errors.Is(err, ErrConflict) {
		t.Errorf("bad source: %v", err)
	}
	if err := s.DeleteCert(ctx, v.N); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.GetCert(ctx, v.N); c.Source != CertACME {
		t.Errorf("after delete = %+v", c)
	}
}

func TestVhostPHPSettings(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	o, err := s.CreateOwner(ctx, "acme", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	v, err := s.CreateVhost(ctx, o.ID, "8.3", "a.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.PHP != DefaultPHPSettings() || v.PHP != (PHPSettings{MemoryLimitMB: 128, UploadMaxMB: 2, MaxExecutionS: 30}) {
		t.Errorf("new vhost settings = %+v", v.PHP)
	}
	if got, err := s.GetVhost(ctx, v.N); err != nil || got.PHP != DefaultPHPSettings() {
		t.Errorf("the column defaults differ from DefaultPHPSettings: %+v, %v", got.PHP, err)
	}
	want := PHPSettings{MemoryLimitMB: 512, UploadMaxMB: 64, MaxExecutionS: 120}
	if err := s.SetVhostPHPSettings(ctx, v.N, want); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetVhost(ctx, v.N); err != nil || got.PHP != want {
		t.Errorf("stored settings = %+v, %v", got.PHP, err)
	}
	if err := s.SetVhostPHPSettings(ctx, 99, want); !errors.Is(err, ErrNotFound) {
		t.Errorf("settings for a missing vhost: %v", err)
	}
}

func TestCreateRefusedOverDiskLimit(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	o, err := s.CreateOwner(ctx, "acme", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	v, err := s.CreateVhost(ctx, o.ID, "8.3", "a.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetQuotaState(ctx, o.ID, QuotaState{Warned: true, Enforced: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVhost(ctx, o.ID, "8.3", "b.example.com", nil); !errors.Is(err, ErrDiskLimit) {
		t.Errorf("vhost over the disk limit: %v", err)
	}
	if err := s.CreateDatabase(ctx, v.N, "v00001_app"); !errors.Is(err, ErrDiskLimit) {
		t.Errorf("database over the disk limit: %v", err)
	}
	if err := s.CreateDBUser(ctx, v.N, "v00001_ro", "read"); !errors.Is(err, ErrDiskLimit) {
		t.Errorf("DB user over the disk limit: %v", err)
	}
	if err := s.CreateAccessAccount(ctx, v.N, "v00001"); err != nil {
		t.Errorf("an access account stores nothing and stays allowed: %v", err)
	}

	if err := s.SetQuotaState(ctx, o.ID, QuotaState{Warned: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDatabase(ctx, v.N, "v00001_app"); err != nil {
		t.Errorf("database after the limit cleared: %v", err)
	}
}

func TestVhostSuspendedBy(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	o, err := s.CreateOwner(ctx, "acme", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	v, err := s.CreateVhost(ctx, o.ID, "8.3", "a.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetVhost(ctx, v.N); got.SuspendedBy != "" {
		t.Errorf("new vhost suspended by %q", got.SuspendedBy)
	}
	if err := s.SetVhostSuspension(ctx, v.N, SuspendedByOwner); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetVhost(ctx, v.N); got.Status != VhostSuspended || got.SuspendedBy != SuspendedByOwner {
		t.Errorf("after owner disable = %s by %q", got.Status, got.SuspendedBy)
	}
	if err := s.SetVhostSuspension(ctx, v.N, SuspendedByAdmin); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetVhost(ctx, v.N); got.SuspendedBy != SuspendedByAdmin {
		t.Errorf("admin takeover = %q", got.SuspendedBy)
	}
	if err := s.SetVhostSuspension(ctx, v.N, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetVhost(ctx, v.N); got.Status != VhostActive || got.SuspendedBy != "" {
		t.Errorf("after resume = %s by %q", got.Status, got.SuspendedBy)
	}
	if err := s.SetVhostSuspension(ctx, v.N, "someone"); err == nil {
		t.Error("an unknown suspender was stored")
	}
}
