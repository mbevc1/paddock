package state

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// stateAt builds a state.db with only the migrations up to version applied, runs seed
// against it, and returns its path.
func stateAt(t *testing.T, version int, seed string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	all, err := migrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, m := range all[:version] {
		body, err := migrationFiles.ReadFile("migrations/" + m.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(t.Context(), string(body)); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		if _, err := db.ExecContext(t.Context(), `INSERT INTO schema_migrations VALUES (?, '2026-11-19T00:00:00Z')`, m.version); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(t.Context(), seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return path
}

const seedBeforeSFTPOnly = `
INSERT INTO owners (id, name, created_at) VALUES (1, 'acme', 't');
INSERT INTO limits VALUES (1, 5, 10240, 10, 10, 5, 1, '', 2048, 200, 512, 10, 20);
INSERT INTO php_versions VALUES ('8.3', 't');
INSERT INTO vhosts VALUES (1, 'v00001', 1, 1000000001, '8.3', 'active', 't');
INSERT INTO vhosts VALUES (2, 'v00002', 1, 1000000002, '8.3', 'active', 't');
INSERT INTO access_accounts VALUES ('v00001', 1, 'sftp', 't');
INSERT INTO ssh_keys (account, public_key, fingerprint, created_at) VALUES ('v00001', 'ssh-ed25519 AAAA', 'SHA256:x', 't');
`

func TestSFTPOnlyMigrationKeepsSFTPAccounts(t *testing.T) {
	ctx := context.Background()
	path := stateAt(t, 2, seedBeforeSFTPOnly)
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	acct, err := s.AccessAccountOf(ctx, 1)
	if err != nil || acct.Name != "v00001" {
		t.Errorf("SFTP account after the migration = %+v, %v", acct, err)
	}
	if keys, err := s.ListSSHKeys(ctx, "v00001"); err != nil || len(keys) != 1 {
		t.Errorf("keys after the migration = %v, %v", keys, err)
	}
	l, err := s.GetLimits(ctx, 1)
	if err != nil || l.MaxAccessAccounts != 5 {
		t.Errorf("limits after the migration = %+v, %v", l, err)
	}
	if err := s.CreateAccessAccount(ctx, 2, "v00002"); err != nil {
		t.Errorf("new account after the migration: %v", err)
	}
}

// Shell accounts have Linux users and jails on the host that only the previous release can
// remove, so the migration refuses rather than forget them.
func TestSFTPOnlyMigrationRefusesShellAccounts(t *testing.T) {
	path := stateAt(t, 2, seedBeforeSFTPOnly+`INSERT INTO access_accounts VALUES ('v00002', 2, 'shell', 't');`)
	_, err := Open(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "v00002") || !strings.Contains(err.Error(), "previous release") {
		t.Fatalf("Open with a shell account = %v, want a refusal naming v00002", err)
	}
	again, err := Open(context.Background(), path)
	if err == nil {
		again.Close()
		t.Fatal("a refused migration was recorded as applied")
	}
}
