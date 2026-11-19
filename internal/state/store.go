// Package state stores the agent's view of the host in state.db. Only the agent opens it.
package state

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// ErrNotFound reports a missing row.
var ErrNotFound = errors.New("not found")

// ErrConflict reports a row that clashes with an existing one.
var ErrConflict = errors.New("conflict")

// Store wraps state.db.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens or creates state.db at path with mode 0600 and applies pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path comes from the agent's configuration.
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}

	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Set("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	// One connection serializes writers and keeps per-connection pragmas in force.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

type migration struct {
	version int
	name    string
}

func migrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		prefix, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(prefix)
		if !ok || err != nil || v < 1 {
			return nil, fmt.Errorf("migration %q: name must start with a positive number and _", e.Name())
		}
		out = append(out, migration{version: v, name: e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := range out {
		if out[i].version != i+1 {
			return nil, fmt.Errorf("migrations must be numbered 1 to %d without gaps", len(out))
		}
	}
	return out, nil
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	all, err := migrations()
	if err != nil {
		return err
	}
	for _, m := range all {
		if err := s.apply(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

// preconditions refuse a migration that would lose what the host still holds.
var preconditions = map[int]func(context.Context, *sql.Tx) error{
	3: noShellAccounts,
}

// noShellAccounts refuses to drop shell support while shell accounts exist: each has a
// Linux user, a jail, and mount units that only the previous release can remove.
func noShellAccounts(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM access_accounts WHERE kind = 'shell' ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(names) > 0 {
		return fmt.Errorf("shell access accounts are no longer supported; delete %s with the previous release first",
			strings.Join(names, ", "))
	}
	return nil
}

func (s *Store) apply(ctx context.Context, m migration) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		if pre := preconditions[m.version]; pre != nil {
			if err := pre(ctx, tx); err != nil {
				return fmt.Errorf("migration %s: %w", m.name, err)
			}
		}
		body, err := migrationFiles.ReadFile("migrations/" + m.name)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			m.version, s.timestamp())
		return err
	})
}

// SchemaVersion returns the highest applied migration.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) timestamp() string { return s.now().Format(time.RFC3339Nano) }

func parseTime(v string) (time.Time, error) { return time.Parse(time.RFC3339Nano, v) }

// isConstraint reports a UNIQUE, PRIMARY KEY, CHECK, or foreign key violation.
func isConstraint(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_CONSTRAINT
}
