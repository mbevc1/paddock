package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Resource is something counted against an owner's limits.
type Resource string

// Counted resources.
const (
	ResourceVhosts         Resource = "vhost"
	ResourceDatabases      Resource = "database"
	ResourceDBUsers        Resource = "DB user"
	ResourceAccessAccounts Resource = "access account"
)

// LimitError reports an owner at their limit for a resource.
type LimitError struct {
	Resource Resource
	Limit    int
}

func (e *LimitError) Error() string { return fmt.Sprintf("%s limit reached (%d)", e.Resource, e.Limit) }

// ErrShellNotAllowed reports a shell account for an owner whose limits forbid shells.
var ErrShellNotAllowed = errors.New("shell accounts are not allowed for this owner")

var quotaQueries = map[Resource]struct{ limit, count string }{
	ResourceVhosts: {"max_vhosts", `SELECT count(*) FROM vhosts WHERE owner_id = ?`},
	ResourceDatabases: {"max_databases", `SELECT count(*) FROM databases d JOIN vhosts v ON v.n = d.vhost_n
		WHERE v.owner_id = ?`},
	ResourceDBUsers: {"max_db_users", `SELECT count(*) FROM db_users u JOIN vhosts v ON v.n = u.vhost_n
		WHERE v.owner_id = ?`},
	ResourceAccessAccounts: {"max_access_accounts", `SELECT count(*) FROM access_accounts a JOIN vhosts v ON v.n = a.vhost_n
		WHERE v.owner_id = ?`},
}

// checkQuota fails with *LimitError when the owner already has as many of r as allowed. It
// runs inside the transaction that adds the resource, so concurrent requests cannot both pass.
func checkQuota(ctx context.Context, tx *sql.Tx, ownerID int64, r Resource) error {
	q := quotaQueries[r]
	var limit, count int
	// The column name comes from the fixed map above, never from input.
	err := tx.QueryRowContext(ctx, `SELECT `+q.limit+` FROM limits WHERE owner_id = ?`, ownerID).Scan(&limit) // #nosec G202
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: owner %d", ErrNotFound, ownerID)
	}
	if err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, q.count, ownerID).Scan(&count); err != nil {
		return err
	}
	if count >= limit {
		return &LimitError{Resource: r, Limit: limit}
	}
	return nil
}

// Usage counts an owner's resources.
func (s *Store) Usage(ctx context.Context, ownerID int64) (map[Resource]int, error) {
	out := map[Resource]int{}
	for r, q := range quotaQueries {
		var n int
		if err := s.db.QueryRowContext(ctx, q.count, ownerID).Scan(&n); err != nil {
			return nil, err
		}
		out[r] = n
	}
	return out, nil
}

func vhostOwner(ctx context.Context, tx *sql.Tx, n int) (int64, error) {
	var owner int64
	err := tx.QueryRowContext(ctx, `SELECT owner_id FROM vhosts WHERE n = ?`, n).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: vhost %d", ErrNotFound, n)
	}
	return owner, err
}

// CreateDatabase records a database of vhost n within its owner's limit.
func (s *Store) CreateDatabase(ctx context.Context, n int, name string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		owner, err := vhostOwner(ctx, tx, n)
		if err != nil {
			return err
		}
		if err := checkQuota(ctx, tx, owner, ResourceDatabases); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO databases (name, vhost_n, created_at) VALUES (?, ?, ?)`, name, n, s.timestamp())
		if isConstraint(err) {
			return fmt.Errorf("%w: database %s exists", ErrConflict, name)
		}
		return err
	})
}

// CreateDBUser records an extra DB user of vhost n within its owner's limit.
func (s *Store) CreateDBUser(ctx context.Context, n int, name, grants string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		owner, err := vhostOwner(ctx, tx, n)
		if err != nil {
			return err
		}
		if err := checkQuota(ctx, tx, owner, ResourceDBUsers); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO db_users (name, vhost_n, grants, created_at) VALUES (?, ?, ?, ?)`,
			name, n, grants, s.timestamp())
		if isConstraint(err) {
			return fmt.Errorf("%w: DB user %s exists", ErrConflict, name)
		}
		return err
	})
}

// AccessKind is an access account's kind.
type AccessKind string

// Access account kinds.
const (
	AccessSFTP  AccessKind = "sftp"
	AccessShell AccessKind = "shell"
)

// CreateAccessAccount records an SFTP or shell account of vhost n within its owner's limit;
// shell accounts also need shell_allowed.
func (s *Store) CreateAccessAccount(ctx context.Context, n int, name string, kind AccessKind) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		owner, err := vhostOwner(ctx, tx, n)
		if err != nil {
			return err
		}
		if kind == AccessShell {
			var allowed bool
			if err := tx.QueryRowContext(ctx, `SELECT shell_allowed FROM limits WHERE owner_id = ?`, owner).Scan(&allowed); err != nil {
				return err
			}
			if !allowed {
				return ErrShellNotAllowed
			}
		}
		if err := checkQuota(ctx, tx, owner, ResourceAccessAccounts); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO access_accounts (name, vhost_n, kind, created_at) VALUES (?, ?, ?, ?)`,
			name, n, kind, s.timestamp())
		if isConstraint(err) {
			return fmt.Errorf("%w: access account %s exists or kind %q is unknown", ErrConflict, name, kind)
		}
		return err
	})
}
