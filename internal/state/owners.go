package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Limits are an owner's quotas (§5).
type Limits struct {
	MaxVhosts          int
	DiskMB             int
	MaxDatabases       int
	MaxDBUsers         int
	MaxAccessAccounts  int
	PHPVersions        []string // empty: every installed version
	MemoryMaxMB        int
	CPUQuotaPct        int
	TasksMax           int
	PMMaxChildren      int
	MaxUserConnections int
}

// DefaultLimits returns the §5 defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxVhosts:          5,
		DiskMB:             10240,
		MaxDatabases:       10,
		MaxDBUsers:         10,
		MaxAccessAccounts:  5,
		MemoryMaxMB:        2048,
		CPUQuotaPct:        200,
		TasksMax:           512,
		PMMaxChildren:      10,
		MaxUserConnections: 20,
	}
}

// Owner is a customer who owns vhosts.
type Owner struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

// CreateOwner inserts an owner and its limits.
func (s *Store) CreateOwner(ctx context.Context, name string, l Limits) (Owner, error) {
	o := Owner{Name: name}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		now := s.timestamp()
		res, err := tx.ExecContext(ctx, `INSERT INTO owners (name, created_at) VALUES (?, ?)`, name, now)
		if isConstraint(err) {
			return fmt.Errorf("%w: owner %q exists", ErrConflict, name)
		}
		if err != nil {
			return err
		}
		if o.ID, err = res.LastInsertId(); err != nil {
			return err
		}
		o.CreatedAt, err = parseTime(now)
		if err != nil {
			return err
		}
		return setLimits(ctx, tx, o.ID, l)
	})
	return o, err
}

// GetOwner returns one owner.
func (s *Store) GetOwner(ctx context.Context, id int64) (Owner, error) {
	var o Owner
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT id, name, created_at FROM owners WHERE id = ?`, id).
		Scan(&o.ID, &o.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Owner{}, fmt.Errorf("%w: owner %d", ErrNotFound, id)
	}
	if err != nil {
		return Owner{}, err
	}
	o.CreatedAt, err = parseTime(created)
	return o, err
}

// ListOwners returns all owners by ID.
func (s *Store) ListOwners(ctx context.Context) ([]Owner, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at FROM owners ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Owner
	for rows.Next() {
		var o Owner
		var created string
		if err := rows.Scan(&o.ID, &o.Name, &created); err != nil {
			return nil, err
		}
		if o.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// RenameOwner changes an owner's name.
func (s *Store) RenameOwner(ctx context.Context, id int64, name string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE owners SET name = ? WHERE id = ?`, name, id)
	if isConstraint(err) {
		return fmt.Errorf("%w: owner %q exists", ErrConflict, name)
	}
	return affectedOne(res, err, "owner")
}

// DeleteOwner removes an owner that has no vhosts left.
func (s *Store) DeleteOwner(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM owners WHERE id = ?`, id)
	if isConstraint(err) {
		return fmt.Errorf("%w: owner %d still has vhosts", ErrConflict, id)
	}
	return affectedOne(res, err, "owner")
}

// SetLimits replaces an owner's limits.
func (s *Store) SetLimits(ctx context.Context, ownerID int64, l Limits) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT id FROM owners WHERE id = ?`, ownerID).Scan(new(int64)); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: owner %d", ErrNotFound, ownerID)
			}
			return err
		}
		return setLimits(ctx, tx, ownerID, l)
	})
}

func setLimits(ctx context.Context, tx *sql.Tx, ownerID int64, l Limits) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO limits (owner_id, max_vhosts, disk_mb, max_databases,
		max_db_users, max_access_accounts, php_versions, memory_max_mb, cpu_quota_pct,
		tasks_max, pm_max_children, max_user_connections)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (owner_id) DO UPDATE SET max_vhosts = excluded.max_vhosts, disk_mb = excluded.disk_mb,
		max_databases = excluded.max_databases, max_db_users = excluded.max_db_users,
		max_access_accounts = excluded.max_access_accounts,
		php_versions = excluded.php_versions, memory_max_mb = excluded.memory_max_mb,
		cpu_quota_pct = excluded.cpu_quota_pct, tasks_max = excluded.tasks_max,
		pm_max_children = excluded.pm_max_children, max_user_connections = excluded.max_user_connections`,
		ownerID, l.MaxVhosts, l.DiskMB, l.MaxDatabases, l.MaxDBUsers, l.MaxAccessAccounts,
		strings.Join(l.PHPVersions, ","), l.MemoryMaxMB, l.CPUQuotaPct, l.TasksMax, l.PMMaxChildren,
		l.MaxUserConnections)
	if isConstraint(err) {
		return fmt.Errorf("%w: limits out of range", ErrConflict)
	}
	return err
}

// GetLimits returns an owner's limits.
func (s *Store) GetLimits(ctx context.Context, ownerID int64) (Limits, error) {
	var l Limits
	var php string
	err := s.db.QueryRowContext(ctx, `SELECT max_vhosts, disk_mb, max_databases, max_db_users,
		max_access_accounts, php_versions, memory_max_mb, cpu_quota_pct, tasks_max,
		pm_max_children, max_user_connections FROM limits WHERE owner_id = ?`, ownerID).
		Scan(&l.MaxVhosts, &l.DiskMB, &l.MaxDatabases, &l.MaxDBUsers, &l.MaxAccessAccounts,
			&php, &l.MemoryMaxMB, &l.CPUQuotaPct, &l.TasksMax, &l.PMMaxChildren, &l.MaxUserConnections)
	if errors.Is(err, sql.ErrNoRows) {
		return Limits{}, fmt.Errorf("%w: limits for owner %d", ErrNotFound, ownerID)
	}
	if php != "" {
		l.PHPVersions = strings.Split(php, ",")
	}
	return l, err
}

func affectedOne(res sql.Result, err error, what string) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, what)
	}
	return nil
}
