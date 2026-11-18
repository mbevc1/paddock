package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// DBUser is an extra database user of a vhost.
type DBUser struct {
	Name   string
	VhostN int
	Grants string
}

// ListDatabases returns a vhost's databases by name.
func (s *Store) ListDatabases(ctx context.Context, n int) ([]string, error) {
	return s.names(ctx, `SELECT name FROM databases WHERE vhost_n = ? ORDER BY name`, n)
}

// DatabaseVhost returns the vhost that owns a database.
func (s *Store) DatabaseVhost(ctx context.Context, name string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT vhost_n FROM databases WHERE name = ?`, name).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: database %s", ErrNotFound, name)
	}
	return n, err
}

// DeleteDatabase forgets a database.
func (s *Store) DeleteDatabase(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM databases WHERE name = ?`, name)
	return affectedOne(res, err, "database "+name)
}

// ListDBUsers returns a vhost's extra DB users by name.
func (s *Store) ListDBUsers(ctx context.Context, n int) ([]DBUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, vhost_n, grants FROM db_users WHERE vhost_n = ? ORDER BY name`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DBUser
	for rows.Next() {
		var u DBUser
		if err := rows.Scan(&u.Name, &u.VhostN, &u.Grants); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetDBUser returns one extra DB user.
func (s *Store) GetDBUser(ctx context.Context, name string) (DBUser, error) {
	var u DBUser
	err := s.db.QueryRowContext(ctx, `SELECT name, vhost_n, grants FROM db_users WHERE name = ?`, name).
		Scan(&u.Name, &u.VhostN, &u.Grants)
	if errors.Is(err, sql.ErrNoRows) {
		return DBUser{}, fmt.Errorf("%w: DB user %s", ErrNotFound, name)
	}
	return u, err
}

// DeleteDBUser forgets an extra DB user.
func (s *Store) DeleteDBUser(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM db_users WHERE name = ?`, name)
	return affectedOne(res, err, "DB user "+name)
}

func (s *Store) names(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
