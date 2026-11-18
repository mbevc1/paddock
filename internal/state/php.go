package state

import (
	"context"
	"fmt"
)

// AddPHPVersion records an installed PHP version; adding it again is a no-op.
func (s *Store) AddPHPVersion(ctx context.Context, version string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO php_versions (version, installed_at) VALUES (?, ?)
		ON CONFLICT (version) DO NOTHING`, version, s.timestamp())
	return err
}

// RemovePHPVersion forgets a PHP version no vhost uses.
func (s *Store) RemovePHPVersion(ctx context.Context, version string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM php_versions WHERE version = ?`, version)
	if isConstraint(err) {
		return fmt.Errorf("%w: PHP %s is in use", ErrConflict, version)
	}
	return affectedOne(res, err, "PHP version "+version)
}

// ListPHPVersions returns installed versions in ascending order.
func (s *Store) ListPHPVersions(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM php_versions ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
