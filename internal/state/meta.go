package state

import (
	"context"
	"database/sql"
	"errors"
)

const metaReconciledVersion = "reconciled_version"

// ReconciledVersion returns the agent version that last reconciled every vhost, or "" if none has.
func (s *Store) ReconciledVersion(ctx context.Context) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM agent_meta WHERE key = ?`, metaReconciledVersion).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetReconciledVersion records the agent version that reconciled every vhost.
func (s *Store) SetReconciledVersion(ctx context.Context, version string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agent_meta (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, metaReconciledVersion, version)
	return err
}
