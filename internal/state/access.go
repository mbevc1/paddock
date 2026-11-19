package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// AccessAccount is an SFTP login of a vhost.
type AccessAccount struct {
	Name   string
	VhostN int
}

// SSHKey is an authorized public key of an access account.
type SSHKey struct {
	ID          int64
	Account     string
	PublicKey   string
	Fingerprint string
}

// AccessAccountOf returns the access account of vhost n.
func (s *Store) AccessAccountOf(ctx context.Context, n int) (AccessAccount, error) {
	var a AccessAccount
	err := s.db.QueryRowContext(ctx, `SELECT name, vhost_n FROM access_accounts WHERE vhost_n = ?`, n).
		Scan(&a.Name, &a.VhostN)
	if errors.Is(err, sql.ErrNoRows) {
		return AccessAccount{}, fmt.Errorf("%w: access account of vhost %d", ErrNotFound, n)
	}
	return a, err
}

// DeleteAccessAccount forgets an access account and its keys.
func (s *Store) DeleteAccessAccount(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM access_accounts WHERE name = ?`, name)
	return affectedOne(res, err, "access account "+name)
}

// AddSSHKey records a public key for an account.
func (s *Store) AddSSHKey(ctx context.Context, account, publicKey, fingerprint string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO ssh_keys (account, public_key, fingerprint, created_at) VALUES (?, ?, ?, ?)`,
		account, publicKey, fingerprint, s.timestamp())
	if isConstraint(err) {
		return fmt.Errorf("%w: key %s for %s", ErrConflict, fingerprint, account)
	}
	return err
}

// RemoveSSHKey forgets a key by fingerprint.
func (s *Store) RemoveSSHKey(ctx context.Context, account, fingerprint string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ssh_keys WHERE account = ? AND fingerprint = ?`, account, fingerprint)
	return affectedOne(res, err, "key "+fingerprint)
}

// ListSSHKeys returns an account's keys in the order they were added.
func (s *Store) ListSSHKeys(ctx context.Context, account string) ([]SSHKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, account, public_key, fingerprint FROM ssh_keys WHERE account = ? ORDER BY id`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSHKey
	for rows.Next() {
		var k SSHKey
		if err := rows.Scan(&k.ID, &k.Account, &k.PublicKey, &k.Fingerprint); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
