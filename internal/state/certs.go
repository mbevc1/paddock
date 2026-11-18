package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CertSource says where a vhost's certificate comes from.
type CertSource string

// Certificate sources.
const (
	CertACME   CertSource = "acme"
	CertUpload CertSource = "upload"
)

// Cert describes a vhost's certificate. A vhost without a row uses ACME.
type Cert struct {
	Source      CertSource
	NotAfter    time.Time
	Fingerprint string
	UpdatedAt   time.Time
}

// SetCert records a vhost's certificate.
func (s *Store) SetCert(ctx context.Context, n int, c Cert) error {
	var notAfter sql.NullString
	if !c.NotAfter.IsZero() {
		notAfter = sql.NullString{String: c.NotAfter.UTC().Format(time.RFC3339Nano), Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO certs (vhost_n, source, not_after, fingerprint, updated_at)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT (vhost_n) DO UPDATE SET source = excluded.source,
		not_after = excluded.not_after, fingerprint = excluded.fingerprint, updated_at = excluded.updated_at`,
		n, c.Source, notAfter, c.Fingerprint, s.timestamp())
	if isConstraint(err) {
		return fmt.Errorf("%w: vhost %d or source %q", ErrConflict, n, c.Source)
	}
	return err
}

// GetCert returns a vhost's certificate record, or source ACME when none exists.
func (s *Store) GetCert(ctx context.Context, n int) (Cert, error) {
	var c Cert
	var notAfter, fp sql.NullString
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT source, not_after, fingerprint, updated_at FROM certs WHERE vhost_n = ?`, n).
		Scan(&c.Source, &notAfter, &fp, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Cert{Source: CertACME}, nil
	}
	if err != nil {
		return Cert{}, err
	}
	c.Fingerprint = fp.String
	if notAfter.Valid {
		if c.NotAfter, err = parseTime(notAfter.String); err != nil {
			return Cert{}, err
		}
	}
	c.UpdatedAt, err = parseTime(updated)
	return c, err
}

// DeleteCert forgets a vhost's certificate record, returning it to ACME.
func (s *Store) DeleteCert(ctx context.Context, n int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM certs WHERE vhost_n = ?`, n)
	return err
}
