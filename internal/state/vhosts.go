package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mbevc1/paddock/internal/validate"
)

// UIDBase is added to the vhost number to give its UID and GID.
const UIDBase = validate.VhostUIDBase

// VhostStatus is a vhost's lifecycle state.
type VhostStatus string

// Vhost statuses.
const (
	VhostCreating  VhostStatus = "creating"
	VhostActive    VhostStatus = "active"
	VhostSuspended VhostStatus = "suspended"
	VhostDeleting  VhostStatus = "deleting"
	VhostFailed    VhostStatus = "failed"
)

// ErrVhostNumbersExhausted reports that all 65535 vhost numbers have been used.
var ErrVhostNumbersExhausted = errors.New("vhost numbers exhausted")

// Vhost is one isolated site.
type Vhost struct {
	N          int
	ID         string
	OwnerID    int64
	UID        int
	PHPVersion string
	Status     VhostStatus
	CreatedAt  time.Time
	PHP        PHPSettings
}

// PHPSettings are the PHP limits a vhost's FPM pool sets.
type PHPSettings struct {
	MemoryLimitMB int
	UploadMaxMB   int
	MaxExecutionS int
}

// DefaultPHPSettings returns PHP's own defaults, which new vhosts start with.
func DefaultPHPSettings() PHPSettings {
	return PHPSettings{MemoryLimitMB: 128, UploadMaxMB: 2, MaxExecutionS: 30}
}

// Domain is a host name served by a vhost.
type Domain struct {
	Name    string
	Primary bool
}

// CreateVhost allocates the next vhost number, never reusing one, and records the vhost in
// status "creating" with its primary domain and aliases. It fails with *LimitError when the
// owner is at max_vhosts.
func (s *Store) CreateVhost(ctx context.Context, ownerID int64, php, primary string, aliases []string) (Vhost, error) {
	var v Vhost
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := checkQuota(ctx, tx, ownerID, ResourceVhosts); err != nil {
			return err
		}
		var seq sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT seq FROM sqlite_sequence WHERE name = 'vhosts'`).Scan(&seq)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		n := int(seq.Int64) + 1
		id, err := validate.VhostNumber(n)
		if err != nil {
			return ErrVhostNumbersExhausted
		}
		now := s.timestamp()
		_, err = tx.ExecContext(ctx, `INSERT INTO vhosts (n, id, owner_id, uid, php_version, status, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, n, id, ownerID, UIDBase+n, php, VhostCreating, now)
		if isConstraint(err) {
			return fmt.Errorf("%w: unknown owner %d or PHP version %s", ErrConflict, ownerID, php)
		}
		if err != nil {
			return err
		}
		if err := insertDomains(ctx, tx, n, primary, aliases); err != nil {
			return err
		}
		created, err := parseTime(now)
		v = Vhost{N: n, ID: id, OwnerID: ownerID, UID: UIDBase + n, PHPVersion: php, Status: VhostCreating, CreatedAt: created,
			PHP: DefaultPHPSettings()}
		return err
	})
	return v, err
}

func insertDomains(ctx context.Context, tx *sql.Tx, n int, primary string, aliases []string) error {
	add := func(name string, isPrimary bool) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO domains (name, vhost_n, is_primary) VALUES (?, ?, ?)`, name, n, isPrimary)
		if isConstraint(err) {
			return fmt.Errorf("%w: domain %s is already in use", ErrConflict, name)
		}
		return err
	}
	if err := add(primary, true); err != nil {
		return err
	}
	for _, a := range aliases {
		if err := add(a, false); err != nil {
			return err
		}
	}
	return nil
}

// SetAliases replaces a vhost's alias domains, keeping its primary domain.
func (s *Store) SetAliases(ctx context.Context, n int, aliases []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM domains WHERE vhost_n = ? AND is_primary = 0`, n); err != nil {
			return err
		}
		for _, a := range aliases {
			_, err := tx.ExecContext(ctx, `INSERT INTO domains (name, vhost_n, is_primary) VALUES (?, ?, 0)`, a, n)
			if isConstraint(err) {
				return fmt.Errorf("%w: domain %s is already in use", ErrConflict, a)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Domains returns a vhost's domains, primary first.
func (s *Store) Domains(ctx context.Context, n int) ([]Domain, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, is_primary FROM domains WHERE vhost_n = ?
		ORDER BY is_primary DESC, name`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.Name, &d.Primary); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

const vhostColumns = `n, id, owner_id, uid, php_version, status, created_at, php_memory_mb, php_upload_mb, php_exec_s`

func scanVhost(row interface{ Scan(...any) error }) (Vhost, error) {
	var v Vhost
	var created string
	if err := row.Scan(&v.N, &v.ID, &v.OwnerID, &v.UID, &v.PHPVersion, &v.Status, &created,
		&v.PHP.MemoryLimitMB, &v.PHP.UploadMaxMB, &v.PHP.MaxExecutionS); err != nil {
		return Vhost{}, err
	}
	var err error
	v.CreatedAt, err = parseTime(created)
	return v, err
}

// GetVhost returns a vhost by number.
func (s *Store) GetVhost(ctx context.Context, n int) (Vhost, error) {
	v, err := scanVhost(s.db.QueryRowContext(ctx, `SELECT `+vhostColumns+` FROM vhosts WHERE n = ?`, n))
	if errors.Is(err, sql.ErrNoRows) {
		return Vhost{}, fmt.Errorf("%w: vhost %d", ErrNotFound, n)
	}
	return v, err
}

// ListVhosts returns vhosts by number; ownerID 0 lists every owner's.
func (s *Store) ListVhosts(ctx context.Context, ownerID int64) ([]Vhost, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+vhostColumns+` FROM vhosts
		WHERE ? = 0 OR owner_id = ? ORDER BY n`, ownerID, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vhost
	for rows.Next() {
		v, err := scanVhost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// CountVhosts returns how many vhosts an owner has, in any status.
func (s *Store) CountVhosts(ctx context.Context, ownerID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM vhosts WHERE owner_id = ?`, ownerID).Scan(&n)
	return n, err
}

// CountVhostsUsingPHP returns how many vhosts run a PHP version.
func (s *Store) CountVhostsUsingPHP(ctx context.Context, version string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM vhosts WHERE php_version = ?`, version).Scan(&n)
	return n, err
}

// SetVhostStatus records a lifecycle change.
func (s *Store) SetVhostStatus(ctx context.Context, n int, status VhostStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE vhosts SET status = ? WHERE n = ?`, status, n)
	if isConstraint(err) {
		return fmt.Errorf("%w: status %q", ErrConflict, status)
	}
	return affectedOne(res, err, fmt.Sprintf("vhost %d", n))
}

// SetVhostPHP records a vhost's PHP version.
func (s *Store) SetVhostPHP(ctx context.Context, n int, php string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE vhosts SET php_version = ? WHERE n = ?`, php, n)
	if isConstraint(err) {
		return fmt.Errorf("%w: PHP %s is not installed", ErrConflict, php)
	}
	return affectedOne(res, err, fmt.Sprintf("vhost %d", n))
}

// SetVhostPHPSettings replaces a vhost's PHP limits.
func (s *Store) SetVhostPHPSettings(ctx context.Context, n int, p PHPSettings) error {
	res, err := s.db.ExecContext(ctx, `UPDATE vhosts SET php_memory_mb = ?, php_upload_mb = ?, php_exec_s = ? WHERE n = ?`,
		p.MemoryLimitMB, p.UploadMaxMB, p.MaxExecutionS, n)
	return affectedOne(res, err, fmt.Sprintf("vhost %d", n))
}

// DeleteVhost removes a vhost and, by cascade, its domains, databases, accounts, and
// certificates. Its number stays used.
func (s *Store) DeleteVhost(ctx context.Context, n int) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM vhosts WHERE n = ?`, n)
	return affectedOne(res, err, fmt.Sprintf("vhost %d", n))
}
