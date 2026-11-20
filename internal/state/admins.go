package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Admin is an administrator known to the agent. Only root CLI commands create admins.
type Admin struct {
	UserID       int64
	Username     string
	TOTPSecret   []byte
	LastUsedStep int64
	// WindowUntil is the end of the admin window; zero when none is open.
	WindowUntil time.Time
	Disabled    bool
}

// AddAdmin records an admin and their TOTP secret.
func (s *Store) AddAdmin(ctx context.Context, userID int64, username string, secret []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admins (user_id, username, totp_secret) VALUES (?, ?, ?)`,
		userID, username, secret)
	if isConstraint(err) {
		return fmt.Errorf("%w: admin %d or %q exists", ErrConflict, userID, username)
	}
	return err
}

// GetAdmin returns an admin by web user ID.
func (s *Store) GetAdmin(ctx context.Context, userID int64) (Admin, error) {
	var a Admin
	var window sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT user_id, username, totp_secret, last_used_step, window_until, disabled
		FROM admins WHERE user_id = ?`, userID).Scan(&a.UserID, &a.Username, &a.TOTPSecret, &a.LastUsedStep, &window, &a.Disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, fmt.Errorf("%w: admin %d", ErrNotFound, userID)
	}
	if err != nil {
		return Admin{}, err
	}
	if window.Valid {
		if a.WindowUntil, err = parseTime(window.String); err != nil {
			return Admin{}, err
		}
	}
	return a, nil
}

// UseTOTPStep marks a TOTP time step as used. It returns false, without error, when the step
// is not newer than the last one used, so each code works once.
func (s *Store) UseTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET last_used_step = ? WHERE user_id = ? AND last_used_step < ?`,
		step, userID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// OpenAdminWindow records the end of an admin's window.
func (s *Store) OpenAdminWindow(ctx context.Context, userID int64, until time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET window_until = ? WHERE user_id = ?`,
		until.UTC().Format(time.RFC3339Nano), userID)
	return affectedOne(res, err, fmt.Sprintf("admin %d", userID))
}

// CloseAdminWindow ends an admin's window.
func (s *Store) CloseAdminWindow(ctx context.Context, userID int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET window_until = NULL WHERE user_id = ?`, userID)
	return affectedOne(res, err, fmt.Sprintf("admin %d", userID))
}

// ErrLastAdmin refuses to remove or disable the last enabled admin, which would leave no one
// to run admin operations.
var ErrLastAdmin = errors.New("no other enabled admin would remain")

// keepAnotherAdmin checks that the admin exists and that another enabled admin remains.
func keepAnotherAdmin(ctx context.Context, tx *sql.Tx, userID int64) error {
	var exists, others int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE user_id = ?),
		count(*) FILTER (WHERE user_id != ? AND disabled = 0) FROM admins`, userID, userID).
		Scan(&exists, &others); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("%w: admin %d", ErrNotFound, userID)
	}
	if others == 0 {
		return ErrLastAdmin
	}
	return nil
}

// RemoveAdmin deletes an admin, ending their admin rights at once.
func (s *Store) RemoveAdmin(ctx context.Context, userID int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := keepAnotherAdmin(ctx, tx, userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM admins WHERE user_id = ?`, userID)
		return err
	})
}

// DisableAdmin stops an admin's admin operations and closes their window, keeping the account.
func (s *Store) DisableAdmin(ctx context.Context, userID int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := keepAnotherAdmin(ctx, tx, userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE admins SET disabled = 1, window_until = NULL WHERE user_id = ?`, userID)
		return err
	})
}

// EnableAdmin lets a disabled admin run admin operations again, after a fresh TOTP code.
func (s *Store) EnableAdmin(ctx context.Context, userID int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET disabled = 0 WHERE user_id = ?`, userID)
	return affectedOne(res, err, fmt.Sprintf("admin %d", userID))
}

// ResetAdminTOTP replaces an admin's secret and closes any open window.
func (s *Store) ResetAdminTOTP(ctx context.Context, userID int64, secret []byte) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET totp_secret = ?, last_used_step = 0, window_until = NULL
		WHERE user_id = ?`, secret, userID)
	return affectedOne(res, err, fmt.Sprintf("admin %d", userID))
}
