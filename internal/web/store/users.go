package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Role is a panel user's role.
type Role string

// Roles.
const (
	RoleOwner Role = "owner"
	RoleAdmin Role = "admin"
)

// User is a panel account.
type User struct {
	ID           int64
	Username     string
	Role         Role
	OwnerID      int64
	PasswordHash string
	// TOTPSecret is set for owners who enrolled; admins' secrets live in the agent.
	TOTPSecret   []byte
	TOTPLastStep int64
	TOTPRequired bool
	// AdminLoginTOTP is whether an admin's login asks for a TOTP code; always true for owners.
	AdminLoginTOTP bool
	Disabled       bool
	// MustChangePassword is set while the user's password is one an admin chose or reset.
	MustChangePassword bool
	CreatedAt          time.Time
}

const userColumns = `id, username, role, owner_id, password_hash, totp_secret, totp_last_step, totp_required, admin_login_totp, disabled,
	must_change_password, created_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var owner sql.NullInt64
	var created sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &owner, &u.PasswordHash, &u.TOTPSecret, &u.TOTPLastStep,
		&u.TOTPRequired, &u.AdminLoginTOTP, &u.Disabled, &u.MustChangePassword, &created); err != nil {
		return User{}, err
	}
	u.OwnerID = owner.Int64
	var err error
	u.CreatedAt, err = parseTS(created)
	return u, err
}

// CreateUser adds a user. Owners need an owner ID; admins have none.
func (s *Store) CreateUser(ctx context.Context, username string, role Role, ownerID int64, passwordHash string) (User, error) {
	var owner sql.NullInt64
	if role == RoleOwner && ownerID > 0 {
		owner = sql.NullInt64{Int64: ownerID, Valid: true}
	}
	now := s.now()
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (username, role, owner_id, password_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		username, role, owner, passwordHash, s.ts(now))
	if isConstraint(err) {
		return User{}, fmt.Errorf("%w: user %q", ErrConflict, username)
	}
	if err != nil {
		return User{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// GetUser returns a user by ID.
func (s *Store) GetUser(ctx context.Context, id int64) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: user %d", ErrNotFound, id)
	}
	return u, err
}

// GetUserByName returns a user by username.
func (s *Store) GetUserByName(ctx context.Context, username string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username = ?`, username))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: user %q", ErrNotFound, username)
	}
	return u, err
}

// ListUsers returns users by ID; ownerID 0 lists every user.
func (s *Store) ListUsers(ctx context.Context, ownerID int64) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users WHERE ? = 0 OR owner_id = ? ORDER BY id`, ownerID, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetMustChangePassword sets whether the user must choose a new password before anything else.
// SetPasswordHash leaves it alone, since a login-time rehash keeps the same password.
func (s *Store) SetMustChangePassword(ctx context.Context, id int64, must bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET must_change_password = ? WHERE id = ?`, must, id)
	return affectedOne(res, err, fmt.Sprintf("user %d", id))
}

// SetPasswordHash replaces a user's password hash.
func (s *Store) SetPasswordHash(ctx context.Context, id int64, hash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	return affectedOne(res, err, fmt.Sprintf("user %d", id))
}

// SetTOTPSecret enrolls an owner's TOTP secret, or removes it when secret is nil.
func (s *Store) SetTOTPSecret(ctx context.Context, id int64, secret []byte) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret = ?, totp_last_step = 0 WHERE id = ? AND role = 'owner'`, secret, id)
	return affectedOne(res, err, fmt.Sprintf("owner user %d", id))
}

// UseTOTPStep marks a time step used; it returns false for a step not newer than the last.
func (s *Store) UseTOTPStep(ctx context.Context, id, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, id, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// SetTOTPRequired records whether an admin requires TOTP for an owner.
func (s *Store) SetTOTPRequired(ctx context.Context, id int64, required bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_required = ? WHERE id = ?`, required, id)
	return affectedOne(res, err, fmt.Sprintf("user %d", id))
}

// SetAdminLoginTOTP sets whether an admin's login asks for a TOTP code.
func (s *Store) SetAdminLoginTOTP(ctx context.Context, id int64, on bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET admin_login_totp = ? WHERE id = ? AND role = 'admin'`, on, id)
	return affectedOne(res, err, fmt.Sprintf("admin user %d", id))
}

// SetDisabled enables or disables a user.
func (s *Store) SetDisabled(ctx context.Context, id int64, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, disabled, id)
	return affectedOne(res, err, fmt.Sprintf("user %d", id))
}

// ReplaceRecoveryCodes stores a fresh set of hashed recovery codes, dropping the old ones.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID int64, hashes []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, h); err != nil {
				return err
			}
		}
		return nil
	})
}

// UseRecoveryCode consumes an unused recovery code; it returns false when none matches.
func (s *Store) UseRecoveryCode(ctx context.Context, userID int64, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
		s.ts(s.now()), userID, hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RecoveryCodesLeft counts a user's unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// DeleteUser removes a user with their sessions, codes, and notifications.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return affectedOne(res, err, fmt.Sprintf("user %d", id))
}
