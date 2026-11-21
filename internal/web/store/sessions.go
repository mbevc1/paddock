package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Session is a signed-in browser. The cookie holds the token; the store keeps its SHA-256.
type Session struct {
	TokenHash string
	UserID    int64
	CreatedAt time.Time
	LastSeen  time.Time
	IP        string
	UserAgent string
	// MFAAt is when the second factor passed; zero while it is still pending.
	MFAAt time.Time
	// AuthAt is the last password or TOTP check, for step-up.
	AuthAt        time.Time
	CSRFToken     string
	Impersonating int64
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, se Session) error {
	var mfa sql.NullString
	if !se.MFAAt.IsZero() {
		mfa = sql.NullString{String: s.ts(se.MFAAt), Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, created_at, last_seen, ip, user_agent, mfa_at,
		auth_at, csrf_token, impersonating) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		se.TokenHash, se.UserID, s.ts(se.CreatedAt), s.ts(se.LastSeen), se.IP, se.UserAgent, mfa, s.ts(se.AuthAt),
		se.CSRFToken, sql.NullInt64{Int64: se.Impersonating, Valid: se.Impersonating != 0})
	return err
}

// GetSession returns a session by token hash.
func (s *Store) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var se Session
	var created, seen, mfa, auth sql.NullString
	var imp sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT token_hash, user_id, created_at, last_seen, ip, user_agent, mfa_at, auth_at,
		csrf_token, impersonating FROM sessions WHERE token_hash = ?`, tokenHash).
		Scan(&se.TokenHash, &se.UserID, &created, &seen, &se.IP, &se.UserAgent, &mfa, &auth, &se.CSRFToken, &imp)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	se.Impersonating = imp.Int64
	for _, p := range []struct {
		dst *time.Time
		src sql.NullString
	}{{&se.CreatedAt, created}, {&se.LastSeen, seen}, {&se.MFAAt, mfa}, {&se.AuthAt, auth}} {
		if *p.dst, err = parseTS(p.src); err != nil {
			return Session{}, err
		}
	}
	return se, nil
}

// TouchSession records activity.
func (s *Store) TouchSession(ctx context.Context, tokenHash string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE token_hash = ?`, s.ts(at), tokenHash)
	return err
}

// MarkSessionAuth records a fresh password or TOTP check for step-up.
func (s *Store) MarkSessionAuth(ctx context.Context, tokenHash string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET auth_at = ? WHERE token_hash = ?`, s.ts(at), tokenHash)
	return affectedOne(res, err, "session")
}

// SetImpersonating records the owner an admin session acts as; 0 ends impersonation.
func (s *Store) SetImpersonating(ctx context.Context, tokenHash string, ownerID int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET impersonating = ? WHERE token_hash = ?`,
		sql.NullInt64{Int64: ownerID, Valid: ownerID != 0}, tokenHash)
	return affectedOne(res, err, "session")
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteUserSessions ends every session of a user, optionally keeping one.
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, keep string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`, userID, keep)
	return err
}

// DeleteSessionsBefore removes sessions created before t, past every absolute lifetime.
func (s *Store) DeleteSessionsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE created_at < ?`, s.ts(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Notification is a message for one user (§11.5).
type Notification struct {
	ID        int64
	UserID    int64
	Kind      string
	Message   string
	CreatedAt time.Time
	ReadAt    time.Time
}

// AddNotification stores a notification.
func (s *Store) AddNotification(ctx context.Context, userID int64, kind, message string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO notifications (user_id, kind, message, created_at) VALUES (?, ?, ?, ?)`,
		userID, kind, message, s.ts(s.now()))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const notificationColumns = `id, user_id, kind, message, created_at, read_at`

func scanNotifications(rows *sql.Rows) ([]Notification, error) {
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var created, read sql.NullString
		if err := rows.Scan(&n.ID, &n.UserID, &n.Kind, &n.Message, &created, &read); err != nil {
			return nil, err
		}
		var err error
		if n.CreatedAt, err = parseTS(created); err != nil {
			return nil, err
		}
		if n.ReadAt, err = parseTS(read); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ListNotifications returns a user's notifications with ID above after, oldest first.
func (s *Store) ListNotifications(ctx context.Context, userID, after int64, limit int) ([]Notification, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+notificationColumns+` FROM notifications
		WHERE user_id = ? AND id > ? ORDER BY id LIMIT ?`, userID, after, limit)
	if err != nil {
		return nil, err
	}
	return scanNotifications(rows)
}

// RecentNotifications returns a user's newest notifications, newest first.
func (s *Store) RecentNotifications(ctx context.Context, userID int64, limit int) ([]Notification, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+notificationColumns+` FROM notifications
		WHERE user_id = ? ORDER BY id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	return scanNotifications(rows)
}

// UnreadCount counts a user's unread notifications.
func (s *Store) UnreadCount(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM notifications WHERE user_id = ? AND read_at IS NULL`, userID).Scan(&n)
	return n, err
}

// MarkNotificationsRead marks a user's notifications read: one by ID, or all when id is 0.
func (s *Store) MarkNotificationsRead(ctx context.Context, userID, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL AND (? = 0 OR id = ?)`,
		s.ts(s.now()), userID, id, id)
	return err
}

// AddLoginEvent records a login attempt.
func (s *Store) AddLoginEvent(ctx context.Context, userID int64, username, ip string, success bool) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO login_events (user_id, username, ip, success, time) VALUES (?, ?, ?, ?, ?)`,
		sql.NullInt64{Int64: userID, Valid: userID != 0}, username, ip, success, s.ts(s.now()))
	return err
}

// KnownIP reports whether a user has logged in successfully from ip before.
func (s *Store) KnownIP(ctx context.Context, userID int64, ip string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM login_events WHERE user_id = ? AND ip = ? AND success = 1`, userID, ip).Scan(&n)
	return n > 0, err
}

// LoginRecord is a user's most recent successful sign-in.
type LoginRecord struct {
	IP   string
	Time time.Time
}

// LastLogins returns each user's most recent successful sign-in, by user ID.
func (s *Store) LastLogins(ctx context.Context) (map[int64]LoginRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, ip, time FROM login_events e
		WHERE success = 1 AND user_id IS NOT NULL
		AND id = (SELECT max(id) FROM login_events WHERE user_id = e.user_id AND success = 1)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]LoginRecord{}
	for rows.Next() {
		var id int64
		var rec LoginRecord
		var at sql.NullString
		if err := rows.Scan(&id, &rec.IP, &at); err != nil {
			return nil, err
		}
		if rec.Time, err = parseTS(at); err != nil {
			return nil, err
		}
		out[id] = rec
	}
	return out, rows.Err()
}
