package state

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// EventKind classifies an agent event for the web process's notifications (§11.5).
type EventKind string

// Event kinds.
const (
	EventApplyFailed   EventKind = "apply_failed"
	EventCertRenewed   EventKind = "cert_renewed"
	EventCertExpiring  EventKind = "cert_expiring"
	EventQuotaWarning  EventKind = "quota_warning"
	EventQuotaExceeded EventKind = "quota_exceeded"
	EventQuotaCleared  EventKind = "quota_cleared"
	EventSSHKeyAdded   EventKind = "ssh_key_added"
)

// Event is something the agent did or noticed that a person may need to know.
type Event struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Kind    EventKind `json:"kind"`
	OwnerID int64     `json:"owner_id,omitempty"`
	VhostN  int       `json:"vhost_n,omitempty"`
	Message string    `json:"message"`
}

func nullInt(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: v != 0} }

// AppendEvent records an event at e.Time, or at the current time when that is zero.
func (s *Store) AppendEvent(ctx context.Context, e Event) (int64, error) {
	ts := s.timestamp()
	if !e.Time.IsZero() {
		ts = e.Time.UTC().Format(time.RFC3339Nano)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO events (time, kind, owner_id, vhost_n, message) VALUES (?, ?, ?, ?, ?)`,
		ts, e.Kind, nullInt(e.OwnerID), nullInt(int64(e.VhostN)), e.Message)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListEvents returns up to limit events after the cursor since, oldest first.
func (s *Store) ListEvents(ctx context.Context, since int64, limit int) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, time, kind, owner_id, vhost_n, message FROM events
		WHERE id > ? ORDER BY id LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts string
		var owner, vhost sql.NullInt64
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &owner, &vhost, &e.Message); err != nil {
			return nil, err
		}
		if e.Time, err = parseTime(ts); err != nil {
			return nil, err
		}
		e.OwnerID, e.VhostN = owner.Int64, int(vhost.Int64)
		out = append(out, e)
	}
	return out, rows.Err()
}

// EventSince reports whether an event of kind for vhost n was recorded at or after t.
func (s *Store) EventSince(ctx context.Context, kind EventKind, n int, t time.Time) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE kind = ? AND vhost_n IS ? AND time >= ?`,
		kind, nullInt(int64(n)), t.UTC().Format(time.RFC3339Nano)).Scan(&count)
	return count > 0, err
}

// QuotaState is an owner's quota notification and enforcement state.
type QuotaState struct {
	Warned   bool
	Enforced bool
}

// GetQuotaState returns an owner's quota state; an owner never scanned has none set.
func (s *Store) GetQuotaState(ctx context.Context, ownerID int64) (QuotaState, error) {
	var q QuotaState
	err := s.db.QueryRowContext(ctx, `SELECT warned, enforced FROM quota_state WHERE owner_id = ?`, ownerID).Scan(&q.Warned, &q.Enforced)
	if errors.Is(err, sql.ErrNoRows) {
		return QuotaState{}, nil
	}
	return q, err
}

// SetQuotaState records an owner's quota state.
func (s *Store) SetQuotaState(ctx context.Context, ownerID int64, q QuotaState) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO quota_state (owner_id, warned, enforced, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (owner_id) DO UPDATE SET warned = excluded.warned, enforced = excluded.enforced, updated_at = excluded.updated_at`,
		ownerID, q.Warned, q.Enforced, s.timestamp())
	return err
}

// VhostByDomain returns the vhost that serves a domain.
func (s *Store) VhostByDomain(ctx context.Context, name string) (Vhost, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT vhost_n FROM domains WHERE name = ?`, name).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return Vhost{}, ErrNotFound
	}
	if err != nil {
		return Vhost{}, err
	}
	return s.GetVhost(ctx, n)
}
