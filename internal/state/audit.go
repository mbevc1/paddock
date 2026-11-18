package state

import (
	"context"
	"time"
)

// AuditEntry records one agent operation. Actor and Args are JSON without secrets.
type AuditEntry struct {
	ID     int64
	Time   time.Time
	Actor  string
	Op     string
	Args   string
	Result string
}

// AppendAudit adds an entry stamped with the current time.
func (s *Store) AppendAudit(ctx context.Context, actor, op, args, result string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO audit (time, actor, op, args, result) VALUES (?, ?, ?, ?, ?)`,
		s.timestamp(), actor, op, args, result)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListAudit returns up to limit entries older than beforeID, newest first; beforeID 0 starts
// at the newest entry.
func (s *Store) ListAudit(ctx context.Context, beforeID int64, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, time, actor, op, args, result FROM audit
		WHERE ? = 0 OR id < ? ORDER BY id DESC LIMIT ?`, beforeID, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Op, &e.Args, &e.Result); err != nil {
			return nil, err
		}
		if e.Time, err = parseTime(ts); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
