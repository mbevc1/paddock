package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// JobStatus is a long-running operation's state.
type JobStatus string

// Job statuses.
const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobSucceeded JobStatus = "succeeded"
	JobFailed    JobStatus = "failed"
)

// Job is a long-running operation polled with job.get.
type Job struct {
	ID           string
	Op           string
	Status       JobStatus
	ActorUserID  int64
	OwnerID      int64
	Result       string
	ErrorCode    string
	ErrorMessage string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CreateJob records a queued job.
func (s *Store) CreateJob(ctx context.Context, id, op string, actorUserID, ownerID int64) error {
	now := s.timestamp()
	_, err := s.db.ExecContext(ctx, `INSERT INTO jobs (id, op, status, actor_user_id, owner_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, id, op, JobQueued, actorUserID, ownerID, now, now)
	if isConstraint(err) {
		return fmt.Errorf("%w: job %s", ErrConflict, id)
	}
	return err
}

// UpdateJob sets a job's status and, when finished, its result or error.
func (s *Store) UpdateJob(ctx context.Context, id string, status JobStatus, result, errCode, errMsg string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE jobs SET status = ?, result = ?, error_code = ?, error_message = ?,
		updated_at = ? WHERE id = ?`, status, result, errCode, errMsg, s.timestamp(), id)
	if isConstraint(err) {
		return fmt.Errorf("%w: job status %q", ErrConflict, status)
	}
	return affectedOne(res, err, "job "+id)
}

// GetJob returns one job.
func (s *Store) GetJob(ctx context.Context, id string) (Job, error) {
	var j Job
	var actor, owner sql.NullInt64
	var result, code, msg sql.NullString
	var created, updated string
	err := s.db.QueryRowContext(ctx, `SELECT id, op, status, actor_user_id, owner_id, result, error_code,
		error_message, created_at, updated_at FROM jobs WHERE id = ?`, id).
		Scan(&j.ID, &j.Op, &j.Status, &actor, &owner, &result, &code, &msg, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, fmt.Errorf("%w: job %s", ErrNotFound, id)
	}
	if err != nil {
		return Job{}, err
	}
	j.ActorUserID, j.OwnerID = actor.Int64, owner.Int64
	j.Result, j.ErrorCode, j.ErrorMessage = result.String, code.String, msg.String
	if j.CreatedAt, err = parseTime(created); err != nil {
		return Job{}, err
	}
	j.UpdatedAt, err = parseTime(updated)
	return j, err
}
