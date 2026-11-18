// Package api defines the newline-delimited JSON protocol between the web process and the
// agent (§4).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
)

// MaxRequestBytes bounds one request line, newline included.
const MaxRequestBytes = 1 << 20

// Role is the web user's role as the web process claims it. The agent uses it for scoping
// only and re-checks rights itself.
type Role string

// Roles.
const (
	RoleOwner Role = "owner"
	RoleAdmin Role = "admin"
)

// Actor is the web user on whose behalf a request is made.
type Actor struct {
	UserID  int64 `json:"user_id"`
	Role    Role  `json:"role"`
	OwnerID int64 `json:"owner_id,omitempty"`
	// ImpersonatedBy is the admin acting as this owner; the audit log records both.
	ImpersonatedBy int64 `json:"impersonated_by,omitempty"`
}

// Request is one line sent to the agent.
type Request struct {
	ID        string          `json:"id"`
	Op        string          `json:"op"`
	Actor     *Actor          `json:"actor,omitempty"`
	AdminTOTP string          `json:"admin_totp,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"`
}

// Response is one line returned by the agent.
type Response struct {
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Code classifies an error (§4).
type Code string

// Error codes.
const (
	CodeInvalidArgument Code = "invalid_argument"
	CodeNotFound        Code = "not_found"
	CodeForbidden       Code = "forbidden"
	CodeLimitExceeded   Code = "limit_exceeded"
	CodeConflict        Code = "conflict"
	CodeTOTPRequired    Code = "totp_required"
	CodeTOTPInvalid     Code = "totp_invalid"
	CodeApplyFailed     Code = "apply_failed"
	CodeInternal        Code = "internal"
)

// Error is an error returned to the caller. Message must never contain secrets.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

// Errorf builds an Error with a formatted message.
func Errorf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// AsError returns err as an *Error, or nil when it is not one.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// JobResult is the result of an operation that runs in the background.
type JobResult struct {
	JobID string `json:"job_id"`
}
