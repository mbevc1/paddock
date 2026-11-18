// Package system runs host commands. It is the only package allowed to import os/exec:
// every command is an argv slice with an absolute program path, a clean environment, and
// secrets on stdin.
package system

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Runner runs one host command.
type Runner interface {
	Run(ctx context.Context, argv []string, opts Opts) (Result, error)
}

// Opts controls one command run.
type Opts struct {
	// Stdin feeds the command; use it for secrets, never argv.
	Stdin io.Reader
	// Dir is the working directory; empty means "/".
	Dir string
	// Env adds KEY=VALUE entries to the base environment.
	Env []string
}

// Result is the captured output of a finished command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// ErrInvalidCommand reports an argv the runner refuses to execute.
var ErrInvalidCommand = errors.New("invalid command")

// ExitError reports a command that ran and exited non-zero.
type ExitError struct {
	Program  string
	ExitCode int
	// Stderr is truncated to maxErrorStderr bytes.
	Stderr string
}

func (e *ExitError) Error() string {
	if e.Stderr == "" {
		return fmt.Sprintf("%s exited with code %d", e.Program, e.ExitCode)
	}
	return fmt.Sprintf("%s exited with code %d: %s", e.Program, e.ExitCode, e.Stderr)
}

const maxErrorStderr = 4096

func newExitError(program string, code int, stderr []byte) *ExitError {
	if len(stderr) > maxErrorStderr {
		stderr = stderr[:maxErrorStderr]
	}
	return &ExitError{Program: program, ExitCode: code, Stderr: string(stderr)}
}
