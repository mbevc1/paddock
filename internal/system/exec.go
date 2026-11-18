package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// baseEnv is the whole environment of every command unless Opts.Env adds to it.
var baseEnv = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C.UTF-8"}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true}

// maxOutput caps captured stdout and stderr each.
const maxOutput = 16 << 20

// waitDelay bounds the wait for output pipes after the context ends or the process exits.
const waitDelay = 5 * time.Second

// Exec runs commands on the host with os/exec.
type Exec struct{}

var _ Runner = Exec{}

// Run starts argv[0] (an absolute path) with argv[1:] and waits for it.
func (Exec) Run(ctx context.Context, argv []string, opts Opts) (Result, error) {
	if err := checkArgv(argv); err != nil {
		return Result{}, err
	}
	env, err := environment(opts.Env)
	if err != nil {
		return Result{}, err
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv is validated by checkArgv; no shell is involved.
	cmd.Env = env
	cmd.Dir = opts.Dir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Stdin = opts.Stdin
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxOutput, maxOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = waitDelay

	err = cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: cmd.ProcessState.ExitCode()}
	if err == nil {
		return res, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, fmt.Errorf("%s: %w", argv[0], ctxErr)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return res, newExitError(argv[0], exitErr.ExitCode(), res.Stderr)
	}
	return res, fmt.Errorf("%s: %w", argv[0], err)
}

func checkArgv(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("%w: empty argv", ErrInvalidCommand)
	}
	if !filepath.IsAbs(argv[0]) || filepath.Clean(argv[0]) != argv[0] {
		return fmt.Errorf("%w: program %q must be a clean absolute path", ErrInvalidCommand, argv[0])
	}
	if shells[filepath.Base(argv[0])] {
		return fmt.Errorf("%w: shells are not allowed", ErrInvalidCommand)
	}
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("%w: argument contains NUL", ErrInvalidCommand)
		}
	}
	return nil
}

func environment(extra []string) ([]string, error) {
	env := append([]string(nil), baseEnv...)
	for _, kv := range extra {
		key, _, ok := strings.Cut(kv, "=")
		if !ok || key == "" || strings.ContainsRune(kv, 0) {
			return nil, fmt.Errorf("%w: bad environment entry", ErrInvalidCommand)
		}
		env = append(env, kv)
	}
	return env, nil
}

// limitedBuffer keeps the first limit bytes written and discards the rest.
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}
