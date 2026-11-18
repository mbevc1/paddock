package system

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
)

// Call is one command a Fake received.
type Call struct {
	Argv  []string
	Stdin []byte
	Dir   string
	Env   []string
}

// Rule scripts the response to matching commands.
type Rule struct {
	prefix    []string
	match     func(argv []string) bool
	result    Result
	err       error
	remaining int
}

// Return sets the result and error for matching commands.
func (r *Rule) Return(res Result, err error) *Rule {
	r.result, r.err = res, err
	return r
}

// Fail makes matching commands exit with code 1 and the given stderr.
func (r *Rule) Fail(stderr string) *Rule {
	return r.Return(Result{Stderr: []byte(stderr), ExitCode: 1}, newExitError("fake", 1, []byte(stderr)))
}

// Times limits the rule to n matches; after that, later rules apply.
func (r *Rule) Times(n int) *Rule {
	r.remaining = n
	return r
}

// Fake records commands and returns scripted results. Commands without a matching rule
// succeed with empty output, unless Strict is set.
type Fake struct {
	// Strict makes unmatched commands fail.
	Strict bool

	mu    sync.Mutex
	rules []*Rule
	calls []Call
}

var _ Runner = (*Fake)(nil)

// On adds a rule for commands whose argv starts with prefix. Earlier rules win.
func (f *Fake) On(prefix ...string) *Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &Rule{prefix: prefix}
	f.rules = append(f.rules, r)
	return r
}

// OnFunc adds a rule for commands that match reports true for. Earlier rules win.
func (f *Fake) OnFunc(match func(argv []string) bool) *Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &Rule{match: match}
	f.rules = append(f.rules, r)
	return r
}

func (r *Rule) matches(argv []string) bool {
	if r.match != nil {
		return r.match(argv)
	}
	return hasPrefix(argv, r.prefix)
}

// Run records the call and returns the first matching rule's result.
func (f *Fake) Run(ctx context.Context, argv []string, opts Opts) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := checkArgv(argv); err != nil {
		return Result{}, err
	}
	call := Call{Argv: slices.Clone(argv), Dir: opts.Dir, Env: slices.Clone(opts.Env)}
	if opts.Stdin != nil {
		data, err := io.ReadAll(opts.Stdin)
		if err != nil {
			return Result{}, err
		}
		call.Stdin = data
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	for _, r := range f.rules {
		if r.remaining < 0 || !r.matches(argv) {
			continue
		}
		if r.remaining > 0 {
			r.remaining--
			if r.remaining == 0 {
				r.remaining = -1
			}
		}
		return r.result, r.err
	}
	if f.Strict {
		return Result{}, fmt.Errorf("fake: unexpected command %q", strings.Join(argv, " "))
	}
	return Result{}, nil
}

// Calls returns the commands received so far.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// Commands returns the argv of every call joined with spaces, for compact assertions.
func (f *Fake) Commands() []string {
	calls := f.Calls()
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = strings.Join(c.Argv, " ")
	}
	return out
}

func hasPrefix(argv, prefix []string) bool {
	return len(argv) >= len(prefix) && slices.Equal(argv[:len(prefix)], prefix)
}
