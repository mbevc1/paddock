package system

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExecRun(t *testing.T) {
	ctx := context.Background()
	var r Exec

	res, err := r.Run(ctx, []string{"/usr/bin/cat"}, Opts{Stdin: strings.NewReader("secret")})
	if err != nil || string(res.Stdout) != "secret" {
		t.Errorf("cat: %q, %v", res.Stdout, err)
	}

	res, err = r.Run(ctx, []string{"/usr/bin/env"}, Opts{Env: []string{"EXTRA=1"}})
	if err != nil {
		t.Fatal(err)
	}
	env := strings.Fields(string(res.Stdout))
	slices.Sort(env)
	if want := []string{"EXTRA=1", "LANG=C.UTF-8", "PATH=/usr/sbin:/usr/bin"}; !slices.Equal(env, want) {
		t.Errorf("environment = %q, want %q", env, want)
	}

	res, err = r.Run(ctx, []string{"/usr/bin/pwd"}, Opts{})
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "/" {
		t.Errorf("default dir: %q, %v", res.Stdout, err)
	}

	res, err = r.Run(ctx, []string{"/usr/bin/ls", "/does-not-exist"}, Opts{})
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode == 0 || res.ExitCode != exitErr.ExitCode {
		t.Fatalf("ls missing: err = %v, result code %d", err, res.ExitCode)
	}
	if !strings.Contains(exitErr.Stderr, "does-not-exist") {
		t.Errorf("stderr = %q", exitErr.Stderr)
	}

	timeout, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := r.Run(timeout, []string{"/usr/bin/sleep", "10"}, Opts{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("sleep with timeout: %v", err)
	}
}

func TestExecRejects(t *testing.T) {
	for _, argv := range [][]string{
		nil,
		{"ls"},
		{"./ls"},
		{"/usr/bin/../bin/ls"},
		{"/bin/sh", "-c", "id"},
		{"/usr/bin/bash", "-c", "id"},
		{"/usr/bin/echo", "a\x00b"},
	} {
		if _, err := (Exec{}).Run(context.Background(), argv, Opts{}); !errors.Is(err, ErrInvalidCommand) {
			t.Errorf("Run(%q) err = %v, want ErrInvalidCommand", argv, err)
		}
	}
	for _, env := range []string{"NOEQUALS", "=x", "A=b\x00c"} {
		if _, err := (Exec{}).Run(context.Background(), []string{"/usr/bin/true"}, Opts{Env: []string{env}}); !errors.Is(err, ErrInvalidCommand) {
			t.Errorf("env %q err = %v, want ErrInvalidCommand", env, err)
		}
	}
}

func TestLimitedBuffer(t *testing.T) {
	b := limitedBuffer{limit: 4}
	for _, s := range []string{"ab", "cdef", "gh"} {
		if n, err := b.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
	}
	if b.String() != "abcd" {
		t.Errorf("buffer = %q, want abcd", b.String())
	}
}

// TestOnlySystemImportsExec enforces that host commands go through Runner.
func TestOnlySystemImportsExec(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || filepath.Dir(path) == self {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "os/exec" {
				t.Errorf("%s imports os/exec; run commands through internal/system.Runner", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
