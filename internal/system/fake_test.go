package system

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestFake(t *testing.T) {
	ctx := context.Background()
	f := &Fake{}
	f.On("/usr/bin/systemctl", "start").Fail("unit failed").Times(1)
	f.On("/usr/bin/systemctl").Return(Result{Stdout: []byte("ok")}, nil)

	if _, err := f.Run(ctx, []string{"/usr/bin/systemctl", "start", "x"}, Opts{}); err == nil {
		t.Error("first start succeeded, want scripted failure")
	}
	res, err := f.Run(ctx, []string{"/usr/bin/systemctl", "start", "x"}, Opts{})
	if err != nil || string(res.Stdout) != "ok" {
		t.Errorf("second start: %q, %v", res.Stdout, err)
	}
	if _, err := f.Run(ctx, []string{"/usr/sbin/chpasswd"}, Opts{Stdin: strings.NewReader("v00012:pw")}); err != nil {
		t.Errorf("unmatched command: %v", err)
	}

	calls := f.Calls()
	if len(calls) != 3 || string(calls[2].Stdin) != "v00012:pw" {
		t.Fatalf("calls = %+v", calls)
	}
	want := []string{"/usr/bin/systemctl start x", "/usr/bin/systemctl start x", "/usr/sbin/chpasswd"}
	if got := f.Commands(); !slices.Equal(got, want) {
		t.Errorf("Commands() = %q, want %q", got, want)
	}

	strict := &Fake{Strict: true}
	if _, err := strict.Run(ctx, []string{"/usr/bin/true"}, Opts{}); err == nil {
		t.Error("strict fake accepted an unscripted command")
	}
	if _, err := strict.Run(ctx, []string{"/bin/sh", "-c", "id"}, Opts{}); !errors.Is(err, ErrInvalidCommand) {
		t.Errorf("fake accepted a shell: %v", err)
	}
}
