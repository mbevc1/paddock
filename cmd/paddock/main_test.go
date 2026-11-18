package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "no arguments", args: nil, wantCode: 2, wantStderr: "Usage: paddock"},
		{name: "help", args: []string{"help"}, wantCode: 0, wantStdout: "Usage: paddock"},
		{name: "version", args: []string{"version"}, wantCode: 0, wantStdout: "paddock dev\n"},
		{name: "unknown command", args: []string{"bogus"}, wantCode: 2, wantStderr: `unknown command "bogus"`},
		{name: "stub", args: []string{"setup"}, wantCode: 1, wantStderr: "paddock setup: not implemented yet"},
		{name: "web without hostname", args: []string{"web"}, wantCode: 1, wantStderr: "-hostname"},
		{name: "admin without subcommand", args: []string{"admin"}, wantCode: 1, wantStderr: "usage: paddock admin"},
		{name: "admin add without username", args: []string{"admin", "add", "-user-id", "1"}, wantCode: 1, wantStderr: "usage: paddock admin"},
		{name: "admin unknown subcommand", args: []string{"admin", "remove", "-user-id", "1"}, wantCode: 1, wantStderr: "usage: paddock admin"},
		{name: "admin without agent", args: []string{"admin", "totp-reset", "-user-id", "1", "-socket", "/nonexistent/agent.sock"}, wantCode: 1, wantStderr: "connect to agent"},
		{name: "agent-notify without event", args: []string{"agent-notify"}, wantCode: 1, wantStderr: "usage: paddock agent-notify"},
		{name: "agent-notify without domains", args: []string{"agent-notify", "md-renewed"}, wantCode: 1, wantStderr: "usage: paddock agent-notify"},
		{name: "reconcile without -all", args: []string{"reconcile"}, wantCode: 1, wantStderr: "usage: paddock reconcile"},
		{name: "agent with stray argument", args: []string{"agent", "extra"}, wantCode: 1, wantStderr: "unexpected arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestEveryPlannedSubcommandExists(t *testing.T) {
	have := map[string]bool{}
	for _, c := range commands() {
		have[c.name] = true
	}
	for _, name := range []string{"agent", "web", "setup", "teardown", "reconcile", "admin", "agent-notify"} {
		if !have[name] {
			t.Errorf("subcommand %q missing", name)
		}
	}
}
