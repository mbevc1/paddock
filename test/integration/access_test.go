//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

func TestSFTPAccount(t *testing.T) {
	h := newAgent(t)
	id, _ := newVhost(t, h, "8.3")
	key, pub := sshKey(t)
	h.mustJob(t, "access.create", ops.AccessCreateArgs{VhostID: id, Kind: state.AccessSFTP, Keys: []string{pub}}, time.Minute)
	argv := append([]string{"/usr/bin/sftp", "-i", key, "-b", "-"}, sshOpts...)
	argv = append(argv, id+"@127.0.0.1")
	res, err := (system.Exec{}).Run(context.Background(), argv, system.Opts{Stdin: strings.NewReader("pwd\nls -1a /\n")})
	out := string(res.Stdout)
	if err != nil || !strings.Contains(out, "Remote working directory: /site") {
		t.Fatalf("sftp: %v\n%s%s", err, out, res.Stderr)
	}
	for _, line := range strings.Split(out, "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "sftp>") && !strings.HasPrefix(l, "Remote") && l != "." && l != ".." && l != "site" {
			t.Errorf("jail root lists %q", l)
		}
	}
	if got := sshRun(t, key, id, "", "id"); strings.Contains(got, "uid=") {
		t.Errorf("SFTP account got a shell: %q", got)
	}
}

func TestShellAccount(t *testing.T) {
	h := newAgent(t)
	id, _ := newVhost(t, h, "8.3")
	sv := mustVhost(t, h, id)
	h.mustCall(t, "owner.limits.set", ops.OwnerLimitsArgs{OwnerID: sv.OwnerID, Limits: ops.LimitsArgs{ShellAllowed: ptrTo(true)}}, nil)
	key, pub := sshKey(t)
	h.mustJob(t, "access.create", ops.AccessCreateArgs{VhostID: id, Kind: state.AccessShell, Keys: []string{pub}}, time.Minute)
	shell := func(cmd string) string { return sshRun(t, key, id, "", "bash -lc '"+cmd+"'") }
	if got := shell("ps -eo uid= | tr -d \" \" | sort -u"); got != uidOf(t, id) {
		t.Errorf("processes visible: %q", got)
	}
	if got := shell("getent passwd | cut -d: -f1"); got != id {
		t.Errorf("users visible: %q", got)
	}
	if got := shell("php -v | head -1"); !strings.HasPrefix(got, "PHP 8.3") {
		t.Errorf("php -v = %q", got)
	}
	if got := shell("cat /proc/self/cgroup"); !strings.Contains(got, "user-"+uidOf(t, id)+".slice") {
		t.Errorf("cgroup = %q", got)
	}
	if got := shell("sudo -n id -u; su -c \"id -u\" root </dev/null"); strings.Contains(got, "\n0") || got == "0" {
		t.Errorf("privilege escalation: %q", got)
	}
}
