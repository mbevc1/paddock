//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

var sshOpts = []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"}

// sshKey writes a new ed25519 key pair and returns the private key path and public key.
func sshKey(t *testing.T) (string, string) {
	t.Helper()
	key := filepath.Join(t.TempDir(), "id")
	if _, err := (system.Exec{}).Run(context.Background(), []string{"/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key}, system.Opts{}); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return key, strings.TrimSpace(string(pub))
}

func sshRun(t *testing.T, key, user, stdin string, argv ...string) string {
	t.Helper()
	full := append([]string{"/usr/bin/ssh", "-i", key}, sshOpts...)
	full = append(full, user+"@127.0.0.1")
	full = append(full, argv...)
	res, _ := (system.Exec{}).Run(context.Background(), full, system.Opts{Stdin: strings.NewReader(stdin)})
	return strings.TrimSpace(string(res.Stdout) + string(res.Stderr))
}

func TestSFTPAccount(t *testing.T) {
	h := newAgent(t)
	id, _ := newVhost(t, h, "8.3")
	key, pub := sshKey(t)
	if job := h.job("access.create", ops.AccessCreateArgs{VhostID: id, Kind: state.AccessSFTP, Keys: []string{pub}}, time.Minute); job.Status != state.JobSucceeded {
		t.Fatalf("access.create: %+v", job)
	}
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
	ctx := context.Background()
	id, _ := newVhost(t, h, "8.3")
	sv := mustVhost(t, h, id)
	if err := h.client.Call(ctx, "owner.limits.set", h.admin, "", ops.OwnerLimitsArgs{OwnerID: sv.OwnerID, Limits: ops.LimitsArgs{ShellAllowed: ptrTo(true)}}, nil); err != nil {
		t.Fatal(err)
	}
	key, pub := sshKey(t)
	if job := h.job("access.create", ops.AccessCreateArgs{VhostID: id, Kind: state.AccessShell, Keys: []string{pub}}, time.Minute); job.Status != state.JobSucceeded {
		t.Fatalf("access.create: %+v", job)
	}
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
	if got := shell("wp --info"); !strings.Contains(got, "WP-CLI version") {
		t.Errorf("wp --info = %q", got)
	}
	if got := shell("cat /proc/self/cgroup"); !strings.Contains(got, "user-"+uidOf(t, id)+".slice") {
		t.Errorf("cgroup = %q", got)
	}
	if got := shell("sudo -n id -u; su -c \"id -u\" root </dev/null"); strings.Contains(got, "\n0") || got == "0" {
		t.Errorf("privilege escalation: %q", got)
	}
}

func mustVhost(t *testing.T, h *agentHarness, id string) state.Vhost {
	t.Helper()
	for _, v := range listVhosts(t, h) {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vhost %s not in state", id)
	return state.Vhost{}
}

func listVhosts(t *testing.T, h *agentHarness) []state.Vhost {
	t.Helper()
	vs, err := h.store.ListVhosts(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

// uidOf returns the vhost's UID, 100000 + N, which is "1" followed by the five digits.
func uidOf(t *testing.T, id string) string {
	t.Helper()
	return "1" + strings.TrimPrefix(id, "v")
}

func ptrTo[T any](v T) *T { return &v }
