//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/system"
)

func TestSFTPAccount(t *testing.T) {
	h := newAgent(t)
	id, _ := newVhost(t, h, "8.3")
	key, pub := sshKey(t)
	h.mustJob(t, "access.create", ops.AccessCreateArgs{VhostID: id, Keys: []string{pub}}, time.Minute)
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
