package ops

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

func TestVhostLogTail(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)

	var got VhostLog
	if err := web.Call(ctx, "vhost.log.tail", owner, "", VhostLogArgs{VhostID: "v00001", Log: "error"}, &got); err != nil ||
		len(got.Lines) != 0 || got.Truncated {
		t.Errorf("missing log = %+v, %v", got, err)
	}

	p := filepath.Join(e.root, BaseWWW, "v00001/logs/error.log")
	if err := os.WriteFile(p, []byte("PHP Warning\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The test process cannot own the file as the vhost user, so the agent refuses it.
	wantCode(t, web.Call(ctx, "vhost.log.tail", owner, "", VhostLogArgs{VhostID: "v00001", Log: "error"}, nil), api.CodeInvalidArgument)

	wantCode(t, web.Call(ctx, "vhost.log.tail", owner, "", VhostLogArgs{VhostID: "v00001", Log: "../../etc/shadow"}, nil), api.CodeInvalidArgument)
	wantCode(t, web.Call(ctx, "vhost.log.tail", owner, "", VhostLogArgs{VhostID: "v00001", Log: "access", Lines: maxLogLines + 1}, nil), api.CodeInvalidArgument)

	other, err := e.store.CreateOwner(ctx, "other", state.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	stranger := &api.Actor{UserID: 9, Role: api.RoleOwner, OwnerID: other.ID}
	wantCode(t, web.Call(ctx, "vhost.log.tail", stranger, "", VhostLogArgs{VhostID: "v00001", Log: "error"}, nil), api.CodeNotFound)
}

func TestLogLines(t *testing.T) {
	lines, cut := logLines([]byte("a\nb\nc\n"), false, 2)
	if len(lines) != 2 || lines[0] != "b" || lines[1] != "c" || !cut {
		t.Errorf("last two = %q, %v", lines, cut)
	}
	if lines, cut := logLines([]byte("a\nb"), false, 5); len(lines) != 2 || lines[1] != "b" || cut {
		t.Errorf("no trailing newline = %q, %v", lines, cut)
	}
	if lines, cut := logLines(nil, false, 5); len(lines) != 0 || cut {
		t.Errorf("empty = %q, %v", lines, cut)
	}
}
