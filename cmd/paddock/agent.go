package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"strconv"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/platform"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

const defaultStatePath = "/var/lib/paddock/agent/state.db"

func runAgent(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", agent.SocketPath, "agent socket path")
	statePath := fs.String("state", defaultStatePath, "state database path")
	webUser := fs.String("web-user", "paddock", "user the web process runs as")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	if os.Geteuid() != 0 {
		return errors.New("the agent must run as root")
	}
	uid, gid, err := lookupUser(*webUser)
	if err != nil {
		return err
	}

	plat, err := detectPlatform()
	if err != nil {
		return err
	}

	log := slog.New(slog.NewJSONHandler(stderr, nil))
	store, err := state.Open(ctx, *statePath)
	if err != nil {
		return err
	}
	defer store.Close()

	gate := &agent.TOTPGate{Store: store}
	srv := &agent.Server{WebUID: uid, Registry: agent.NewRegistry(), Store: store, Gate: gate, Log: log}
	srv.RegisterJobGet()
	ops.RegisterAdmin(srv.Registry, store, gate)
	ops.RegisterOwners(srv.Registry, store)
	host := &ops.Host{Run: system.Exec{}, Files: render.Writer{}, Platform: plat, Log: log}
	ops.RegisterPHP(srv.Registry, store, host)

	l, err := agent.Listen(*socket, gid)
	if err != nil {
		return err
	}
	log.Info("agent listening", "socket", *socket, "version", version)
	return srv.Serve(ctx, l)
}

func lookupUser(name string) (uid uint32, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("look up user %s: %w", name, err)
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("user %s: bad UID %q", name, u.Uid)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("user %s: bad GID %q", name, u.Gid)
	}
	return uint32(uid64), gid, nil
}

func detectPlatform() (platform.Platform, error) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return platform.Platform{}, err
	}
	defer f.Close()
	return platform.Detect(f)
}
