package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/agent/ops"
)

var errNotifyUsage = errors.New("usage: paddock agent-notify md-renewed DOMAIN [DOMAIN ...]")

// runAgentNotify is mod_md's MDNotifyCmd: it asks the agent to check and reload the front
// Apache after a certificate renewal.
func runAgentNotify(ctx context.Context, args []string, _, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "md-renewed" {
		return errNotifyUsage
	}
	fs := flag.NewFlagSet("agent-notify md-renewed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", agent.SocketPath, "agent socket path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errNotifyUsage
	}
	ctx, cancel := context.WithTimeout(ctx, agentCallTimeout)
	defer cancel()
	client, err := agent.Dial(ctx, *socket)
	if err != nil {
		return err
	}
	defer client.Close()
	return client.Call(ctx, "front.md-renewed", nil, "", ops.MDRenewedArgs{Domains: fs.Args()}, nil)
}
