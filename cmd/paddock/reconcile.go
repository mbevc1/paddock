package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/agent/ops"
)

const reconcileTimeout = 30 * time.Minute

var errReconcileUsage = errors.New("usage: paddock reconcile -all")

// runReconcile asks the agent, as root, to re-render and re-apply everything in state.db.
func runReconcile(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	all := fs.Bool("all", false, "reconcile every vhost")
	socket := fs.String("socket", agent.SocketPath, "agent socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*all || fs.NArg() > 0 {
		return errReconcileUsage
	}
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()
	client, err := agent.Dial(ctx, *socket)
	if err != nil {
		return err
	}
	defer client.Close()
	var res ops.ReconcileResult
	if err := client.Call(ctx, "reconcile.run", nil, "", struct{}{}, &res); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "Reconciled %d vhosts; %d files changed.\n", res.Vhosts, len(res.Changed)); err != nil {
		return err
	}
	for _, p := range res.Changed {
		if _, err := fmt.Fprintln(stdout, "  "+p); err != nil {
			return err
		}
	}
	return nil
}
