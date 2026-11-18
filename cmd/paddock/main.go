// Command paddock is the Paddock hosting panel: a root agent that changes the host and a web
// panel that drives it.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

var errNotImplemented = errors.New("not implemented yet")

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout, stderr io.Writer) error
}

func commands() []command {
	return []command{
		{"agent", "run the root agent on /run/paddock/agent.sock", runAgent},
		{"web", "run the web panel (as user paddock)", runWeb},
		{"setup", "configure this host for Paddock (root)", runSetup},
		{"teardown", "remove all vhosts and Paddock's host configuration", notImplemented},
		{"reconcile", "re-render and re-apply everything from state.db (root)", runReconcile},
		{"admin", "add an admin, reset an admin's TOTP, or reset a password (root)", runAdmin},
		{"agent-notify", "tell the agent mod_md renewed certificates (MDNotifyCmd)", runAgentNotify},
		{"version", "print the version", printVersion},
	}
}

func notImplemented(context.Context, []string, io.Writer, io.Writer) error {
	return errNotImplemented
}

func printVersion(_ context.Context, _ []string, stdout, _ io.Writer) error {
	_, err := fmt.Fprintf(stdout, "paddock %s\n", version)
	return err
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: paddock <command> [arguments]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-13s %s\n", c.name, c.summary)
	}
}

// run returns the process exit code: 0 on success, 1 when a command fails, 2 on usage errors.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	name := args[0]
	if name == "help" || name == "-h" || name == "--help" {
		usage(stdout)
		return 0
	}
	for _, c := range commands() {
		if c.name != name {
			continue
		}
		if err := c.run(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "paddock %s: %v\n", name, err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stderr, "paddock: unknown command %q\n\n", name)
	usage(stderr)
	return 2
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
