package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mbevc1/paddock/internal/setup"
)

func runSetup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts setup.Options
	fs.StringVar(&opts.AdminUser, "admin", "admin", "username of the first admin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	if os.Geteuid() != 0 {
		return errors.New("paddock setup must run as root")
	}
	d := &setup.Deps{
		Out: stdout,
		WebUser: func() (int, int, error) {
			uid, gid, err := lookupUser("paddock")
			return int(uid), gid, err
		},
	}
	return setup.Run(ctx, opts, d)
}
