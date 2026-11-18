package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/setup"
	"github.com/mbevc1/paddock/internal/system"
)

func runSetup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts setup.Options
	fs.StringVar(&opts.Hostname, "hostname", "", "panel hostname (required)")
	fs.StringVar(&opts.WWWDevice, "www-device", "", "block device for /srv/www (needed until it is mounted)")
	fs.BoolVar(&opts.Format, "format", false, "create XFS on an empty --www-device")
	php := fs.String("php", "8.3,8.4", "PHP versions to install, comma-separated")
	fs.StringVar(&opts.Email, "email", "", "ACME contact address (optional)")
	fs.StringVar(&opts.AdminUser, "admin", "admin", "username of the first admin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	if opts.Hostname == "" {
		return errors.New("--hostname is required")
	}
	opts.PHPVersions = strings.Split(*php, ",")
	if os.Geteuid() != 0 {
		return errors.New("paddock setup must run as root")
	}
	plat, err := detectPlatform()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	run := system.Exec{}
	files := render.Writer{}
	hostFS := &ops.HostFS{}
	d := &setup.Deps{
		Run: run, Files: files, FS: hostFS, Out: stdout,
		Host: &ops.Host{Run: run, Files: files, FS: hostFS, Platform: plat, Log: log},
		WebUser: func() (int, int, error) {
			uid, gid, err := lookupUser("paddock")
			return int(uid), gid, err
		},
	}
	return setup.Run(ctx, opts, d)
}
