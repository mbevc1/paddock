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

const agentCallTimeout = 30 * time.Second

var errAdminUsage = errors.New("usage: paddock admin add -user-id N -username NAME | paddock admin totp-reset -user-id N")

func runAdmin(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errAdminUsage
	}
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", agent.SocketPath, "agent socket path")
	userID := fs.Int64("user-id", 0, "panel user ID of the admin")
	var username *string
	if args[0] == "add" {
		username = fs.String("username", "", "panel username of the admin")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 || *userID < 1 || username != nil && *username == "" {
		return errAdminUsage
	}

	var op string
	var callArgs any
	switch args[0] {
	case "add":
		op, callArgs = "admin.add", ops.AdminAddArgs{UserID: *userID, Username: *username}
	case "totp-reset":
		op, callArgs = "admin.totp.reset", ops.AdminUserArgs{UserID: *userID}
	default:
		return errAdminUsage
	}

	ctx, cancel := context.WithTimeout(ctx, agentCallTimeout)
	defer cancel()
	client, err := agent.Dial(ctx, *socket)
	if err != nil {
		return err
	}
	defer client.Close()
	var enrolled ops.TOTPEnrollment
	if err := client.Call(ctx, op, nil, "", callArgs, &enrolled); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Add this TOTP secret to the admin's authenticator app. It is shown only once:\n%s\n", enrolled.TOTPURI)
	return err
}
