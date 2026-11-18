package web

import (
	"context"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
)

// Agent is the web process's only way to read or change the host.
type Agent interface {
	Call(ctx context.Context, op string, actor *api.Actor, adminTOTP string, args, result any) error
}

// DialAgent opens one connection per call, so concurrent requests never share a stream.
type DialAgent struct {
	Socket string
}

// Call runs one agent operation.
func (d DialAgent) Call(ctx context.Context, op string, actor *api.Actor, adminTOTP string, args, result any) error {
	c, err := agent.Dial(ctx, d.Socket)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Call(ctx, op, actor, adminTOTP, args, result)
}
