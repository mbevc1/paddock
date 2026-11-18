package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/mbevc1/paddock/internal/api"
)

// Client sends requests over one agent connection. It is safe for concurrent use; requests
// are serialized on the connection.
type Client struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
	seq    int
}

// Dial connects to the agent socket.
func Dial(ctx context.Context, path string) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("connect to agent: %w", err)
	}
	return NewClient(conn), nil
}

// NewClient wraps an established connection to the agent.
func NewClient(conn net.Conn) *Client {
	return &Client{conn: conn, reader: bufio.NewReaderSize(conn, 64*1024)}
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Call runs op and decodes its result into result, which may be nil. Agent errors come back
// as *api.Error.
func (c *Client) Call(ctx context.Context, op string, actor *api.Actor, adminTOTP string, args, result any) error {
	var raw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		raw = b
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	req := api.Request{ID: "c" + strconv.Itoa(c.seq), Op: op, Actor: actor, AdminTOTP: adminTOTP, Args: raw}
	line, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = c.conn.Close() })
	defer stop()
	if _, err := c.conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("send to agent: %w", err)
	}
	respLine, err := c.reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read from agent: %w", err)
	}
	var resp api.Response
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return fmt.Errorf("decode agent response: %w", err)
	}
	if resp.ID != req.ID && resp.Error == nil {
		return fmt.Errorf("agent answered request %q, want %q", resp.ID, req.ID)
	}
	if !resp.OK {
		if resp.Error == nil {
			return api.Errorf(api.CodeInternal, "agent returned no error detail")
		}
		return resp.Error
	}
	if result != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, result)
	}
	return nil
}
