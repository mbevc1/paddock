package ops

import (
	"bytes"
	"context"
	"strings"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

const (
	defaultLogLines = 200
	maxLogLines     = 1000
	// maxLogBytes bounds what one read takes from the end of a log.
	maxLogBytes = 256 << 10
)

// logFiles maps the log names callers may ask for to files in the vhost's logs directory.
var logFiles = map[string]string{
	"access": "access.log",
	"error":  "error.log",
	"php":    "php-error.log",
	"fpm":    "php-fpm.log",
}

// VhostLogArgs are the arguments of vhost.log.tail. Lines defaults to 200.
type VhostLogArgs struct {
	VhostID string `json:"vhost_id"`
	Log     string `json:"log"`
	Lines   int    `json:"lines"`
}

// VhostLog is the end of one log; Truncated is true when the log holds earlier lines.
type VhostLog struct {
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"`
}

func registerLogs(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "vhost.log.tail", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[VhostLogArgs](c)
		if err != nil {
			return nil, err
		}
		file, ok := logFiles[args.Log]
		if !ok {
			return nil, api.Errorf(api.CodeInvalidArgument, "unknown log %q", args.Log)
		}
		lines := args.Lines
		if lines == 0 {
			lines = defaultLogLines
		}
		if lines < 1 || lines > maxLogLines {
			return nil, api.Errorf(api.CodeInvalidArgument, "lines must be between 1 and %d", maxLogLines)
		}
		sv, err := loadVhost(ctx, store, c.Actor, args.VhostID)
		if err != nil {
			return nil, err
		}
		data, cut, err := h.FS.Tail(BaseWWW, sv.ID+"/logs/"+file, sv.UID, maxLogBytes)
		if err != nil {
			h.logger().Warn("reading a vhost log failed", "vhost", sv.ID, "log", file, "err", err)
			return nil, api.Errorf(api.CodeInvalidArgument, "%s cannot be read", file)
		}
		out, more := logLines(data, cut, lines)
		return VhostLog{Lines: out, Truncated: more}, nil
	}})
}

// logLines returns the last n lines of data; the result is truncated when data was cut short
// or held more than n lines.
func logLines(data []byte, cut bool, n int) ([]string, bool) {
	data = bytes.TrimRight(data, "\n")
	if len(data) == 0 {
		return []string{}, cut
	}
	all := strings.Split(string(data), "\n")
	if len(all) > n {
		return all[len(all)-n:], true
	}
	return all, cut
}
