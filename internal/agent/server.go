package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

// SocketPath is where the agent listens.
const SocketPath = "/run/paddock/agent.sock"

// AdminGate decides whether an admin actor may run an admin operation now.
type AdminGate interface {
	Authorize(ctx context.Context, actor *api.Actor, code string) error
}

type denyAdmins struct{}

func (denyAdmins) Authorize(context.Context, *api.Actor, string) error {
	return api.Errorf(api.CodeForbidden, "admin operations are not available")
}

// Server answers requests on the agent socket.
type Server struct {
	// WebUID is the UID of user paddock; with root, the only caller allowed.
	WebUID   uint32
	Registry *Registry
	Store    *state.Store
	// Gate authorizes admin operations; nil denies them all.
	Gate AdminGate
	Log  *slog.Logger
	// PeerUID identifies the caller; nil means SO_PEERCRED. Tests replace it because they
	// cannot change their own UID.
	PeerUID func(*net.UnixConn) (uint32, error)

	jobs sync.WaitGroup
	// jobCtx outlives connections so jobs finish after the caller hangs up.
	jobCtx  context.Context
	jobOnce sync.Once
}

func (s *Server) initJobs(ctx context.Context) {
	s.jobOnce.Do(func() { s.jobCtx = context.WithoutCancel(ctx) })
}

func (s *Server) logger() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

func (s *Server) gate() AdminGate {
	if s.Gate == nil {
		return denyAdmins{}
	}
	return s.Gate
}

// Listen creates the socket at path, replacing a stale socket, with owner root, group gid,
// and mode 0660.
func Listen(path string, gid int) (*net.UnixListener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	if err := os.Chown(path, 0, gid); err != nil {
		_ = l.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil { // #nosec G302 -- the web process connects through group paddock.
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// Serve accepts connections until ctx ends, then waits for running jobs.
func (s *Server) Serve(ctx context.Context, l *net.UnixListener) error {
	s.initJobs(ctx)
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	var conns sync.WaitGroup
	defer func() {
		conns.Wait()
		s.jobs.Wait()
	}()
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		conns.Go(func() { s.ServeConn(ctx, conn) })
	}
}

// ServeConn answers requests on one connection until it closes or ctx ends.
func (s *Server) ServeConn(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	s.initJobs(ctx)
	identify := s.PeerUID
	if identify == nil {
		identify = peerUID
	}
	uid, err := identify(conn)
	if err != nil {
		s.logger().Warn("peer credentials unavailable", "err", err)
		return
	}
	if uid != 0 && uid != s.WebUID {
		s.logger().Warn("connection from forbidden UID", "uid", uid)
		_ = writeResponse(conn, api.Response{Error: api.Errorf(api.CodeForbidden, "caller not allowed")})
		return
	}

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), api.MaxRequestBytes)
	for sc.Scan() {
		resp := s.handle(ctx, uid, sc.Bytes())
		if err := writeResponse(conn, resp); err != nil {
			return
		}
	}
	if errors.Is(sc.Err(), bufio.ErrTooLong) {
		_ = writeResponse(conn, api.Response{Error: api.Errorf(api.CodeInvalidArgument,
			"request larger than %d bytes", api.MaxRequestBytes)})
	}
}

func writeResponse(w io.Writer, resp api.Response) error {
	resp.OK = resp.Error == nil
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func (s *Server) handle(ctx context.Context, uid uint32, line []byte) api.Response {
	var req api.Request
	if err := json.Unmarshal(line, &req); err != nil {
		return api.Response{Error: api.Errorf(api.CodeInvalidArgument, "malformed request")}
	}
	resp := api.Response{ID: req.ID}
	op, ok := s.Registry.Lookup(req.Op)
	if !ok {
		resp.Error = api.Errorf(api.CodeInvalidArgument, "unknown operation %q", req.Op)
		return resp
	}
	call := &Call{Op: op.Name, Actor: req.Actor, CallerUID: uid, Args: req.Args}

	var result any
	err := s.authorize(ctx, op, call, req.AdminTOTP)
	if err == nil {
		if op.Long {
			result, err = s.startJob(op, call)
		} else {
			result, err = op.Handler(ctx, call)
		}
	}
	apiErr := s.toAPIError(op.Name, err)
	s.audit(ctx, op, call, apiErr)
	if apiErr != nil {
		resp.Error = apiErr
		return resp
	}
	if result != nil {
		b, err := json.Marshal(result)
		if err != nil {
			resp.Error = s.toAPIError(op.Name, err)
			return resp
		}
		resp.Result = b
	}
	return resp
}

func (s *Server) authorize(ctx context.Context, op Op, c *Call, code string) error {
	switch op.Class {
	case ClassRoot:
		if c.CallerUID != 0 || c.Actor != nil {
			return api.Errorf(api.CodeForbidden, "%s is for root only", op.Name)
		}
	case ClassSystem:
		if c.CallerUID != s.WebUID || c.Actor != nil {
			return api.Errorf(api.CodeForbidden, "%s is for the web process only", op.Name)
		}
	case ClassGate:
		if c.Actor != nil {
			return api.Errorf(api.CodeInvalidArgument, "%s takes no actor", op.Name)
		}
	case ClassOwner, ClassAdmin:
		if err := checkActor(c.Actor); err != nil {
			return err
		}
		if op.Class == ClassAdmin {
			if c.Actor.Role != api.RoleAdmin {
				return api.Errorf(api.CodeForbidden, "%s needs an admin", op.Name)
			}
			return s.gate().Authorize(ctx, c.Actor, code)
		}
	default:
		return api.Errorf(api.CodeInternal, "operation has no class")
	}
	return nil
}

func checkActor(a *api.Actor) error {
	if a == nil || a.UserID < 1 {
		return api.Errorf(api.CodeInvalidArgument, "actor missing")
	}
	switch a.Role {
	case api.RoleOwner:
		if a.OwnerID < 1 {
			return api.Errorf(api.CodeInvalidArgument, "owner actor without owner_id")
		}
	case api.RoleAdmin:
	default:
		return api.Errorf(api.CodeInvalidArgument, "unknown role")
	}
	return nil
}

// toAPIError maps an error for the caller and logs internal detail without returning it.
func (s *Server) toAPIError(op string, err error) *api.Error {
	if err == nil {
		return nil
	}
	if e := api.AsError(err); e != nil {
		return e
	}
	switch {
	case errors.Is(err, state.ErrNotFound):
		return api.Errorf(api.CodeNotFound, "not found")
	case errors.Is(err, state.ErrConflict):
		return api.Errorf(api.CodeConflict, "conflict")
	}
	s.logger().Error("operation failed", "op", op, "err", err)
	return api.Errorf(api.CodeInternal, "internal error")
}

func (s *Server) audit(ctx context.Context, op Op, c *Call, apiErr *api.Error) {
	result := "ok"
	if apiErr != nil {
		result = string(apiErr.Code)
	}
	s.auditResult(ctx, op, c, result)
}

func (s *Server) auditResult(ctx context.Context, op Op, c *Call, result string) {
	if s.Store == nil {
		return
	}
	if _, err := s.Store.AppendAudit(ctx, actorJSON(c), op.Name, redactArgs(c.Args, op.Secrets), result); err != nil {
		s.logger().Error("audit write failed", "op", op.Name, "err", err)
	}
}

func newJobID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) startJob(op Op, c *Call) (any, error) {
	if s.Store == nil {
		return nil, errors.New("jobs need a state store")
	}
	id, err := newJobID()
	if err != nil {
		return nil, err
	}
	var userID, ownerID int64
	if c.Actor != nil {
		userID, ownerID = c.Actor.UserID, c.Actor.OwnerID
	}
	ctx := s.jobCtx
	if err := s.Store.CreateJob(ctx, id, op.Name, userID, ownerID); err != nil {
		return nil, err
	}
	s.jobs.Go(func() { s.runJob(ctx, id, op, c) })
	return api.JobResult{JobID: id}, nil
}

func (s *Server) runJob(ctx context.Context, id string, op Op, c *Call) {
	if err := s.Store.UpdateJob(ctx, id, state.JobRunning, "", "", ""); err != nil {
		s.logger().Error("job update failed", "job", id, "err", err)
	}
	result, err := op.Handler(ctx, c)
	status, out, code, msg := state.JobSucceeded, "", "", ""
	if apiErr := s.toAPIError(op.Name, err); apiErr != nil {
		status, code, msg = state.JobFailed, string(apiErr.Code), apiErr.Message
	} else if result != nil {
		b, err := json.Marshal(result)
		if err != nil {
			status, code, msg = state.JobFailed, string(api.CodeInternal), "internal error"
		} else {
			out = string(b)
		}
	}
	if err := s.Store.UpdateJob(ctx, id, status, out, code, msg); err != nil {
		s.logger().Error("job update failed", "job", id, "err", err)
	}
	outcome := "ok"
	if code != "" {
		outcome = code
	}
	s.auditResult(ctx, op, c, "job "+id+": "+outcome)
}

// JobView is what job.get returns.
type JobView struct {
	ID     string          `json:"id"`
	Op     string          `json:"op"`
	Status state.JobStatus `json:"status"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *api.Error      `json:"error,omitempty"`
}

// RegisterJobGet adds job.get, which shows a job to its owner and to admins.
func (s *Server) RegisterJobGet() {
	s.Registry.Register(Op{Name: "job.get", Class: ClassOwner, Handler: func(ctx context.Context, c *Call) (any, error) {
		args, err := DecodeArgs[struct {
			JobID string `json:"job_id"`
		}](c)
		if err != nil {
			return nil, err
		}
		j, err := s.Store.GetJob(ctx, args.JobID)
		if errors.Is(err, state.ErrNotFound) || err == nil && c.Actor.Role != api.RoleAdmin && j.OwnerID != c.Actor.OwnerID {
			return nil, api.Errorf(api.CodeNotFound, "job not found")
		}
		if err != nil {
			return nil, err
		}
		v := JobView{ID: j.ID, Op: j.Op, Status: j.Status}
		if j.Result != "" {
			v.Result = json.RawMessage(j.Result)
		}
		if j.ErrorCode != "" {
			v.Error = &api.Error{Code: api.Code(j.ErrorCode), Message: j.ErrorMessage}
		}
		return v, nil
	}})
}
