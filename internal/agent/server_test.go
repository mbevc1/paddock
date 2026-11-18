package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
)

const webUID = 990

func socketPair(t *testing.T) (server, client *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int, name string) *net.UnixConn {
		f := os.NewFile(uintptr(fd), name)
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	return conn(fds[0], "server"), conn(fds[1], "client")
}

type harness struct {
	t      *testing.T
	srv    *Server
	store  *state.Store
	client *net.UnixConn
	reader *bufio.Reader
}

// start serves one connection whose peer appears to have callerUID.
func start(t *testing.T, callerUID uint32, configure func(*Server)) *harness {
	t.Helper()
	store, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv := &Server{WebUID: webUID, Registry: NewRegistry(), Store: store,
		PeerUID: func(*net.UnixConn) (uint32, error) { return callerUID, nil }}
	srv.RegisterJobGet()
	if configure != nil {
		configure(srv)
	}
	server, client := socketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.ServeConn(ctx, server)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		<-done
		srv.jobs.Wait()
	})
	return &harness{t: t, srv: srv, store: store, client: client, reader: bufio.NewReader(client)}
}

func (h *harness) send(line string) api.Response {
	h.t.Helper()
	if _, err := h.client.Write([]byte(line + "\n")); err != nil {
		h.t.Fatal(err)
	}
	return h.read()
}

func (h *harness) read() api.Response {
	h.t.Helper()
	if err := h.client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		h.t.Fatal(err)
	}
	line, err := h.reader.ReadBytes('\n')
	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}
	var resp api.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		h.t.Fatalf("decode %q: %v", line, err)
	}
	return resp
}

func (h *harness) request(req api.Request) api.Response {
	h.t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.send(string(b))
}

func wantCode(t *testing.T, resp api.Response, code api.Code) {
	t.Helper()
	if resp.OK || resp.Error == nil || resp.Error.Code != code {
		t.Errorf("response = %+v, want error %s", resp, code)
	}
}

var owner7 = &api.Actor{UserID: 7, Role: api.RoleOwner, OwnerID: 12}

func echoOp(name string, class Class) Op {
	return Op{Name: name, Class: class, Handler: func(_ context.Context, c *Call) (any, error) {
		return map[string]any{"caller": c.CallerUID}, nil
	}}
}

func TestPeerUIDOverSocketpair(t *testing.T) {
	server, client := socketPair(t)
	defer server.Close()
	defer client.Close()
	uid, err := peerUID(server)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint32(os.Getuid()); uid != want { // #nosec G115 -- UIDs fit in uint32.
		t.Errorf("peer UID = %d, want %d", uid, want)
	}
}

func TestForbiddenCallerUID(t *testing.T) {
	h := start(t, 1000, nil)
	resp := h.read()
	wantCode(t, resp, api.CodeForbidden)
	if _, err := h.reader.ReadByte(); err == nil {
		t.Error("connection stayed open for a forbidden UID")
	}
}

func TestProtocolErrors(t *testing.T) {
	h := start(t, webUID, func(s *Server) { s.Registry.Register(echoOp("ping", ClassOwner)) })

	wantCode(t, h.send(`{"id":"r1","op":"no.such.op"}`), api.CodeInvalidArgument)
	wantCode(t, h.send(`{"id":`), api.CodeInvalidArgument)

	resp := h.request(api.Request{ID: "r2", Op: "ping", Actor: owner7})
	if !resp.OK || resp.ID != "r2" || string(resp.Result) != `{"caller":990}` {
		t.Errorf("connection unusable after malformed JSON: %+v", resp)
	}

	big := `{"id":"r3","op":"ping","args":"` + strings.Repeat("a", api.MaxRequestBytes) + `"}`
	wantCode(t, h.send(big), api.CodeInvalidArgument)
	if _, err := h.reader.ReadByte(); err == nil {
		t.Error("connection stayed open after an oversized request")
	}
}

func TestClasses(t *testing.T) {
	ops := func(s *Server) {
		for _, op := range []Op{echoOp("own", ClassOwner), echoOp("adm", ClassAdmin), echoOp("gate", ClassGate),
			echoOp("sys", ClassSystem), echoOp("root", ClassRoot)} {
			s.Registry.Register(op)
		}
	}
	admin := &api.Actor{UserID: 1, Role: api.RoleAdmin}

	web := start(t, webUID, ops)
	for _, tc := range []struct {
		name string
		req  api.Request
		want api.Code
	}{
		{"owner op without actor", api.Request{Op: "own"}, api.CodeInvalidArgument},
		{"owner actor without owner_id", api.Request{Op: "own", Actor: &api.Actor{UserID: 7, Role: api.RoleOwner}}, api.CodeInvalidArgument},
		{"unknown role", api.Request{Op: "own", Actor: &api.Actor{UserID: 7, Role: "root"}}, api.CodeInvalidArgument},
		{"admin op from owner", api.Request{Op: "adm", Actor: owner7, AdminTOTP: "123456"}, api.CodeForbidden},
		{"admin op without gate", api.Request{Op: "adm", Actor: admin, AdminTOTP: "123456"}, api.CodeForbidden},
		{"system op on behalf of a user", api.Request{Op: "sys", Actor: owner7}, api.CodeForbidden},
		{"gate op with actor", api.Request{Op: "gate", Actor: owner7}, api.CodeInvalidArgument},
		{"root op from web", api.Request{Op: "root"}, api.CodeForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) { wantCode(t, web.request(tc.req), tc.want) })
	}
	for _, req := range []api.Request{{Op: "own", Actor: owner7}, {Op: "own", Actor: admin}, {Op: "sys"}, {Op: "gate"}} {
		if resp := web.request(req); !resp.OK {
			t.Errorf("%s as web: %+v", req.Op, resp)
		}
	}

	root := start(t, 0, ops)
	if resp := root.request(api.Request{Op: "root"}); !resp.OK {
		t.Errorf("root op as root: %+v", resp)
	}
	wantCode(t, root.request(api.Request{Op: "sys"}), api.CodeForbidden)
}

type allowCode string

func (a allowCode) Authorize(_ context.Context, _ *api.Actor, code string) error {
	if code != string(a) {
		return api.Errorf(api.CodeTOTPInvalid, "code rejected")
	}
	return nil
}

func TestAdminGateIsConsulted(t *testing.T) {
	h := start(t, webUID, func(s *Server) {
		s.Gate = allowCode("246810")
		s.Registry.Register(echoOp("adm", ClassAdmin))
	})
	admin := &api.Actor{UserID: 1, Role: api.RoleAdmin}
	wantCode(t, h.request(api.Request{Op: "adm", Actor: admin, AdminTOTP: "000000"}), api.CodeTOTPInvalid)
	if resp := h.request(api.Request{Op: "adm", Actor: admin, AdminTOTP: "246810"}); !resp.OK {
		t.Errorf("admin op with accepted code: %+v", resp)
	}
}

func TestAuditContent(t *testing.T) {
	h := start(t, webUID, func(s *Server) {
		s.Registry.Register(Op{Name: "access.create", Class: ClassOwner, Secrets: []string{"keys"},
			Handler: func(context.Context, *Call) (any, error) { return nil, nil }})
		s.Registry.Register(Op{Name: "boom", Class: ClassOwner,
			Handler: func(context.Context, *Call) (any, error) { return nil, errors.New("db at /secret/path exploded") }})
	})
	args := `{"vhost_id":"v00012","kind":"sftp","password":"hunter2-long-pass","keys":["ssh-ed25519 AAAA"],"nested":{"admin_totp":"123456"}}`
	if resp := h.send(`{"id":"a1","op":"access.create","actor":{"user_id":7,"role":"owner","owner_id":12},"admin_totp":"999999","args":` + args + `}`); !resp.OK {
		t.Fatalf("access.create: %+v", resp)
	}
	resp := h.request(api.Request{ID: "a2", Op: "boom", Actor: owner7})
	wantCode(t, resp, api.CodeInternal)
	if strings.Contains(resp.Error.Message, "/secret/path") {
		t.Errorf("internal detail leaked: %q", resp.Error.Message)
	}

	entries, err := h.store.ListAudit(context.Background(), 0, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
	boom, create := entries[0], entries[1]
	if boom.Op != "boom" || boom.Result != "internal" {
		t.Errorf("boom entry = %+v", boom)
	}
	if create.Op != "access.create" || create.Result != "ok" ||
		create.Actor != `{"caller_uid":990,"user_id":7,"role":"owner","owner_id":12}` {
		t.Errorf("create entry = %+v", create)
	}
	for _, secret := range []string{"hunter2", "123456", "999999", "AAAA"} {
		if strings.Contains(create.Args, secret) {
			t.Errorf("audit args leak %q: %s", secret, create.Args)
		}
	}
	if !strings.Contains(create.Args, `"vhost_id":"v00012"`) {
		t.Errorf("audit args lost plain values: %s", create.Args)
	}
}

func TestLongOperationRunsAsJob(t *testing.T) {
	release := make(chan struct{})
	h := start(t, webUID, func(s *Server) {
		s.Registry.Register(Op{Name: "php.version.install", Class: ClassOwner, Long: true,
			Handler: func(context.Context, *Call) (any, error) {
				<-release
				return map[string]string{"version": "8.4"}, nil
			}})
	})
	resp := h.request(api.Request{ID: "j1", Op: "php.version.install", Actor: owner7, Args: json.RawMessage(`{"version":"8.4"}`)})
	var job api.JobResult
	if !resp.OK || json.Unmarshal(resp.Result, &job) != nil || len(job.JobID) != 32 {
		t.Fatalf("job submission: %+v", resp)
	}
	jobArgs := json.RawMessage(`{"job_id":"` + job.JobID + `"}`)

	other := &api.Actor{UserID: 8, Role: api.RoleOwner, OwnerID: 13}
	wantCode(t, h.request(api.Request{Op: "job.get", Actor: other, Args: jobArgs}), api.CodeNotFound)
	wantCode(t, h.request(api.Request{Op: "job.get", Actor: owner7, Args: json.RawMessage(`{"job_id":"x","extra":1}`)}), api.CodeInvalidArgument)

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp := h.request(api.Request{Op: "job.get", Actor: owner7, Args: jobArgs})
		var v JobView
		if !resp.OK || json.Unmarshal(resp.Result, &v) != nil {
			t.Fatalf("job.get: %+v", resp)
		}
		if v.Status == state.JobSucceeded {
			if string(v.Result) != `{"version":"8.4"}` {
				t.Errorf("job result = %s", v.Result)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job still %s", v.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestListen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, os.Getgid()); err == nil {
		t.Error("Listen replaced a regular file")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	l, err := Listen(path, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode = %v, %v", fi.Mode().Perm(), err)
	}
	_ = l.Close()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket left behind after close: %v", err)
	}
}

func TestRegistryPanics(t *testing.T) {
	r := NewRegistry()
	r.Register(echoOp("x", ClassOwner))
	for name, op := range map[string]Op{
		"duplicate":  echoOp("x", ClassOwner),
		"no handler": {Name: "y", Class: ClassOwner},
		"no class":   {Name: "z", Handler: echoOp("z", ClassOwner).Handler},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: Register did not panic", name)
				}
			}()
			r.Register(op)
		}()
	}
}
