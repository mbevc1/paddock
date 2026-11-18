// Package agent implements the root agent: the Unix socket server, caller checks, operation
// dispatch, audit, and background jobs.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/mbevc1/paddock/internal/api"
)

// Class says who may call an operation (§4).
type Class int

// Operation classes.
const (
	// ClassOwner operations run on behalf of a web user; handlers scope them to the actor.
	ClassOwner Class = iota + 1
	// ClassAdmin operations need an admin actor with a fresh, agent-verified TOTP code or an
	// open admin window.
	ClassAdmin
	// ClassGate operations verify a credential for any user ID; only the web process or root
	// may call them.
	ClassGate
	// ClassSystem operations serve the web process itself, never on behalf of a user.
	ClassSystem
	// ClassRoot operations are root CLI commands, such as adding an admin.
	ClassRoot
)

func (c Class) String() string {
	switch c {
	case ClassOwner:
		return "owner"
	case ClassAdmin:
		return "admin"
	case ClassGate:
		return "gate"
	case ClassSystem:
		return "system"
	case ClassRoot:
		return "root"
	}
	return fmt.Sprintf("Class(%d)", int(c))
}

// Call is one authorized invocation handed to a handler.
type Call struct {
	Op        string
	Actor     *api.Actor
	CallerUID uint32
	Args      json.RawMessage
}

// Handler performs an operation and returns its JSON-encodable result. Errors that are not
// *api.Error reach the caller as "internal" without detail.
type Handler func(ctx context.Context, c *Call) (any, error)

// Op describes one registered operation.
type Op struct {
	Name    string
	Class   Class
	Handler Handler
	// Long operations run as background jobs; the caller receives a job ID.
	Long bool
	// Secrets lists argument names to redact from the audit log, on top of the defaults.
	Secrets []string
}

// Registry maps operation names to their descriptions.
type Registry struct {
	ops map[string]Op
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{ops: map[string]Op{}} }

// Register adds an operation. It panics on a duplicate name or missing class or handler,
// since those are programming errors caught at startup.
func (r *Registry) Register(op Op) {
	if op.Name == "" || op.Handler == nil || op.Class < ClassOwner || op.Class > ClassRoot {
		panic(fmt.Sprintf("agent: incomplete operation %q", op.Name))
	}
	if _, dup := r.ops[op.Name]; dup {
		panic(fmt.Sprintf("agent: operation %q registered twice", op.Name))
	}
	r.ops[op.Name] = op
}

// Lookup returns a registered operation.
func (r *Registry) Lookup(name string) (Op, bool) {
	op, ok := r.ops[name]
	return op, ok
}

// DecodeArgs decodes c.Args into T, rejecting unknown fields and trailing data.
func DecodeArgs[T any](c *Call) (T, error) {
	var v T
	if len(c.Args) == 0 {
		return v, api.Errorf(api.CodeInvalidArgument, "arguments missing")
	}
	dec := json.NewDecoder(bytes.NewReader(c.Args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, api.Errorf(api.CodeInvalidArgument, "arguments do not match %s", c.Op)
	}
	if dec.More() {
		return v, api.Errorf(api.CodeInvalidArgument, "arguments do not match %s", c.Op)
	}
	return v, nil
}
