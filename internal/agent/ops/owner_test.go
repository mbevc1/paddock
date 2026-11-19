package ops

import (
	"context"
	"testing"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/state"
)

func ptr[T any](v T) *T { return &v }

// adminSession enrolls admin 1 and opens their window, so later calls need no code.
func adminSession(t *testing.T, e *env, web *agent.Client) *api.Actor {
	t.Helper()
	ctx := context.Background()
	var enrolled TOTPEnrollment
	if err := e.client(0).Call(ctx, "admin.add", nil, "", AdminAddArgs{UserID: 1, Username: "admin"}, &enrolled); err != nil {
		t.Fatal(err)
	}
	code := auth.TOTPCode(secretFromURI(t, enrolled.TOTPURI), auth.TOTPStep(e.now))
	if err := web.Call(ctx, "admin.totp.verify", nil, "", TOTPVerifyArgs{UserID: 1, Code: code}, nil); err != nil {
		t.Fatal(err)
	}
	return &api.Actor{UserID: 1, Role: api.RoleAdmin}
}

func TestOwnerOperations(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	web := e.client(webUID)
	admin := adminSession(t, e, web)

	var created OwnerCreated
	args := OwnerCreateArgs{Name: "Acme Ltd", Limits: LimitsArgs{MaxVhosts: ptr(1), PHPVersions: ptr([]string{"8.3"})}}
	if err := web.Call(ctx, "owner.create", admin, "", args, &created); err != nil {
		t.Fatal(err)
	}
	l, err := e.store.GetLimits(ctx, created.OwnerID)
	if err != nil || l.MaxVhosts != 1 || l.DiskMB != 10240 || len(l.PHPVersions) != 1 {
		t.Errorf("limits = %+v, %v", l, err)
	}
	wantCode(t, web.Call(ctx, "owner.create", admin, "", args, nil), api.CodeConflict)

	for name, bad := range map[string]OwnerCreateArgs{
		"empty name":      {Name: ""},
		"control in name": {Name: "a\nb"},
		"negative vhosts": {Name: "x", Limits: LimitsArgs{MaxVhosts: ptr(-1)}},
		"zero memory":     {Name: "x", Limits: LimitsArgs{MemoryMaxMB: ptr(0)}},
		"unknown PHP":     {Name: "x", Limits: LimitsArgs{PHPVersions: ptr([]string{"7.4"})}},
		"duplicate PHP":   {Name: "x", Limits: LimitsArgs{PHPVersions: ptr([]string{"8.3", "8.3"})}},
		"huge disk":       {Name: "x", Limits: LimitsArgs{DiskMB: ptr(1 << 31)}},
	} {
		t.Run(name, func(t *testing.T) {
			wantCode(t, web.Call(ctx, "owner.create", admin, "", bad, nil), api.CodeInvalidArgument)
		})
	}
	owner := &api.Actor{UserID: 7, Role: api.RoleOwner, OwnerID: created.OwnerID}
	wantCode(t, web.Call(ctx, "owner.create", owner, "", OwnerCreateArgs{Name: "Mine"}, nil), api.CodeForbidden)

	set := OwnerLimitsArgs{OwnerID: created.OwnerID, Limits: LimitsArgs{MaxDatabases: ptr(3)}}
	if err := web.Call(ctx, "owner.limits.set", admin, "", set, nil); err != nil {
		t.Fatal(err)
	}
	if l, _ := e.store.GetLimits(ctx, created.OwnerID); l.MaxDatabases != 3 || l.MaxVhosts != 1 {
		t.Errorf("partial limits update = %+v", l)
	}
	wantCode(t, web.Call(ctx, "owner.limits.set", admin, "", OwnerLimitsArgs{OwnerID: 999}, nil), api.CodeNotFound)

	if err := web.Call(ctx, "owner.update", admin, "", OwnerUpdateArgs{OwnerID: created.OwnerID, Name: "Acme Group"}, nil); err != nil {
		t.Fatal(err)
	}

	if err := e.store.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.CreateVhost(ctx, created.OwnerID, "8.3", "a.example.com", nil); err != nil {
		t.Fatal(err)
	}
	wantCode(t, web.Call(ctx, "owner.delete", admin, "", OwnerIDArgs(created), nil), api.CodeConflict)

	var other OwnerCreated
	if err := web.Call(ctx, "owner.create", admin, "", OwnerCreateArgs{Name: "Empty"}, &other); err != nil {
		t.Fatal(err)
	}
	if err := web.Call(ctx, "owner.delete", admin, "", OwnerIDArgs(other), nil); err != nil {
		t.Errorf("delete owner without vhosts: %v", err)
	}
}

// TestLimitExceededReachesCaller checks that a quota failure in the state store arrives as
// limit_exceeded with the limit in the message, for every counted resource.
func TestLimitExceededReachesCaller(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	l := state.DefaultLimits()
	l.MaxVhosts, l.MaxDatabases, l.MaxAccessAccounts = 1, 1, 1
	o, err := e.store.CreateOwner(ctx, "acme", l)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	v, err := e.store.CreateVhost(ctx, o.ID, "8.3", "a.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateDatabase(ctx, v.N, "v00001_a"); err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateAccessAccount(ctx, v.N, "v00001"); err != nil {
		t.Fatal(err)
	}
	e.reg.Register(agent.Op{Name: "test.consume", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[struct {
			What string `json:"what"`
		}](c)
		if err != nil {
			return nil, err
		}
		switch args.What {
		case "vhost":
			_, err = e.store.CreateVhost(ctx, o.ID, "8.3", "b.example.com", nil)
		case "database":
			err = e.store.CreateDatabase(ctx, v.N, "v00001_b")
		case "access":
			err = e.store.CreateAccessAccount(ctx, v.N, "v00001_b")
		}
		return nil, err
	}})
	web := e.client(webUID)
	owner := &api.Actor{UserID: 7, Role: api.RoleOwner, OwnerID: o.ID}
	for what, want := range map[string]string{
		"vhost":    "vhost limit reached (1)",
		"database": "database limit reached (1)",
		"access":   "access account limit reached (1)",
	} {
		err := web.Call(ctx, "test.consume", owner, "", map[string]string{"what": what}, nil)
		wantCode(t, err, api.CodeLimitExceeded)
		if apiErr := api.AsError(err); apiErr == nil || apiErr.Message != want {
			t.Errorf("%s: message = %v, want %q", what, err, want)
		}
	}
}
