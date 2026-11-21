package ops

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

func TestServerHealth(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	until := time.Date(2027, 1, 30, 10, 0, 0, 0, time.UTC)
	e.host.MDStatus = func(context.Context) ([]MDDomain, error) {
		return []MDDomain{{Name: "shop.example.com", State: "certificate(rsa) is valid", NotAfter: until}}, nil
	}
	e.run.OnFunc(func(argv []string) bool {
		return slices.Contains(argv, "is-active") && strings.Contains(argv[len(argv)-1], "-fpm@v00001")
	}).Return(system.Result{ExitCode: 3}, &system.ExitError{Program: "systemctl", ExitCode: 3})

	wantCode(t, web.Call(ctx, "server.health", owner, "", struct{}{}, nil), api.CodeForbidden)

	admin := adminSession(t, e, web)
	var got []VhostHealth
	if err := web.Call(ctx, "server.health", admin, "", struct{}{}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("health = %+v", got)
	}
	h := got[0]
	if h.ID != "v00001" || h.Primary != "shop.example.com" || h.OwnerID != owner.OwnerID ||
		h.Backend != UnitActive || h.FPM != UnitInactive ||
		h.Cert.Source != state.CertACME || h.Cert.NotAfter == nil || !h.Cert.NotAfter.Equal(until) {
		t.Errorf("health = %+v", h)
	}
}

func TestServerHealthWithoutMDStatus(t *testing.T) {
	ctx := context.Background()
	e, web, _, _ := activeVhost(t)
	e.host.MDStatus = func(context.Context) ([]MDDomain, error) { return nil, errors.New("connection refused") }
	admin := adminSession(t, e, web)
	var got []VhostHealth
	if err := web.Call(ctx, "server.health", admin, "", struct{}{}, &got); err != nil || len(got) != 1 ||
		got[0].Cert.Error != "certificate status unavailable" {
		t.Errorf("health = %+v, %v", got, err)
	}
}

func TestServerHealthSkipsUnitsOfInactiveVhosts(t *testing.T) {
	ctx := context.Background()
	e, web, _, _ := activeVhost(t)
	e.host.MDStatus = func(context.Context) ([]MDDomain, error) { return nil, nil }
	if err := e.store.SetVhostStatus(ctx, 1, state.VhostSuspended); err != nil {
		t.Fatal(err)
	}
	admin := adminSession(t, e, web)
	before := len(e.run.Calls())
	var got []VhostHealth
	if err := web.Call(ctx, "server.health", admin, "", struct{}{}, &got); err != nil || len(got) != 1 ||
		got[0].Backend != "" || got[0].FPM != "" {
		t.Errorf("health = %+v, %v", got, err)
	}
	for _, c := range e.run.Calls()[before:] {
		if slices.Contains(c.Argv, "is-active") {
			t.Errorf("checked a unit of a suspended vhost: %v", c.Argv)
		}
	}
}
