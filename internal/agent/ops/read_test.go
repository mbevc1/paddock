package ops

import (
	"context"
	"strings"
	"testing"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/mariadb"
	"github.com/mbevc1/paddock/internal/state"
)

func TestReadOperations(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	if err := web.Call(ctx, "db.create", owner, "", DBArgs{VhostID: "v00001", Suffix: "app"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := web.Call(ctx, "dbuser.create", owner, "", DBUserCreateArgs{VhostID: "v00001", Suffix: "ro", Grants: mariadb.PrivilegesRead}, nil); err != nil {
		t.Fatal(err)
	}
	if v := runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Keys: []string{newSSHKey(t, "k")}}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	other, err := e.store.CreateOwner(ctx, "other", state.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	stranger := &api.Actor{UserID: 9, Role: api.RoleOwner, OwnerID: other.ID}

	var list []VhostView
	if err := web.Call(ctx, "vhost.list", owner, "", VhostListArgs{OwnerID: other.ID}, &list); err != nil || len(list) != 1 ||
		list[0].Primary != "shop.example.com" || list[0].Aliases[0] != "www.shop.example.com" {
		t.Errorf("owner's list = %+v, %v", list, err)
	}
	if err := web.Call(ctx, "vhost.list", stranger, "", VhostListArgs{OwnerID: owner.OwnerID}, &list); err != nil || len(list) != 0 {
		t.Errorf("stranger's list = %+v, %v", list, err)
	}

	var d VhostDetail
	if err := web.Call(ctx, "vhost.get", owner, "", VhostIDArgs{VhostID: "v00001"}, &d); err != nil {
		t.Fatal(err)
	}
	if d.Cert.Source != state.CertACME || len(d.Databases) != 1 || len(d.DBUsers) != 1 || d.Access == nil ||
		d.Access.Account != "v00001" || len(d.Access.Keys) != 1 {
		t.Errorf("detail = %+v", d)
	}
	wantCode(t, web.Call(ctx, "vhost.get", stranger, "", VhostIDArgs{VhostID: "v00001"}, nil), api.CodeNotFound)

	var versions []string
	if err := web.Call(ctx, "php.version.list", owner, "", struct{}{}, &versions); err != nil || len(versions) != 2 {
		t.Errorf("versions = %v, %v", versions, err)
	}
	var ov OwnerView
	if err := web.Call(ctx, "owner.get", owner, "", OwnerIDArgs{OwnerID: owner.OwnerID}, &ov); err != nil || ov.Limits.MaxVhosts != 5 {
		t.Errorf("owner.get = %+v, %v", ov, err)
	}
	wantCode(t, web.Call(ctx, "owner.get", stranger, "", OwnerIDArgs{OwnerID: owner.OwnerID}, nil), api.CodeNotFound)
	wantCode(t, web.Call(ctx, "owner.list", owner, "", struct{}{}, nil), api.CodeForbidden)
	wantCode(t, web.Call(ctx, "audit.list", owner, "", AuditListArgs{}, nil), api.CodeForbidden)

	admin := adminSession(t, e, web)
	var owners []OwnerView
	if err := web.Call(ctx, "owner.list", admin, "", struct{}{}, &owners); err != nil || len(owners) != 2 {
		t.Errorf("owner.list = %+v, %v", owners, err)
	}
	var audit []state.AuditEntry
	if err := web.Call(ctx, "audit.list", admin, "", AuditListArgs{Limit: 5}, &audit); err != nil || len(audit) != 5 {
		t.Errorf("audit.list = %d entries, %v", len(audit), err)
	}

	impersonated := &api.Actor{UserID: admin.UserID, Role: api.RoleOwner, OwnerID: owner.OwnerID, ImpersonatedBy: admin.UserID}
	if err := web.Call(ctx, "vhost.list", impersonated, "", VhostListArgs{}, &list); err != nil || len(list) != 1 {
		t.Errorf("impersonated list = %+v, %v", list, err)
	}
	entries, err := e.store.ListAudit(ctx, 0, 1)
	if err != nil || !strings.Contains(entries[0].Actor, `"impersonated_by":1`) {
		t.Errorf("audit actor = %+v, %v", entries, err)
	}
}

func TestVhostUpdateAliases(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	if v := runJob(t, web, "vhost.update", owner, VhostUpdateArgs{VhostID: "v00001", Aliases: []string{"shop.example.org"}}); v.Status != state.JobSucceeded {
		t.Fatalf("update: %+v", v)
	}
	front := frontConfig(t, e)
	if !strings.Contains(front, "MDomain shop.example.com shop.example.org") || strings.Contains(front, "www.shop.example.com") {
		t.Errorf("front:\n%s", front)
	}
	if d, _ := e.store.Domains(ctx, 1); len(d) != 2 || d[1].Name != "shop.example.org" {
		t.Errorf("domains = %+v", d)
	}

	e.run.On("/usr/sbin/apachectl").Fail("Syntax error").Times(1)
	wantJobError(t, runJob(t, web, "vhost.update", owner, VhostUpdateArgs{VhostID: "v00001", Aliases: []string{"x.example.com"}}), api.CodeApplyFailed)
	if d, _ := e.store.Domains(ctx, 1); len(d) != 2 || d[1].Name != "shop.example.org" {
		t.Errorf("aliases after a failed update = %+v", d)
	}
	wantJobError(t, runJob(t, web, "vhost.update", owner, VhostUpdateArgs{VhostID: "v00001", Aliases: []string{"bad domain"}}), api.CodeInvalidArgument)
}
