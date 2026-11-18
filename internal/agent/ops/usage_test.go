package ops

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/mariadb"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

const xfsReport = "report -p -N -n -b"

// scriptUsage makes the next measurement report diskMB of files and dbMB of databases for
// vhost 1.
func scriptUsage(e *env, diskMB, dbMB int64) {
	e.run.OnFunc(func(argv []string) bool { return len(argv) > 3 && argv[3] == xfsReport }).
		Return(system.Result{Stdout: fmt.Appendf(nil, "#1  %d  0  102400  00 [--------]\n", diskMB*1024)}, nil).Times(1)
	e.run.OnCall(func(c system.Call) bool { return string(c.Stdin) == mariadb.AllDatabaseSizes() }).
		Return(system.Result{Stdout: fmt.Appendf(nil, "v00001_wp\t%d\n", dbMB<<20)}, nil).Times(1)
}

func eventKinds(t *testing.T, e *env) []state.EventKind {
	t.Helper()
	events, err := e.store.ListEvents(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []state.EventKind
	for _, ev := range events {
		kinds = append(kinds, ev.Kind)
	}
	return kinds
}

// sqlSince returns the stdin of every mariadb call after mark.
func sqlSince(e *env, mark int) []string {
	var out []string
	for _, c := range e.run.Calls()[mark:] {
		if c.Argv[0] == "/usr/bin/mariadb" && string(c.Stdin) != mariadb.AllDatabaseSizes() {
			out = append(out, string(c.Stdin))
		}
	}
	return out
}

func TestQuotaWarningAndEnforcement(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	l := state.DefaultLimits()
	l.DiskMB = 100
	if err := e.store.SetLimits(ctx, owner.OwnerID, l); err != nil {
		t.Fatal(err)
	}
	if err := web.Call(ctx, "db.create", owner, "", DBArgs{VhostID: "v00001", Suffix: "wp"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, u := range []DBUserCreateArgs{{VhostID: "v00001", Suffix: "rw", Grants: mariadb.PrivilegesAll}, {VhostID: "v00001", Suffix: "ro", Grants: mariadb.PrivilegesRead}} {
		if err := web.Call(ctx, "dbuser.create", owner, "", u, nil); err != nil {
			t.Fatal(err)
		}
	}
	scan := func(diskMB, dbMB int64) int {
		t.Helper()
		scriptUsage(e, diskMB, dbMB)
		mark := len(e.run.Calls())
		if err := ScanUsage(ctx, e.store, e.host); err != nil {
			t.Fatalf("scan at %d+%d MB: %v", diskMB, dbMB, err)
		}
		return mark
	}

	scan(50, 10)
	if kinds := eventKinds(t, e); len(kinds) != 0 {
		t.Errorf("events at 60%% = %v", kinds)
	}

	scan(85, 10)
	if kinds := eventKinds(t, e); !slices.Equal(kinds, []state.EventKind{state.EventQuotaWarning}) {
		t.Errorf("events at 95%% = %v", kinds)
	}

	mark := scan(95, 10)
	if kinds := eventKinds(t, e); !slices.Equal(kinds, []state.EventKind{state.EventQuotaWarning, state.EventQuotaExceeded}) {
		t.Errorf("events at 105%% = %v", kinds)
	}
	if !slices.Contains(e.run.Commands()[mark:], "/usr/sbin/xfs_quota -x -c limit -p bhard=97280k 1 /srv/www") {
		t.Errorf("files not frozen: %q", e.run.Commands()[mark:])
	}
	revoked := sqlSince(e, mark)
	want := []string{
		"REVOKE INSERT, UPDATE, CREATE ON `v00001\\_wp`.* FROM 'v00001'@'localhost';\n",
		"REVOKE INSERT, UPDATE, CREATE ON `v00001\\_%`.* FROM 'v00001_rw'@'localhost';\n",
	}
	if !slices.Equal(revoked, want) {
		t.Errorf("revokes:\n got %q\nwant %q", revoked, want)
	}

	mark = scan(99, 10)
	if kinds := eventKinds(t, e); len(kinds) != 2 {
		t.Errorf("repeat scan over the limit added events: %v", kinds)
	}
	if got := sqlSince(e, mark); len(got) != 0 {
		t.Errorf("repeat scan changed grants: %q", got)
	}

	var usage OwnerUsage
	scriptUsage(e, 99, 10)
	if err := web.Call(ctx, "usage.get", owner, "", UsageArgs{VhostID: "v00001"}, &usage); err != nil {
		t.Fatal(err)
	}
	if usage.TotalBytes != 109<<20 || usage.LimitBytes != 100<<20 || len(usage.Vhosts) != 1 || usage.Vhosts[0].DBBytes != 10<<20 {
		t.Errorf("usage = %+v", usage)
	}

	mark = scan(40, 10)
	if kinds := eventKinds(t, e); !slices.Equal(kinds[2:], []state.EventKind{state.EventQuotaCleared}) {
		t.Errorf("events after cleanup = %v", kinds)
	}
	if !slices.Contains(e.run.Commands()[mark:], "/usr/sbin/xfs_quota -x -c limit -p bhard=100m 1 /srv/www") {
		t.Errorf("disk limit not restored: %q", e.run.Commands()[mark:])
	}
	if got := sqlSince(e, mark); len(got) != 2 || !strings.HasPrefix(got[0], "GRANT INSERT, UPDATE, CREATE") {
		t.Errorf("grants not restored: %q", got)
	}
	if q, _ := e.store.GetQuotaState(ctx, owner.OwnerID); q.Warned || q.Enforced {
		t.Errorf("quota state after cleanup = %+v", q)
	}
}

func TestUsageScoping(t *testing.T) {
	ctx := context.Background()
	_, web, owner, _ := activeVhost(t)
	stranger := &api.Actor{UserID: 9, Role: api.RoleOwner, OwnerID: 999}
	wantCode(t, web.Call(ctx, "usage.get", stranger, "", UsageArgs{VhostID: "v00001"}, nil), api.CodeNotFound)
	wantCode(t, web.Call(ctx, "usage.get", stranger, "", UsageArgs{OwnerID: owner.OwnerID}, nil), api.CodeForbidden)
	wantCode(t, web.Call(ctx, "usage.get", owner, "", UsageArgs{}, nil), api.CodeInvalidArgument)
}

func TestParseProjectReport(t *testing.T) {
	got, err := parseProjectReport([]byte("#0  0  0  0  00 [--------]\n#12  2048  0  1048576  00 [--------]\n\nnoise\n"))
	if err != nil || got[12] != 2048*1024 || got[0] != 0 {
		t.Errorf("parseProjectReport = %v, %v", got, err)
	}
	if _, err := parseProjectReport([]byte("#x 1\n")); err == nil {
		t.Error("bad project accepted")
	}
}

func TestCertExpiryEvents(t *testing.T) {
	ctx := context.Background()
	e, _, _, _ := activeVhost(t)
	if err := e.store.SetCert(ctx, 1, state.Cert{Source: state.CertUpload, NotAfter: e.now.Add(5 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		scriptUsage(e, 1, 0)
		if err := ScanUsage(ctx, e.store, e.host); err != nil {
			t.Fatal(err)
		}
	}
	if kinds := eventKinds(t, e); !slices.Equal(kinds, []state.EventKind{state.EventCertExpiring}) {
		t.Errorf("events = %v, want one expiry warning a day", kinds)
	}
	e.now = e.now.Add(25 * time.Hour)
	scriptUsage(e, 1, 0)
	if err := ScanUsage(ctx, e.store, e.host); err != nil {
		t.Fatal(err)
	}
	if kinds := eventKinds(t, e); len(kinds) != 2 {
		t.Errorf("events a day later = %v", kinds)
	}
}

func TestEventsListAndSources(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	allowShell(t, e, owner.OwnerID)
	if v := runJob(t, web, "access.create", owner, AccessCreateArgs{VhostID: "v00001", Kind: state.AccessSFTP, Keys: []string{newSSHKey(t, "k")}}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	if err := e.client(0).Call(ctx, "front.md-renewed", nil, "", MDRenewedArgs{Domains: []string{"shop.example.com", "unknown.example.com"}}, nil); err != nil {
		t.Fatal(err)
	}
	e.run.On("/usr/sbin/apachectl").Fail("Syntax error").Times(1)
	wantCode(t, web.Call(ctx, "cert.upload", owner, "", func() CertUploadArgs {
		chain, key := testCert(t, e.now, "shop.example.com", "www.shop.example.com")
		return CertUploadArgs{VhostID: "v00001", ChainPEM: chain, KeyPEM: key}
	}(), nil), api.CodeApplyFailed)

	var page EventsPage
	if err := web.Call(ctx, "events.list", nil, "", EventsListArgs{Since: 0, Limit: 2}, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 || page.Events[0].Kind != state.EventSSHKeyAdded || page.Events[1].Kind != state.EventCertRenewed {
		t.Errorf("first page = %+v", page.Events)
	}
	var rest EventsPage
	if err := web.Call(ctx, "events.list", nil, "", EventsListArgs{Since: page.Next}, &rest); err != nil {
		t.Fatal(err)
	}
	if len(rest.Events) != 1 || rest.Events[0].Kind != state.EventApplyFailed || rest.Events[0].OwnerID != owner.OwnerID ||
		!strings.HasPrefix(rest.Events[0].Message, "cert.upload: ") {
		t.Errorf("second page = %+v", rest.Events)
	}
	wantCode(t, web.Call(ctx, "events.list", owner, "", EventsListArgs{}, nil), api.CodeForbidden)
}
