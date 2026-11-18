package ops

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/mariadb"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
)

// lastSQL returns the stdin of the most recent mariadb call.
func lastSQL(t *testing.T, e *env) string {
	t.Helper()
	calls := e.run.Calls()
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i].Argv[0] == "/usr/bin/mariadb" {
			return string(calls[i].Stdin)
		}
	}
	t.Fatal("no mariadb call")
	return ""
}

func TestPrimaryDBUserOnCreate(t *testing.T) {
	e, _, _, _ := activeVhost(t)
	sql := lastSQL(t, e)
	if !strings.HasPrefix(sql, "CREATE USER 'v00001'@'localhost' IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD('") ||
		!strings.HasSuffix(sql, "') WITH MAX_USER_CONNECTIONS 20;\n") {
		t.Errorf("primary user SQL = %q", sql)
	}
}

func TestDatabaseOperations(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)

	var res DatabaseResult
	if err := web.Call(ctx, "db.create", owner, "", DBArgs{VhostID: "v00001", Suffix: "wp"}, &res); err != nil || res.Database != "v00001_wp" {
		t.Fatalf("db.create = %+v, %v", res, err)
	}
	if sql := lastSQL(t, e); !strings.Contains(sql, "CREATE DATABASE `v00001_wp` CHARACTER SET utf8mb4") ||
		!strings.Contains(sql, "GRANT ALL PRIVILEGES ON `v00001\\_wp`.* TO 'v00001'@'localhost'") {
		t.Errorf("db.create SQL = %q", sql)
	}
	wantCode(t, web.Call(ctx, "db.create", owner, "", DBArgs{VhostID: "v00001", Suffix: "wp"}, nil), api.CodeConflict)
	for _, bad := range []string{"", "WP", "w_p", "w`p", strings.Repeat("a", 21)} {
		wantCode(t, web.Call(ctx, "db.create", owner, "", DBArgs{VhostID: "v00001", Suffix: bad}, nil), api.CodeInvalidArgument)
	}
	stranger := &api.Actor{UserID: 9, Role: api.RoleOwner, OwnerID: 999}
	wantCode(t, web.Call(ctx, "db.create", stranger, "", DBArgs{VhostID: "v00001", Suffix: "x"}, nil), api.CodeNotFound)

	e.run.On("/usr/bin/mariadb").Fail("ERROR 1007 (HY000): Can't create database").Times(1)
	wantCode(t, web.Call(ctx, "db.create", owner, "", DBArgs{VhostID: "v00001", Suffix: "shop"}, nil), api.CodeApplyFailed)
	if dbs, _ := e.store.ListDatabases(ctx, 1); len(dbs) != 1 {
		t.Errorf("failed create left state rows: %q", dbs)
	}

	l := state.DefaultLimits()
	l.MaxDatabases = 1
	if err := e.store.SetLimits(ctx, owner.OwnerID, l); err != nil {
		t.Fatal(err)
	}
	wantCode(t, web.Call(ctx, "db.create", owner, "", DBArgs{VhostID: "v00001", Suffix: "shop"}, nil), api.CodeLimitExceeded)

	wantCode(t, web.Call(ctx, "db.delete", owner, "", DBArgs{VhostID: "v00001", Suffix: "nope"}, nil), api.CodeNotFound)
	e.run.On("/usr/bin/mariadb").Return(system.Result{}, nil).Times(1)
	e.run.On("/usr/bin/mariadb").Fail("ERROR 1141 (42000) at line 1: There is no such grant defined").Times(1)
	if err := web.Call(ctx, "db.delete", owner, "", DBArgs{VhostID: "v00001", Suffix: "wp"}, nil); err != nil {
		t.Fatalf("db.delete with the grant already gone: %v", err)
	}
	if dbs, _ := e.store.ListDatabases(ctx, 1); len(dbs) != 0 {
		t.Errorf("database still recorded: %q", dbs)
	}
}

func TestDBUserOperations(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)

	var creds DBCredentials
	if err := web.Call(ctx, "dbuser.create", owner, "", DBUserCreateArgs{VhostID: "v00001", Suffix: "ro", Grants: mariadb.PrivilegesRead}, &creds); err != nil {
		t.Fatal(err)
	}
	if creds.User != "v00001_ro" || len(creds.Password) != 24 {
		t.Errorf("credentials = %+v", creds)
	}
	sql := lastSQL(t, e)
	if !strings.Contains(sql, "IDENTIFIED BY '"+creds.Password+"'") || !strings.Contains(sql, "GRANT SELECT, SHOW VIEW ON `v00001\\_%`.*") {
		t.Errorf("dbuser.create SQL = %q", sql)
	}
	for _, c := range e.run.Calls() {
		if strings.Contains(strings.Join(c.Argv, " "), creds.Password) {
			t.Error("password passed in argv")
		}
	}
	wantCode(t, web.Call(ctx, "dbuser.create", owner, "", DBUserCreateArgs{VhostID: "v00001", Suffix: "rw", Grants: "root"}, nil), api.CodeInvalidArgument)
	if _, err := e.store.GetDBUser(ctx, "v00001_rw"); !errors.Is(err, state.ErrNotFound) {
		t.Error("refused user recorded")
	}
	wantCode(t, web.Call(ctx, "dbuser.create", owner, "", DBUserCreateArgs{VhostID: "v00001", Suffix: "toolongname", Grants: mariadb.PrivilegesAll}, nil), api.CodeInvalidArgument)

	var reset DBCredentials
	if err := web.Call(ctx, "dbuser.password.reset", owner, "", DBArgs{VhostID: "v00001", Suffix: "ro"}, &reset); err != nil {
		t.Fatal(err)
	}
	if reset.Password == creds.Password || !strings.Contains(lastSQL(t, e), "ALTER USER 'v00001_ro'@'localhost' IDENTIFIED BY") {
		t.Errorf("reset = %+v, SQL %q", reset, lastSQL(t, e))
	}
	if err := web.Call(ctx, "dbuser.password.reset", owner, "", DBArgs{VhostID: "v00001"}, &reset); err != nil || reset.User != "v00001" {
		t.Fatalf("primary reset = %+v, %v", reset, err)
	}
	if sql := lastSQL(t, e); !strings.Contains(sql, "IDENTIFIED VIA unix_socket OR mysql_native_password") {
		t.Errorf("primary reset dropped unix_socket: %q", sql)
	}
	wantCode(t, web.Call(ctx, "dbuser.password.reset", owner, "", DBArgs{VhostID: "v00001", Suffix: "nope"}, nil), api.CodeNotFound)

	if err := web.Call(ctx, "dbuser.delete", owner, "", DBArgs{VhostID: "v00001", Suffix: "ro"}, nil); err != nil {
		t.Fatal(err)
	}
	if sql := lastSQL(t, e); sql != "DROP USER IF EXISTS 'v00001_ro'@'localhost';\n" {
		t.Errorf("dbuser.delete SQL = %q", sql)
	}

	entries, err := e.store.ListAudit(ctx, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if strings.Contains(en.Args, creds.Password) || strings.Contains(en.Args, reset.Password) {
			t.Errorf("audit entry %s contains a password", en.Op)
		}
	}
}

func TestVhostDeleteDropsDatabases(t *testing.T) {
	ctx := context.Background()
	e, web, owner, _ := activeVhost(t)
	if err := web.Call(ctx, "db.create", owner, "", DBArgs{VhostID: "v00001", Suffix: "wp"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := web.Call(ctx, "dbuser.create", owner, "", DBUserCreateArgs{VhostID: "v00001", Suffix: "ro", Grants: mariadb.PrivilegesRead}, nil); err != nil {
		t.Fatal(err)
	}
	if v := runJob(t, web, "vhost.delete", owner, VhostDeleteArgs{VhostID: "v00001", Confirm: "shop.example.com"}); v.Status != state.JobSucceeded {
		t.Fatal(v)
	}
	want := "DROP DATABASE IF EXISTS `v00001_wp`;\nDROP USER IF EXISTS 'v00001'@'localhost';\nDROP USER IF EXISTS 'v00001_ro'@'localhost';\n"
	if sql := lastSQL(t, e); sql != want {
		t.Errorf("delete SQL:\n got %q\nwant %q", sql, want)
	}
}
