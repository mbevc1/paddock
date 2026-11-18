package mariadb

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mbevc1/paddock/internal/system"
)

func TestIdentAndAccount(t *testing.T) {
	if got, err := Ident("v00012_app"); err != nil || got != "`v00012_app`" {
		t.Errorf("Ident = %q, %v", got, err)
	}
	if got, err := Account("v00012_ro"); err != nil || got != "'v00012_ro'@'localhost'" {
		t.Errorf("Account = %q, %v", got, err)
	}
	for _, bad := range []string{"", "a`b", "a'b", "a b", "A", "a;drop", "a-b", "a\x00", "a%", strings.Repeat("a", 65)} {
		if _, err := Ident(bad); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Ident(%q) = %v", bad, err)
		}
		if _, err := Account(bad); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Account(%q) = %v", bad, err)
		}
	}
}

func TestGrantEscaping(t *testing.T) {
	if got, err := GrantDB("v00012_app"); err != nil || got != "`v00012\\_app`" {
		t.Errorf("GrantDB = %q, %v", got, err)
	}
	// 32 characters with 6 underscores escape to 38: fine. 60 with 5 escape to 65: refused.
	if _, err := GrantDB("v00012_a_b_c_d_e_abcdefghijklmn"); err != nil {
		t.Errorf("short escaped name refused: %v", err)
	}
	long := "v00012_" + strings.Repeat("a_", 26) + "z"
	if len(long) > 64 {
		t.Fatalf("test name too long: %d", len(long))
	}
	if _, err := GrantDB(long); !errors.Is(err, ErrInvalidName) {
		t.Errorf("GrantDB(%d chars, escaped over 64) = %v", len(long), err)
	}
	if got, err := GrantVhostDatabases("v00012"); err != nil || got != "`v00012\\_%`" {
		t.Errorf("GrantVhostDatabases = %q, %v", got, err)
	}
	if _, err := GrantVhostDatabases("v00012_x"); err == nil {
		t.Error("GrantVhostDatabases accepted an underscore")
	}
}

func TestString(t *testing.T) {
	for in, want := range map[string]string{
		"abc":       "'abc'",
		"it's":      `'it\'s'`,
		`a\b`:       `'a\\b'`,
		"a\x00b\nc": `'a\0b\nc'`,
		"\r\x1a":    `'\r\Z'`,
	} {
		if got := String(in); got != want {
			t.Errorf("String(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestNewPassword(t *testing.T) {
	a, err := NewPassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewPassword()
	if len(a) != passwordLength || a == b || strings.Trim(a, passwordAlphabet) != "" {
		t.Errorf("passwords %q and %q", a, b)
	}
}

func TestStatements(t *testing.T) {
	sql, err := CreatePrimaryUser("v00012", "pw'x", 20)
	if err != nil || sql != "CREATE USER 'v00012'@'localhost' IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD('pw\\'x') WITH MAX_USER_CONNECTIONS 20;\n" {
		t.Errorf("CreatePrimaryUser = %q, %v", sql, err)
	}
	sql, err = CreateDatabase("v00012_app", "v00012")
	if err != nil || !strings.Contains(sql, "CREATE DATABASE `v00012_app` CHARACTER SET utf8mb4") ||
		!strings.Contains(sql, "GRANT ALL PRIVILEGES ON `v00012\\_app`.* TO 'v00012'@'localhost'") {
		t.Errorf("CreateDatabase = %q, %v", sql, err)
	}
	sql, err = CreateUser("v00012_ro", "v00012", "secret", PrivilegesRead, 5)
	if err != nil || !strings.Contains(sql, "GRANT SELECT, SHOW VIEW ON `v00012\\_%`.* TO 'v00012_ro'@'localhost'") ||
		!strings.Contains(sql, "WITH MAX_USER_CONNECTIONS 5") {
		t.Errorf("CreateUser = %q, %v", sql, err)
	}
	if _, err := CreateUser("v00012_ro", "v00012", "x", "root", 5); err == nil {
		t.Error("unknown privilege level accepted")
	}
	revoke, err := RevokeWrites("v00012", []string{"v00012_app"}, []string{"v00012_rw"})
	want := []string{
		"REVOKE INSERT, UPDATE, CREATE ON `v00012\\_app`.* FROM 'v00012'@'localhost'",
		"REVOKE INSERT, UPDATE, CREATE ON `v00012\\_%`.* FROM 'v00012_rw'@'localhost'",
	}
	if err != nil || strings.Join(revoke, "|") != strings.Join(want, "|") {
		t.Errorf("RevokeWrites = %q, %v", revoke, err)
	}
	restore, _ := RestoreWrites("v00012", []string{"v00012_app"}, nil)
	if len(restore) != 1 || !strings.HasPrefix(restore[0], "GRANT INSERT, UPDATE, CREATE ON `v00012\\_app`.* TO") {
		t.Errorf("RestoreWrites = %q", restore)
	}
	sql, err = DatabaseSizes("v00012")
	if err != nil || !strings.Contains(sql, `LIKE 'v00012\\_%'`) {
		t.Errorf("DatabaseSizes = %q, %v", sql, err)
	}
}

func TestClient(t *testing.T) {
	ctx := context.Background()
	f := &system.Fake{}
	f.On(clientBinary).Return(system.Result{Stdout: []byte("v00012_app\t1024\nv00012_shop\t0\n")}, nil).Times(1)
	c := Client{Run: f}
	rows, err := c.Query(ctx, "SELECT 1;")
	if err != nil || len(rows) != 2 || rows[0][0] != "v00012_app" || rows[0][1] != "1024" {
		t.Errorf("Query = %q, %v", rows, err)
	}
	if call := f.Calls()[0]; strings.Join(call.Argv, " ") != "/usr/bin/mariadb --protocol=socket --batch --skip-column-names" || string(call.Stdin) != "SELECT 1;" {
		t.Errorf("call = %+v", call)
	}

	f.On(clientBinary).Fail("ERROR 1141 (42000) at line 1: There is no such grant defined").Times(1)
	if err := c.ExecEach(ctx, []string{"REVOKE a", "REVOKE b"}, NoSuchGrant); err != nil {
		t.Errorf("missing grant not allowed: %v", err)
	}
	f.On(clientBinary).Fail("ERROR 1045 (28000): Access denied").Times(1)
	if err := c.ExecEach(ctx, []string{"REVOKE a"}, NoSuchGrant); err == nil {
		t.Error("access denied treated as done")
	}
}
