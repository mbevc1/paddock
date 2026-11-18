//go:build integration

package integration

import (
	"testing"

	"github.com/mbevc1/paddock/internal/agent/ops"
)

func TestDatabaseIsolation(t *testing.T) {
	h := newAgent(t)
	a, aDomain := newVhost(t, h, "8.3")
	b, _ := newVhost(t, h, "8.3")
	for _, id := range []string{a, b} {
		h.mustCall(t, "db.create", ops.DBArgs{VhostID: id, Suffix: "app"}, nil)
	}
	connect := func(user, db string) string {
		return servePHP(t, a, aDomain, "db.php", "mysqli_report(MYSQLI_REPORT_OFF);\n"+
			"$m = @new mysqli('localhost', '"+user+"', '', '"+db+"');\n"+
			"echo $m->connect_errno ? 'ERR' : 'OK';")
	}
	if got := connect(a, a+"_app"); got != "OK" {
		t.Errorf("A to its own database: %q", got)
	}
	if got := connect(b, b+"_app"); got != "ERR" {
		t.Errorf("A logged in as B: %q", got)
	}
	if got := connect(a, b+"_app"); got != "ERR" {
		t.Errorf("A opened B's database: %q", got)
	}
}

func TestVhostCreateWithDatabase(t *testing.T) {
	h := newAgent(t)
	h.installPHP(t, "8.3")
	id, domain := h.createVhost(t, ops.VhostCreateArgs{OwnerID: h.newOwner(t, ops.LimitsArgs{}), PHPVersion: "8.3", Database: "app"})
	got := servePHP(t, id, domain, "db.php", "mysqli_report(MYSQLI_REPORT_OFF);\n"+
		"$m = @new mysqli('localhost', '"+id+"', '', '"+id+"_app');\n"+
		"if ($m->connect_errno) { echo 'ERR'; exit; }\n"+
		"echo $m->query('SHOW TABLES')->num_rows;")
	if got != "0" {
		t.Errorf("the vhost's new database answered %q, want an empty database", got)
	}
	other, _ := newVhost(t, h, "8.3")
	if got := phpEval(t, other, "mysqli_report(MYSQLI_REPORT_OFF);\n"+
		"$m = @new mysqli('localhost', '"+other+"', '', '"+id+"_app');\n"+
		"echo $m->connect_errno ? 'ERR' : 'OK';"); got != "ERR" {
		t.Errorf("another vhost opened the new database: %q", got)
	}
}
