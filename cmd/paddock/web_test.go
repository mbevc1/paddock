package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The challenge socket's path appears in several packaged files, and Apache reaches it only
// through a directory that the SELinux module labels httpd_var_run_t.
func TestACMESocketMatchesPackaging(t *testing.T) {
	dir := filepath.Dir(defaultACMESck)
	if dir == "/run/paddock" {
		t.Fatalf("%s sits directly in /run/paddock, whose var_run_t label Apache may not write to", defaultACMESck)
	}
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, c := range []struct{ file, want string }{
		{"deploy/etc/httpd/conf.d/paddock-01-panel.conf", `"unix:` + defaultACMESck + `|`},
		{"deploy/tmpfiles.d/paddock.conf", "d " + dir + " 0755 paddock paddock -\n"},
		{"deploy/systemd/paddock-web.service", "ReadWritePaths=/var/lib/paddock/web " + dir + "\n"},
		{"deploy/selinux/paddock.cil", `(filecon "` + dir + `(/.*)?" any (system_u object_r httpd_var_run_t `},
		{"deploy/selinux/paddock.cil", "(allow httpd_t unconfined_service_t (unix_stream_socket (connectto)))"},
		{"packaging/paddock.spec", "semodule -i %{_datadir}/selinux/packages/paddock.cil"},
		{"packaging/paddock.spec", "restorecon -R " + dir},
	} {
		if !strings.Contains(read(c.file), c.want) {
			t.Errorf("%s lacks %q", c.file, c.want)
		}
	}
}
