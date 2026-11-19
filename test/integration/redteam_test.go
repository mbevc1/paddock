//go:build integration

package integration

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
	"github.com/mbevc1/paddock/internal/validate"
)

// TestRedTeam makes every attempt from §7.7 as vhost A against vhost B, both created through
// the agent as the panel creates them. Attempts run as A's PHP (sandbox, SELinux domain and UID
// all apply) and, where noted, as a plain process with A's UID in the host namespaces, so each
// layer is tested on its own.
func TestRedTeam(t *testing.T) {
	h := newAgent(t)
	h.installPHP(t, "8.3")
	ownerA := h.newOwner(t, ops.LimitsArgs{DiskMB: ptrTo(20)})
	ownerB := h.newOwner(t, ops.LimitsArgs{})
	a, aDomain := h.createVhost(t, ops.VhostCreateArgs{OwnerID: ownerA, PHPVersion: "8.3", Database: "app"})
	b, bDomain := h.createVhost(t, ops.VhostCreateArgs{OwnerID: ownerB, PHPVersion: "8.3", Database: "app"})
	key, pub := sshKey(t)
	h.mustJob(t, "access.create", ops.AccessCreateArgs{VhostID: a, Keys: []string{pub}}, time.Minute)

	token := "redteam-" + randomHex(t, 12)
	secret := writeAs(t, b, "private/secret.txt", token+"\n", 0o600)
	mustSQL(t, fmt.Sprintf("CREATE TABLE `%s_app`.secret (v VARCHAR(64)); INSERT INTO `%s_app`.secret VALUES ('%s');", b, b, token))
	bFPM := mainPID(t, "paddock-php83-fpm@"+b+".service")

	noToken := func(t *testing.T, desc, out string) {
		t.Helper()
		if strings.Contains(out, token) {
			t.Errorf("%s: B's secret leaked: %.300s", desc, out)
		}
	}
	sliceA := fmt.Sprintf("paddock-owner-%d.slice", ownerA)

	t.Run("read B's files", func(t *testing.T) {
		noToken(t, "A's PHP reading B's file", phpShell(t, a, "cat "+secret))
		if got := phpShell(t, a, "ls -A /srv/www"); got != a {
			t.Errorf("A's PHP lists /srv/www as %q, want only %s", got, a)
		}
		noToken(t, "A's UID in the host namespace", asVhostUID(t, a, "/usr/bin/cat", secret))
		noToken(t, "the front Apache user", asApache(t, "/usr/bin/cat", secret))
	})

	t.Run("make a shared web server read B's files", func(t *testing.T) {
		symlinkAs(t, a, secret, "public/leak.txt")
		_, body := fetchFront(t, aDomain, "/leak.txt")
		noToken(t, "symlink in A's tree", body)

		mkdirAs(t, a, "public/rw")
		writeAs(t, a, "public/rw/.htaccess", "RewriteEngine On\nRewriteRule ^x$ "+secret+" [L]\n", 0o644)
		_, body = fetchFront(t, aDomain, "/rw/x")
		noToken(t, "rewrite in A's .htaccess", body)

		mkdirAs(t, a, "public/fs")
		writeAs(t, a, "public/fs/.htaccess", "Options +FollowSymLinks\n", 0o644)
		symlinkAs(t, a, secret, "public/fs/leak.txt")
		_, body = fetchFront(t, aDomain, "/fs/leak.txt")
		noToken(t, "FollowSymLinks in A's .htaccess", body)

		noToken(t, "B's Host header on A's backend", backendGet(t, a, "/private/secret.txt", bDomain))
	})

	t.Run("list B's domains through mod_md's status", func(t *testing.T) {
		if got := phpEval(t, a, "$f = @fsockopen('127.0.0.1', 81, $e, $s, 3); echo $f ? 'OPEN' : 'BLOCKED';"); got != "BLOCKED" {
			t.Errorf("A's PHP reached the md-status listener: %q", got)
		}
		if got := phpShell(t, a, "curl -s -m 5 http://127.0.0.1/md-status https://127.0.0.1/md-status -k"); strings.Contains(got, bDomain) {
			t.Errorf("A's PHP read B's domain from md-status: %.300s", got)
		}
		if got := asVhostUID(t, a, "/usr/bin/curl", "-s", "-o", "/dev/null", "-m", "5", "-w", "%{http_code}", "http://127.0.0.1:81/md-status"); got != "000" {
			t.Errorf("A's UID reached the md-status listener: HTTP %s", got)
		}
	})

	t.Run("run code as B through B's PHP socket", func(t *testing.T) {
		sock := "/run/paddock/fpm/" + b + "/php83.sock"
		if got := phpShell(t, a, "test -e "+sock+" && echo present"); strings.Contains(got, "present") {
			t.Error("B's FPM socket path is visible to A's PHP")
		}
		got := asVhostUID(t, a, phpCLI("8.3"), "-r", "$s = @stream_socket_client('unix://"+sock+"'); echo $s ? 'OPEN' : 'DENIED';")
		if got != "DENIED" {
			t.Errorf("A's UID connecting to B's FPM socket: %q", got)
		}
		fi, err := os.Stat(sock)
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); fi.Mode().Perm() != 0o600 || strconv.Itoa(int(st.Uid)) != uidOf(t, b) {
			t.Errorf("B's FPM socket is %v owned by %d", fi.Mode().Perm(), st.Uid)
		}
	})

	t.Run("connect to B's backend on loopback", func(t *testing.T) {
		addr := backendAddr(t, b)
		if got := phpEval(t, a, "$f = @fsockopen('"+addr+"', 81, $e, $s, 3); echo $f ? 'OPEN' : 'BLOCKED';"); got != "BLOCKED" {
			t.Errorf("A's PHP connecting to B's backend: %q", got)
		}
		if got := asVhostUID(t, a, "/usr/bin/curl", "-s", "-o", "/dev/null", "-m", "5", "-w", "%{http_code}", "http://"+addr+":81/"); got != "000" {
			t.Errorf("A's UID reached B's backend: HTTP %s", got)
		}
	})

	t.Run("squat B's backend address while it restarts", func(t *testing.T) {
		unit := "paddock-httpd@" + b + ".service"
		mustRun(t, "/usr/bin/systemctl", "stop", unit)
		defer mustRun(t, "/usr/bin/systemctl", "start", unit)
		bind := "$s = @stream_socket_server('tcp://" + backendAddr(t, b) + ":81', $e, $m); echo $s ? 'BOUND' : 'DENIED';"
		if got := asVhostUID(t, a, phpCLI("8.3"), "-r", bind); got != "DENIED" {
			t.Errorf("A's UID binding B's address: %q", got)
		}
		if got := phpEval(t, a, bind); got != "DENIED" {
			t.Errorf("A's PHP binding B's address: %q", got)
		}
		if got := mustRun(t, "/usr/sbin/sysctl", "-n", "net.ipv4.ip_unprivileged_port_start"); got != "1024" {
			t.Errorf("net.ipv4.ip_unprivileged_port_start = %s", got)
		}
	})

	t.Run("list or inspect B's processes", func(t *testing.T) {
		if got := phpShell(t, a, `ps -eo uid= | tr -d " " | sort -u`); got != uidOf(t, a) {
			t.Errorf("A's PHP sees processes of UIDs %q", got)
		}
		if got := phpShell(t, a, "test -d /proc/"+bFPM+" && echo visible"); strings.Contains(got, "visible") {
			t.Error("A's PHP sees B's FPM in /proc")
		}
		if got := phpShell(t, a, "kill -0 "+bFPM+" && echo signaled"); strings.Contains(got, "signaled") {
			t.Error("A's PHP can signal B's FPM")
		}
		bHTTPD := mainPID(t, "paddock-httpd@"+b+".service")
		if asVhostUIDSucceeds(t, a, "/usr/bin/kill", "-0", bHTTPD) {
			t.Error("A's UID can signal B's backend")
		}
		if asVhostUIDSucceeds(t, a, "/usr/bin/cat", "/proc/"+bFPM+"/environ") {
			t.Error("A's UID can read B's environment")
		}
	})

	t.Run("read B's temp files, shared memory and IPC", func(t *testing.T) {
		t.Logf("B: %s", phpShell(t, b, "echo b >/tmp/b-"+token+"; echo b >/dev/shm/b-"+token+"; ipcmk -M 4096"))
		noToken(t, "A's PHP listing /tmp and /dev/shm", phpShell(t, a, "ls -a /tmp /dev/shm"))
		if got := phpShell(t, a, `ipcs -m | awk 'NR > 3 && NF { print $2 }'`); got != "" {
			t.Errorf("A's PHP sees shared memory segments %q", got)
		}
	})

	t.Run("read B's databases", func(t *testing.T) {
		query := func(user, db, sql string) string {
			return phpEval(t, a, "mysqli_report(MYSQLI_REPORT_OFF);\n"+
				"$m = @new mysqli('localhost', '"+user+"', '', '"+db+"');\n"+
				"if ($m->connect_errno) { echo 'ERR'; exit; }\n"+
				"$r = @$m->query('"+sql+"');\n"+
				"echo $r ? implode(',', array_column($r->fetch_all(), 0)) : 'ERR';")
		}
		noToken(t, "A's PHP as B's DB user", query(b, b+"_app", "SELECT v FROM secret"))
		noToken(t, "A's DB user on B's database", query(a, a+"_app", "SELECT v FROM "+b+"_app.secret"))
		noToken(t, "A's PHP as root", query("root", "", "SELECT v FROM "+b+"_app.secret"))
	})

	t.Run("see B through SFTP or SSH", func(t *testing.T) {
		if got := strings.Fields(sftpBatch(t, key, a, "-ls -1a /\n")); containsWord(got, "srv") {
			t.Errorf("A's SFTP root lists %q", got)
		}
		local := filepath.Join(t.TempDir(), "got")
		sftpBatch(t, key, a, "-get /srv/www/"+b+"/private/secret.txt "+local+"\n-get /site/../../"+b+"/private/secret.txt "+local+"\n")
		if data, err := os.ReadFile(local); err == nil {
			noToken(t, "A's SFTP fetching B's file", string(data))
		}
		if got := sshRun(t, key, a, "", "id"); strings.Contains(got, "uid=") {
			t.Errorf("A's SFTP account ran a command: %q", got)
		}
	})

	t.Run("starve B of CPU, memory or disk", func(t *testing.T) {
		for _, prop := range []string{"MemoryMax", "CPUQuotaPerSecUSec", "TasksMax"} {
			if v := mustRun(t, "/usr/bin/systemctl", "show", "-p", prop, "--value", sliceA); v == "" || v == "infinity" {
				t.Errorf("%s has %s=%q", sliceA, prop, v)
			}
		}
		fill := "/srv/www/" + a + "/tmp/fill"
		defer os.Remove(fill)
		if got := phpShell(t, a, "dd if=/dev/zero of="+fill+" bs=1M count=40"); !strings.Contains(strings.ToLower(got), "quota exceeded") {
			t.Errorf("A wrote past its 20 MB quota: %s", got)
		}
		bFill := "/srv/www/" + b + "/tmp/fill"
		defer os.Remove(bFill)
		if got := phpShell(t, b, "dd if=/dev/zero of="+bFill+" bs=1M count=5 && echo written"); !strings.Contains(got, "written") {
			t.Errorf("B could not write after A filled its quota: %s", got)
		}
	})

	t.Run("gain privileges", func(t *testing.T) {
		if got := phpShell(t, a, "cat /proc/self/status"); !regexp.MustCompile(`NoNewPrivs:\s+1`).MatchString(got) {
			t.Error("A's PHP runs without NoNewPrivs")
		}
		if got := phpShell(t, a, "sudo -n id -u"); got == "0" {
			t.Error("sudo in A's PHP reached root")
		}
		if got := mustRun(t, "/usr/sbin/sysctl", "-n", "user.max_user_namespaces"); got != "0" {
			t.Errorf("user.max_user_namespaces = %s", got)
		}
		if got := phpShell(t, a, "unshare -U true && echo created"); strings.Contains(got, "created") {
			t.Error("A's PHP created a user namespace")
		}
		for _, f := range []string{"/etc/subuid", "/etc/subgid"} {
			if overlaps := subIDOverlaps(t, f, state.UIDBase+1, state.UIDBase+validate.MaxVhostNumber); len(overlaps) > 0 {
				t.Errorf("%s ranges cover vhost IDs: %q", f, overlaps)
			}
		}
	})
}

// mustSQL runs SQL as MariaDB's root, which logs in over unix_socket.
func mustSQL(t *testing.T, sql string) {
	t.Helper()
	res, err := (system.Exec{}).Run(context.Background(), []string{"/usr/bin/mariadb"}, system.Opts{Stdin: strings.NewReader(sql)})
	if err != nil {
		t.Fatalf("mariadb: %v: %s", err, res.Stderr)
	}
}

func asVhostUIDSucceeds(t *testing.T, id string, argv ...string) bool {
	t.Helper()
	uid := uidOf(t, id)
	full := append([]string{"/usr/bin/setpriv", "--reuid=" + uid, "--regid=" + uid, "--clear-groups", "--"}, argv...)
	_, err := run(context.Background(), full...)
	return err == nil
}

func mkdirAs(t *testing.T, id, rel string) {
	t.Helper()
	path := filepath.Join("/srv/www", id, rel)
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatal(err)
	}
	uid := atoi(t, uidOf(t, id))
	if err := os.Lchown(path, uid, uid); err != nil {
		t.Fatal(err)
	}
}

func symlinkAs(t *testing.T, id, target, rel string) {
	t.Helper()
	path := filepath.Join("/srv/www", id, rel)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	uid := atoi(t, uidOf(t, id))
	if err := os.Lchown(path, uid, uid); err != nil {
		t.Fatal(err)
	}
}

func containsWord(words []string, w string) bool {
	for _, x := range words {
		if x == w {
			return true
		}
	}
	return false
}

// subIDOverlaps returns the entries of a subuid or subgid file whose range meets [lo, hi].
func subIDOverlaps(t *testing.T, path string, lo, hi int) []string {
	t.Helper()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var overlaps []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) != 3 {
			continue
		}
		start, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 == nil && err2 == nil && start <= hi && start+count > lo {
			overlaps = append(overlaps, sc.Text())
		}
	}
	return overlaps
}
