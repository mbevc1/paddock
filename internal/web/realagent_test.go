package web

import (
	"bufio"
	"context"
	"encoding/base32"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/platform"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
	"github.com/mbevc1/paddock/internal/web/store"
)

const testWebUID = 990

// inProcessAgent serves each call on a fresh socketpair, as DialAgent does over the socket.
type inProcessAgent struct {
	t     *testing.T
	srv   func() *agent.Server
	store *state.Store
}

func (a *inProcessAgent) Call(ctx context.Context, op string, actor *api.Actor, totp string, args, result any) error {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	conn := func(fd int) net.Conn {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			a.t.Fatal(err)
		}
		return c
	}
	server, client := conn(fds[0]).(*net.UnixConn), conn(fds[1])
	done := make(chan struct{})
	go func() {
		a.srv().ServeConn(context.Background(), server)
		close(done)
	}()
	defer func() {
		_ = client.Close()
		<-done
	}()
	return agent.NewClient(client).Call(ctx, op, actor, totp, args, result)
}

type realHarness struct {
	*harness
	state  *state.Store
	run    *system.Fake
	secret []byte
	admin  store.User
}

// newRealHarness runs the panel against the agent's real operations, with a fake host.
func newRealHarness(t *testing.T) *realHarness {
	t.Helper()
	ctx := context.Background()
	st, err := state.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	plat, err := platform.ForMajor(9)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, base := range []string{ops.BaseWWW, ops.BaseJail, ops.BaseFPMRun, ops.BaseArchive} {
		if err := os.MkdirAll(filepath.Join(root, base), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mountinfo := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(mountinfo, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	run := &system.Fake{}
	host := &ops.Host{Run: run, Files: render.Writer{Root: root}, Platform: plat,
		FS:         &ops.HostFS{Root: root, MountInfo: mountinfo, Chown: func(*os.Root, string, int, int) error { return nil }},
		WaitSocket: func(context.Context, string) error { return nil }}
	gate := &agent.TOTPGate{Store: st}
	reg := agent.NewRegistry()
	(&agent.Server{Registry: reg, Store: st}).RegisterJobGet()
	ops.RegisterAdmin(reg, st, gate)
	ops.RegisterOwners(reg, st)
	ops.RegisterPHP(reg, st, host)
	ops.RegisterVhosts(reg, st, host)
	ag := &inProcessAgent{t: t, store: st, srv: func() *agent.Server {
		return &agent.Server{WebUID: testWebUID, Registry: reg, Store: st, Gate: gate,
			PeerUID: func(*net.UnixConn) (uint32, error) { return testWebUID, nil }}
	}}

	h := newHarness(t)
	h.srv.agent = ag
	rh := &realHarness{harness: h, state: st, run: run}
	h.agent = nil

	// The first admin exists in both databases, as paddock setup leaves it.
	rh.admin = h.user("root-admin", store.RoleAdmin, 0)
	root0 := &inProcessAgent{t: t, store: st, srv: func() *agent.Server {
		return &agent.Server{WebUID: testWebUID, Registry: reg, Store: st, Gate: gate,
			PeerUID: func(*net.UnixConn) (uint32, error) { return 0, nil }}
	}}
	var enrolled ops.TOTPEnrollment
	if err := root0.Call(ctx, "admin.add", nil, "", ops.AdminAddArgs{UserID: rh.admin.ID, Username: "root-admin"}, &enrolled); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(enrolled.TOTPURI)
	if err != nil {
		t.Fatal(err)
	}
	if rh.secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret")); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPHPVersion(ctx, "8.3"); err != nil {
		t.Fatal(err)
	}
	return rh
}

// adminCode returns the admin's TOTP code at the harness time. The agent checks codes against
// the real clock, so tests that use it keep the harness clock near now.
func (rh *realHarness) adminCode() string {
	return auth.TOTPCode(rh.secret, auth.TOTPStep(time.Now()))
}

func (rh *realHarness) adminBrowser() *browser {
	rh.t.Helper()
	b := rh.browser()
	wantRedirect(rh.t, b.login("root-admin", ownerPassword), "/login/totp")
	wantRedirect(rh.t, b.do("POST", "/login/totp", url.Values{"code": {rh.adminCode()}}), "/dashboard")
	return b
}

// ownerWithVhost creates an owner, its panel user, and one active vhost directly in state.
func (rh *realHarness) ownerWithVhost(name, user, domain string) (state.Owner, state.Vhost) {
	rh.t.Helper()
	ctx := context.Background()
	o, err := rh.state.CreateOwner(ctx, name, state.DefaultLimits())
	if err != nil {
		rh.t.Fatal(err)
	}
	v, err := rh.state.CreateVhost(ctx, o.ID, "8.3", domain, nil)
	if err != nil {
		rh.t.Fatal(err)
	}
	if err := rh.state.SetVhostStatus(ctx, v.N, state.VhostActive); err != nil {
		rh.t.Fatal(err)
	}
	rh.user(user, store.RoleOwner, o.ID)
	return o, v
}

func TestOwnersSeeOnlyTheirOwnVhosts(t *testing.T) {
	rh := newRealHarness(t)
	rh.now = time.Now()
	_, va := rh.ownerWithVhost("Acme", "alice", "a.example.com")
	_, vb := rh.ownerWithVhost("Bobco", "bob", "b.example.com")
	alice := rh.browser()
	wantRedirect(t, alice.login("alice", ownerPassword), "/dashboard")

	if rec := alice.do("GET", "/vhosts/"+va.ID, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "a.example.com") {
		t.Fatalf("own vhost = %d", rec.Code)
	}
	if rec := alice.do("GET", "/vhosts", nil); strings.Contains(rec.Body.String(), "b.example.com") {
		t.Error("list shows another owner's vhost")
	}
	for _, req := range []struct{ method, path string }{
		{"GET", "/vhosts/" + vb.ID},
		{"POST", "/vhosts/" + vb.ID + "/databases"},
		{"POST", "/vhosts/" + vb.ID + "/cert"},
	} {
		var form url.Values
		if req.method == "POST" {
			form = url.Values{"suffix": {"x"}, "chain": {"x"}, "key": {"x"}}
		}
		if rec := alice.do(req.method, req.path, form); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", req.method, req.path, rec.Code)
		}
	}
	if rec := alice.do("GET", "/admin/owners", nil); rec.Code != http.StatusNotFound {
		t.Errorf("owner reached an admin page: %d", rec.Code)
	}
}

func TestAdminActionWithoutTOTPFailsAtTheAgent(t *testing.T) {
	rh := newRealHarness(t)
	rh.now = time.Now()
	b := rh.adminBrowser()
	// Login opened the agent's admin window; close it so only a fresh code works.
	if err := rh.state.OpenAdminWindow(context.Background(), rh.admin.ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	rec := b.do("POST", "/admin/owners", url.Values{"name": {"Acme"}, "username": {"alice"}})
	wantRedirect(t, rec, "/admin/owners?error=")
	if owners, _ := rh.state.ListOwners(context.Background()); len(owners) != 0 {
		t.Fatal("owner created without a code")
	}
	entries, err := rh.state.ListAudit(context.Background(), 0, 1)
	if err != nil || entries[0].Op != "owner.create" || entries[0].Result != string(api.CodeTOTPRequired) {
		t.Errorf("the agent did not refuse: %+v, %v", entries, err)
	}
	if rec := b.do("GET", "/admin/owners", nil); !strings.Contains(rec.Body.String(), "Confirm admin access") {
		t.Error("admin page did not ask for a code")
	}

	// Login used this step's code; the next step's is fresh and within the allowed skew.
	next := auth.TOTPCode(rh.secret, auth.TOTPStep(time.Now())+1)
	rec = b.do("POST", "/admin/owners", url.Values{"name": {"Acme"}, "username": {"alice"}, "totp": {next}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "shown only once") {
		t.Fatalf("create with a code = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := rh.store.GetUserByName(context.Background(), "alice"); err != nil {
		t.Error("panel user not created")
	}
}

func TestImpersonationRecordsBothIdentities(t *testing.T) {
	ctx := context.Background()
	rh := newRealHarness(t)
	rh.now = time.Now()
	o, v := rh.ownerWithVhost("Acme", "alice", "a.example.com")
	alice, _ := rh.store.GetUserByName(ctx, "alice")
	b := rh.adminBrowser()
	before := b.cookie
	wantRedirect(t, b.do("POST", "/admin/owners/"+itoa(o.ID)+"/impersonate", url.Values{}), "/dashboard")
	if b.cookie == before {
		t.Error("session not rotated when impersonation started")
	}
	if rec := b.do("GET", "/vhosts/"+v.ID, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Acting as owner") {
		t.Fatalf("impersonated vhost page = %d", rec.Code)
	}
	if rec := b.do("POST", "/vhosts/"+v.ID+"/databases", url.Values{"suffix": {"app"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("impersonated db.create = %d %.300s", rec.Code, rec.Body.String())
	}
	entries, err := rh.state.ListAudit(ctx, 0, 1)
	want := `"user_id":` + itoa(rh.admin.ID) + `,"role":"owner","owner_id":` + itoa(o.ID) + `,"impersonated_by":` + itoa(rh.admin.ID)
	if err != nil || entries[0].Op != "db.create" || !strings.Contains(entries[0].Actor, want) {
		t.Errorf("audit actor = %+v, want %s", entries, want)
	}
	notes, _ := rh.store.RecentNotifications(ctx, alice.ID, 5)
	if len(notes) != 1 || notes[0].Kind != "impersonation" {
		t.Errorf("owner notifications = %+v", notes)
	}
	wantRedirect(t, b.do("POST", "/admin/impersonate/stop", url.Values{}), "/admin/owners")
	se, _ := rh.store.GetSession(ctx, hashToken(b.cookie))
	if se.Impersonating != 0 {
		t.Error("still impersonating after stop")
	}
}

func TestApplyFailureStreamsToTheOwner(t *testing.T) {
	ctx := context.Background()
	rh := newRealHarness(t)
	rh.now = time.Now()
	o, v := rh.ownerWithVhost("Acme", "alice", "a.example.com")
	alice := rh.browser()
	alice.login("alice", ownerPassword)
	if err := rh.store.MarkNotificationsRead(ctx, mustUser(t, rh.store, "alice").ID, 0); err != nil {
		t.Fatal(err)
	}

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := ioPipe()
	req := httptest.NewRequestWithContext(streamCtx, "GET", "https://panel.example.com:8443/notifications/stream", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: alice.cookie})
	go func() {
		rh.srv.Handler().ServeHTTP(&streamRecorder{w: pw, header: http.Header{}}, req)
		_ = pw.Close()
	}()
	lines := bufio.NewScanner(pr)

	rh.run.On("/usr/sbin/apachectl").Fail("AH00526: Syntax error").Times(1)
	chain, key := uploadPair(t, "a.example.com")
	wantRedirect(t, alice.do("POST", "/vhosts/"+v.ID+"/cert", url.Values{"chain": {chain}, "key": {key}}), "/vhosts/"+v.ID+"?error=")
	if err := rh.srv.pollOnce(ctx); err != nil {
		t.Fatal(err)
	}

	got := make(chan string, 1)
	go func() {
		for lines.Scan() {
			if strings.HasPrefix(lines.Text(), "data: ") {
				got <- lines.Text()
				return
			}
		}
	}()
	select {
	case data := <-got:
		if !strings.Contains(data, `"kind":"apply_failed"`) || !strings.Contains(data, "cert.upload") {
			t.Errorf("streamed %s", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification streamed")
	}
	_ = o
}

// TestTemplatesGuardActionsWithCan checks that every form posting to a route that needs a
// permission beyond the user's own account sits in a template that checks that permission.
func TestTemplatesGuardActionsWithCan(t *testing.T) {
	h := newHarness(t)
	rt := &Router{}
	h.srv.routes(rt)
	mux := http.NewServeMux()
	perms := map[string]Permission{}
	for _, r := range rt.routes {
		key := r.Method + " " + r.Pattern
		perms[key] = r.Perm
		mux.Handle(key, http.NotFoundHandler())
	}
	action := regexp.MustCompile(`action="([^"]+)"`)
	expr := regexp.MustCompile(`\{\{[^}]*\}\}`)
	err := fs.WalkDir(templateFiles, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := templateFiles.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range action.FindAllStringSubmatch(string(body), -1) {
			target := expr.ReplaceAllString(m[1], "x")
			req := httptest.NewRequestWithContext(context.Background(), "POST", target, nil)
			_, pattern := mux.Handler(req)
			perm, ok := perms[pattern]
			if !ok {
				t.Errorf("%s posts to %s, which no route serves", path, m[1])
				continue
			}
			if perm == PermPublic || perm == PermPending || perm == PermSelf {
				continue
			}
			if !strings.Contains(string(body), `.Can "`+string(perm)+`"`) {
				t.Errorf("%s posts to %s (%s) without {{if .Can %q}}", path, m[1], perm, perm)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
