package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/web/store"
)

// fakeAgent answers agent calls from a table of handlers and records them.
type fakeAgent struct {
	mu       sync.Mutex
	handlers map[string]func(actor *api.Actor, totp string, args json.RawMessage) (any, error)
	calls    []agentCall
}

type agentCall struct {
	Op    string
	Actor *api.Actor
	TOTP  string
	Args  string
}

func (f *fakeAgent) on(op string, h func(actor *api.Actor, totp string, args json.RawMessage) (any, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.handlers == nil {
		f.handlers = map[string]func(*api.Actor, string, json.RawMessage) (any, error){}
	}
	f.handlers[op] = h
}

func (f *fakeAgent) Call(_ context.Context, op string, actor *api.Actor, totp string, args, result any) error {
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.calls = append(f.calls, agentCall{Op: op, Actor: actor, TOTP: totp, Args: string(raw)})
	h := f.handlers[op]
	f.mu.Unlock()
	if h == nil {
		return api.Errorf(api.CodeNotFound, "no fake for %s", op)
	}
	out, err := h(actor, totp, raw)
	if err != nil || result == nil || out == nil {
		return err
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, result)
}

type harness struct {
	t     *testing.T
	srv   *Server
	store *store.Store
	agent *fakeAgent
	now   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := &harness{t: t, store: st, agent: &fakeAgent{}, now: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}
	st.SetClock(func() time.Time { return h.now })
	srv, err := New(Config{Hostname: "panel.example.com", TLSAddr: ":8443"}, Deps{Agent: h.agent, Store: st, Now: func() time.Time { return h.now }})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	return h
}

func (h *harness) user(name string, role store.Role, ownerID int64) store.User {
	h.t.Helper()
	hash, err := auth.HashPassword(ownerPassword)
	if err != nil {
		h.t.Fatal(err)
	}
	u, err := h.store.CreateUser(context.Background(), name, role, ownerID, hash)
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

// browser keeps one session cookie and sends same-origin requests with its CSRF token.
type browser struct {
	h      *harness
	cookie string
	origin string
	// header is added to every request, for example Referer or HX-Request.
	header http.Header
}

func (h *harness) browser() *browser { return &browser{h: h, origin: h.srv.origin} }

func (b *browser) csrf() string {
	if b.cookie == "" {
		return ""
	}
	se, err := b.h.store.GetSession(context.Background(), hashToken(b.cookie))
	if err != nil {
		return ""
	}
	return se.CSRFToken
}

func (b *browser) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	b.h.t.Helper()
	var body io.Reader
	if form != nil {
		if form.Get("csrf") == "" {
			form.Set("csrf", b.csrf())
		}
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequestWithContext(context.Background(), method, "https://panel.example.com:8443"+path, body)
	req.RemoteAddr = "192.0.2.10:50000"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if b.origin != "" && method != http.MethodGet {
		req.Header.Set("Origin", b.origin)
	}
	if b.cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: b.cookie})
	}
	for k, v := range b.header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	b.h.srv.Handler().ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			b.cookie = c.Value
			if c.MaxAge < 0 {
				b.cookie = ""
			}
		}
	}
	return rec
}

func (b *browser) login(user, password string) *httptest.ResponseRecorder {
	b.h.t.Helper()
	return b.do("POST", "/login", url.Values{"username": {user}, "password": {password}})
}

func wantRedirect(t *testing.T, rec *httptest.ResponseRecorder, prefix string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want a redirect to %s; body %.300s", rec.Code, prefix, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, prefix) {
		t.Fatalf("Location = %q, want %s", loc, prefix)
	}
}

const ownerPassword = "violet sparrow ledger"

func TestEveryRouteHasAPermissionAndHeaders(t *testing.T) {
	h := newHarness(t)
	rec := h.browser().do("GET", "/login", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login = %d", rec.Code)
	}
	for _, header := range []string{"Content-Security-Policy", "X-Frame-Options", "Referrer-Policy", "X-Content-Type-Options"} {
		if rec.Header().Get(header) == "" {
			t.Errorf("%s missing", header)
		}
	}
	if body := rec.Body.String(); strings.Contains(body, "<script>") || strings.Contains(body, "style=") {
		t.Error("inline script or style would break the CSP")
	}
	if rec := h.browser().do("GET", "/static/htmx.min.js", nil); rec.Code != http.StatusOK {
		t.Errorf("htmx = %d", rec.Code)
	}
}

func TestLoginOwnerWithoutTOTP(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	b := h.browser()
	rec := b.login("alice", ownerPassword)
	wantRedirect(t, rec, "/dashboard")
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("cookie = %+v", cookie)
	}
	se, err := h.store.GetSession(context.Background(), hashToken(cookie.Value))
	if err != nil || se.MFAAt.IsZero() {
		t.Fatalf("session = %+v, %v", se, err)
	}
	if strings.Contains(fmt.Sprint(se), cookie.Value) {
		t.Error("session stores the raw token")
	}
	if n, _ := h.store.UnreadCount(context.Background(), se.UserID); n != 1 {
		t.Errorf("new-IP notification count = %d", n)
	}
}

func TestLoginFailuresBackOff(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	b := h.browser()
	if rec := b.login("alice", "wrong password!"); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), loginFailed) {
		t.Fatalf("wrong password = %d", rec.Code)
	}
	rec := b.login("alice", ownerPassword)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Too many failed attempts") {
		t.Fatalf("immediate retry = %d %s", rec.Code, rec.Body.String())
	}
	h.now = h.now.Add(2 * time.Second)
	b.login("alice", "wrong again!!")
	h.now = h.now.Add(time.Second)
	if rec := b.login("alice", ownerPassword); !strings.Contains(rec.Body.String(), "Try again in 1s") {
		t.Errorf("second backoff: %s", rec.Body.String())
	}
	h.now = h.now.Add(2 * time.Second)
	wantRedirect(t, b.login("alice", ownerPassword), "/dashboard")
}

func TestUnknownUserTakesAsLongAsWrongPassword(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	measure := func(user string) time.Duration {
		h.srv.limiter = newLimiter(h.srv.now)
		start := time.Now()
		h.browser().login(user, "not the password")
		return time.Since(start)
	}
	measure("alice")
	known, unknown := measure("alice"), measure("nobody-here")
	if unknown < known/2 {
		t.Errorf("unknown user took %v, known user %v: usernames can be probed by timing", unknown, known)
	}
}

func TestOwnerTOTPAndRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	u := h.user("alice", store.RoleOwner, 3)
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetTOTPSecret(ctx, u.ID, secret); err != nil {
		t.Fatal(err)
	}
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.ReplaceRecoveryCodes(ctx, u.ID, hashes); err != nil {
		t.Fatal(err)
	}

	b := h.browser()
	wantRedirect(t, b.login("alice", ownerPassword), "/login/totp")
	pending := b.cookie
	wantRedirect(t, b.do("GET", "/dashboard", nil), "/login")
	code := auth.TOTPCode(secret, auth.TOTPStep(h.now))
	wantRedirect(t, b.do("POST", "/login/totp", url.Values{"code": {code}}), "/dashboard")
	if b.cookie == pending {
		t.Error("session token not rotated after the second factor")
	}
	if _, err := h.store.GetSession(ctx, hashToken(pending)); err == nil {
		t.Error("pending session still valid")
	}

	replay := h.browser()
	h.now = h.now.Add(10 * time.Second)
	wantRedirect(t, replay.login("alice", ownerPassword), "/login/totp")
	if rec := replay.do("POST", "/login/totp", url.Values{"code": {code}}); rec.Code != http.StatusUnauthorized {
		t.Errorf("replayed code = %d", rec.Code)
	}

	h.now = h.now.Add(time.Minute)
	rc := h.browser()
	wantRedirect(t, rc.login("alice", ownerPassword), "/login/totp")
	wantRedirect(t, rc.do("POST", "/login/totp", url.Values{"recovery": {strings.ToUpper(codes[0])}}), "/dashboard")
	h.now = h.now.Add(time.Minute)
	again := h.browser()
	wantRedirect(t, again.login("alice", ownerPassword), "/login/totp")
	if rec := again.do("POST", "/login/totp", url.Values{"recovery": {codes[0]}}); rec.Code != http.StatusUnauthorized {
		t.Errorf("reused recovery code = %d", rec.Code)
	}
}

func TestAdminSecondFactorGoesToAgent(t *testing.T) {
	h := newHarness(t)
	admin := h.user("root-admin", store.RoleAdmin, 0)
	h.agent.on("admin.totp.verify", func(_ *api.Actor, _ string, args json.RawMessage) (any, error) {
		if strings.Contains(string(args), `"code":"135790"`) && strings.Contains(string(args), fmt.Sprintf(`"user_id":%d`, admin.ID)) {
			return nil, nil
		}
		return nil, api.Errorf(api.CodeTOTPInvalid, "code rejected")
	})
	b := h.browser()
	wantRedirect(t, b.login("root-admin", ownerPassword), "/login/totp")
	if rec := b.do("POST", "/login/totp", url.Values{"code": {"000000"}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong admin code = %d", rec.Code)
	}
	h.now = h.now.Add(2 * time.Second)
	wantRedirect(t, b.do("POST", "/login/totp", url.Values{"code": {"135790"}}), "/dashboard")
	h.agent.on("owner.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []any{}, nil })
	h.agent.on("php.version.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []string{"8.3"}, nil })
	if rec := b.do("GET", "/admin/status", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "reachable") {
		t.Errorf("admin status = %d", rec.Code)
	}
}

// An admin whose login TOTP is off signs in with the password; the agent still asks for a
// code before the first admin operation.
func TestAdminLoginWithoutTOTP(t *testing.T) {
	h := newHarness(t)
	admin := h.user("root-admin", store.RoleAdmin, 0)
	if err := h.store.SetAdminLoginTOTP(context.Background(), admin.ID, false); err != nil {
		t.Fatal(err)
	}
	h.agent.on("owner.list", func(*api.Actor, string, json.RawMessage) (any, error) {
		return nil, api.Errorf(api.CodeTOTPRequired, "admin code required")
	})
	b := h.browser()
	wantRedirect(t, b.login("root-admin", ownerPassword), "/dashboard")
	if rec := b.do("GET", "/admin/owners", nil); !strings.Contains(rec.Body.String(), "Confirm admin access") {
		t.Errorf("admin page without an open window = %d, want the unlock form", rec.Code)
	}
}

func TestSessionExpiry(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	h.user("root-admin", store.RoleAdmin, 0)
	h.agent.on("admin.totp.verify", func(*api.Actor, string, json.RawMessage) (any, error) { return nil, nil })

	owner := h.browser()
	owner.login("alice", ownerPassword)
	admin := h.browser()
	admin.login("root-admin", ownerPassword)
	admin.do("POST", "/login/totp", url.Values{"code": {"123456"}})

	h.now = h.now.Add(16 * time.Minute)
	if rec := owner.do("GET", "/security", nil); rec.Code != http.StatusOK {
		t.Errorf("owner after 16 idle minutes = %d", rec.Code)
	}
	wantRedirect(t, admin.do("GET", "/security", nil), "/login")

	for range 25 {
		h.now = h.now.Add(29 * time.Minute)
		if rec := owner.do("GET", "/security", nil); rec.Code != http.StatusOK {
			break
		}
	}
	if h.now.Sub(time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)) <= absoluteLife {
		t.Fatal("test did not pass the absolute lifetime")
	}
	wantRedirect(t, owner.do("GET", "/security", nil), "/login")
}

func TestOriginAndCSRF(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	b := h.browser()
	b.login("alice", ownerPassword)

	if rec := b.do("POST", "/notifications/read", url.Values{"csrf": {"forged"}}); rec.Code != http.StatusForbidden {
		t.Errorf("wrong CSRF token = %d", rec.Code)
	}
	b.origin = "https://evil.example.net"
	if rec := b.do("POST", "/notifications/read", url.Values{}); rec.Code != http.StatusForbidden {
		t.Errorf("foreign Origin = %d", rec.Code)
	}
	b.origin = ""
	if rec := b.do("POST", "/notifications/read", url.Values{}); rec.Code != http.StatusForbidden {
		t.Errorf("missing Origin = %d", rec.Code)
	}
	b.origin = h.srv.origin
	wantRedirect(t, b.do("POST", "/notifications/read", url.Values{}), "/notifications")

	other := h.browser()
	other.origin = "https://evil.example.net"
	if rec := other.login("alice", ownerPassword); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin login = %d", rec.Code)
	}
}

func TestStepUpOnSensitiveActions(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	b := h.browser()
	b.login("alice", ownerPassword)
	h.now = h.now.Add(stepUpWindow + time.Minute)
	for _, path := range []string{
		"/security/password", "/security/totp/begin", "/security/totp/confirm", "/security/totp/disable", "/security/recovery",
		"/vhosts/v00001/delete", "/vhosts/v00001/databases/app/delete", "/vhosts/v00001/dbusers/ro/delete",
		"/vhosts/v00001/dbusers/ro/password", "/vhosts/v00001/dbpassword",
		"/vhosts/v00001/access", "/vhosts/v00001/access/delete", "/vhosts/v00001/keys", "/vhosts/v00001/keys/remove",
	} {
		rec := b.do("POST", path, url.Values{})
		wantRedirect(t, rec, "/reauth")
	}
	if len(h.agent.calls) != 0 {
		t.Errorf("stale sessions reached the agent: %+v", h.agent.calls)
	}

	wantRedirect(t, b.do("POST", "/reauth", url.Values{"password": {ownerPassword}, "next": {"/security"}}), "/security")
	wantRedirect(t, b.do("POST", "/security/totp/begin", url.Values{}), "/security")
}

func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	u := h.user("alice", store.RoleOwner, 3)
	first, second := h.browser(), h.browser()
	first.login("alice", ownerPassword)
	second.login("alice", ownerPassword)
	if rec := first.do("POST", "/security/password", url.Values{"current": {ownerPassword}, "new": {"short"}, "confirm": {"short"}}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("weak password = %d", rec.Code)
	}
	next := "amber falcon quarry"
	wantRedirect(t, first.do("POST", "/security/password", url.Values{"current": {ownerPassword}, "new": {next}, "confirm": {next}}), "/security")
	wantRedirect(t, second.do("GET", "/security", nil), "/login")
	got, _ := h.store.GetUser(ctx, u.ID)
	if ok, _, _ := auth.VerifyPassword(next, got.PasswordHash); !ok {
		t.Error("password not changed")
	}
}

func TestTOTPEnrollment(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	u := h.user("alice", store.RoleOwner, 3)
	b := h.browser()
	b.login("alice", ownerPassword)
	wantRedirect(t, b.do("POST", "/security/totp/begin", url.Values{}), "/security")
	secret, ok := h.srv.enroll.get(hashToken(b.cookie))
	if !ok {
		t.Fatal("no pending secret")
	}
	if rec := b.do("GET", "/security", nil); !strings.Contains(rec.Body.String(), "otpauth://totp/") {
		t.Error("enrollment URI not shown")
	}
	rec := b.do("POST", "/security/totp/confirm", url.Values{"code": {auth.TOTPCode(secret, auth.TOTPStep(h.now))}})
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), "<li><code>") != auth.RecoveryCodeCount {
		t.Fatalf("confirm = %d", rec.Code)
	}
	got, _ := h.store.GetUser(ctx, u.ID)
	if got.TOTPSecret == nil {
		t.Error("secret not stored")
	}
	if left, _ := h.store.RecoveryCodesLeft(ctx, u.ID); left != auth.RecoveryCodeCount {
		t.Errorf("recovery codes = %d", left)
	}
}

func TestRequiredTOTPForcesEnrollment(t *testing.T) {
	h := newHarness(t)
	u := h.user("alice", store.RoleOwner, 3)
	if err := h.store.SetTOTPRequired(context.Background(), u.ID, true); err != nil {
		t.Fatal(err)
	}
	b := h.browser()
	b.login("alice", ownerPassword)
	wantRedirect(t, b.do("GET", "/vhosts", nil), "/security")
	if rec := b.do("GET", "/security", nil); rec.Code != http.StatusOK {
		t.Errorf("security page = %d", rec.Code)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/vhosts": "/vhosts", "//evil.example": "/", "https://evil.example/": "/", "": "/", "/a\\b": "/", "/x\r\nSet-Cookie: a": "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

type selfSignedOnly struct{}

func (selfSignedOnly) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, errors.New("no certificate in this test")
}
func (selfSignedOnly) Trusted() bool { return false }

func TestRunReportsBusyPortBeforeListening(t *testing.T) {
	var lc net.ListenConfig
	busy, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var logs bytes.Buffer
	srv, err := New(Config{Hostname: "panel.example.com", TLSAddr: "127.0.0.1:0", RedirectAddr: busy.Addr().String()},
		Deps{Agent: &fakeAgent{}, Store: st, Certs: selfSignedOnly{}, Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = srv.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "redirect address "+busy.Addr().String()) {
		t.Fatalf("Run = %v, want an error naming the busy redirect address", err)
	}
	if strings.Contains(logs.String(), "panel listening") {
		t.Errorf("logged that the panel listens although binding failed:\n%s", logs.String())
	}
}

func adminOverviewHarness(t *testing.T) (*harness, *browser) {
	t.Helper()
	h := newHarness(t)
	admin := h.user("root-admin", store.RoleAdmin, 0)
	if err := h.store.SetAdminLoginTOTP(context.Background(), admin.ID, false); err != nil {
		t.Fatal(err)
	}
	h.agent.on("vhost.list", func(*api.Actor, string, json.RawMessage) (any, error) {
		return []ops.VhostView{
			{ID: "v00001", OwnerID: 3, PHPVersion: "8.3", Status: "active", Primary: "shop.example.com"},
			{ID: "v00002", OwnerID: 4, PHPVersion: "8.2", Status: "suspended", Primary: "blog.example.org"},
		}, nil
	})
	h.agent.on("owner.list", func(*api.Actor, string, json.RawMessage) (any, error) {
		return []ops.OwnerView{{ID: 3, Name: "Acme Ltd"}, {ID: 4, Name: "Blue Fox"}}, nil
	})
	h.agent.on("php.version.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []string{"8.2", "8.3"}, nil })
	b := h.browser()
	wantRedirect(t, b.login("root-admin", ownerPassword), "/dashboard")
	return h, b
}

func TestAdminDashboardShowsTheServer(t *testing.T) {
	_, b := adminOverviewHarness(t)
	body := b.do("GET", "/dashboard", nil).Body.String()
	for _, want := range []string{"shop.example.com", "blog.example.org", "Acme Ltd", "Blue Fox", "8.2, 8.3",
		`<span class="tile-value">2</span>`, `<span class="tile-value">1</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("admin dashboard lacks %q", want)
		}
	}
}

func TestAdminDashboardWithoutAWindowStillListsVhosts(t *testing.T) {
	h, b := adminOverviewHarness(t)
	h.agent.on("owner.list", func(*api.Actor, string, json.RawMessage) (any, error) {
		return nil, api.Errorf(api.CodeTOTPRequired, "admin code required")
	})
	body := b.do("GET", "/dashboard", nil).Body.String()
	for _, want := range []string{"shop.example.com", `action="/admin/unlock"`, `name="next" value="/dashboard"`} {
		if !strings.Contains(body, want) {
			t.Errorf("locked admin dashboard lacks %q", want)
		}
	}
}

func TestOwnersPageCountsVhosts(t *testing.T) {
	_, b := adminOverviewHarness(t)
	if body := b.do("GET", "/admin/owners", nil).Body.String(); !strings.Contains(body, "1 / 0") {
		t.Errorf("owners page does not count each owner's vhosts against the limit:\n%s", body)
	}
}

func TestNavMarksTheCurrentSection(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	h.agent.on("vhost.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []ops.VhostView{}, nil })
	b := h.browser()
	b.login("alice", ownerPassword)
	body := b.do("GET", "/vhosts", nil).Body.String()
	if !strings.Contains(body, `href="/vhosts" aria-current="page"`) || strings.Contains(body, `href="/dashboard" aria-current`) {
		t.Errorf("nav does not mark /vhosts as current")
	}
}

func TestAdminManagesAVhostAsItsOwner(t *testing.T) {
	h, b := adminOverviewHarness(t)
	h.agent.on("owner.get", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.OwnerView{ID: 3, Name: "Acme Ltd"}, nil
	})
	body := b.do("GET", "/dashboard", nil).Body.String()
	for _, want := range []string{`action="/admin/owners/3/impersonate"`, `name="next" value="/vhosts/v00001"`, ">Manage<"} {
		if !strings.Contains(body, want) {
			t.Errorf("admin dashboard lacks %q", want)
		}
	}
	wantRedirect(t, b.do("POST", "/admin/owners/3/impersonate", url.Values{"next": {"/vhosts/v00001"}}), "/vhosts/v00001?")
	if se, _ := h.store.GetSession(context.Background(), hashToken(b.cookie)); se.Impersonating != 3 {
		t.Errorf("session is not acting as owner 3: %+v", se)
	}

	other := h.browser()
	wantRedirect(t, other.login("root-admin", ownerPassword), "/dashboard")
	wantRedirect(t, other.do("POST", "/admin/owners/3/impersonate", url.Values{"next": {"//evil.example/x"}}), "/?")
}

func TestManageNeedsAnOpenAdminWindow(t *testing.T) {
	h, b := adminOverviewHarness(t)
	h.agent.on("owner.list", func(*api.Actor, string, json.RawMessage) (any, error) {
		return nil, api.Errorf(api.CodeTOTPRequired, "admin code required")
	})
	if body := b.do("GET", "/dashboard", nil).Body.String(); strings.Contains(body, ">Manage<") {
		t.Error("Manage shows while the admin window is closed")
	}
}

// An expired or missing session sends every request to the login page, which returns the user
// to where they were.
func TestExpiredSessionGoesToLoginAndBack(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	h.agent.on("vhost.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []ops.VhostView{}, nil })

	b := h.browser()
	wantRedirect(t, b.do("GET", "/vhosts?x=1", nil), "/login?next=%2Fvhosts%3Fx%3D1")

	b.header = http.Header{"Referer": {"https://panel.example.com:8443/vhosts/v00001"}}
	wantRedirect(t, b.do("POST", "/vhosts/v00001/php", url.Values{"php": {"8.4"}}), "/login?next=%2Fvhosts%2Fv00001")

	b.header.Set("HX-Request", "true")
	rec := b.do("GET", "/jobs/7", nil)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("HX-Redirect") != "/login?next=%2Fvhosts%2Fv00001" {
		t.Errorf("htmx request without a session = %d, HX-Redirect %q", rec.Code, rec.Header().Get("HX-Redirect"))
	}

	if body := b.do("GET", "/login?next=%2Fvhosts", nil).Body.String(); !strings.Contains(body, `name="next" value="/vhosts"`) {
		t.Error("login form does not carry next")
	}
	b.header = nil
	wantRedirect(t, b.do("POST", "/login", url.Values{"username": {"alice"}, "password": {ownerPassword}, "next": {"/vhosts"}}), "/vhosts")

	evil := h.browser()
	wantRedirect(t, evil.do("POST", "/login", url.Values{"username": {"alice"}, "password": {ownerPassword}, "next": {"//evil.example/"}}), "/dashboard")
}

func TestNextSurvivesTheSecondFactor(t *testing.T) {
	h := newHarness(t)
	admin := h.user("root-admin", store.RoleAdmin, 0)
	h.agent.on("admin.totp.verify", func(_ *api.Actor, _ string, args json.RawMessage) (any, error) {
		if strings.Contains(string(args), fmt.Sprintf(`"user_id":%d`, admin.ID)) {
			return nil, nil
		}
		return nil, api.Errorf(api.CodeTOTPInvalid, "code rejected")
	})
	b := h.browser()
	wantRedirect(t, b.do("POST", "/login", url.Values{"username": {"root-admin"}, "password": {ownerPassword}, "next": {"/admin/owners"}}), "/login/totp?next=%2Fadmin%2Fowners")
	if body := b.do("GET", "/login/totp?next=%2Fadmin%2Fowners", nil).Body.String(); !strings.Contains(body, `name="next" value="/admin/owners"`) {
		t.Error("TOTP form does not carry next")
	}
	wantRedirect(t, b.do("POST", "/login/totp", url.Values{"code": {"135790"}, "next": {"/admin/owners"}}), "/admin/owners")
}

func TestVhostPageShowsHowToConnect(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	h.agent.on("vhost.get", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.VhostDetail{VhostView: ops.VhostView{ID: "v00006", OwnerID: 3, PHPVersion: "8.4", Status: "active", Primary: "shop.example.com"},
			Access: &ops.AccessView{Account: "v00006"}}, nil
	})
	h.agent.on("php.version.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []string{"8.4"}, nil })
	h.agent.on("host.ssh.keys", func(*api.Actor, string, json.RawMessage) (any, error) {
		return []ops.HostKeyView{{Type: "ssh-ed25519", Fingerprint: "SHA256:abc123"}}, nil
	})
	b := h.browser()
	b.login("alice", ownerPassword)
	body := b.do("GET", "/vhosts/v00006", nil).Body.String()
	for _, want := range []string{"sftp v00006@panel.example.com", "scp -r", "v00006@panel.example.com:public/", "ssh-ed25519", "SHA256:abc123"} {
		if !strings.Contains(body, want) {
			t.Errorf("vhost page lacks %q", want)
		}
	}
}

func TestHeaderShowsWhoIsSignedIn(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	h.agent.on("vhost.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []ops.VhostView{}, nil })
	h.agent.on("owner.get", func(*api.Actor, string, json.RawMessage) (any, error) { return ops.OwnerView{ID: 3}, nil })
	h.agent.on("usage.get", func(*api.Actor, string, json.RawMessage) (any, error) { return ops.OwnerUsage{}, nil })
	b := h.browser()
	b.login("alice", ownerPassword)
	body := b.do("GET", "/dashboard", nil).Body.String()
	if !strings.Contains(body, `<a class="whoami" href="/security">alice <span class="badge">owner</span></a>`) {
		t.Error("header does not link the signed-in owner to their security page")
	}
	if strings.Contains(body, `>Security</a>`) {
		t.Error("the menu still has a separate Security item")
	}
	if body := b.do("GET", "/security", nil).Body.String(); !strings.Contains(body, `<a class="whoami" href="/security" aria-current="page">`) {
		t.Error("the account link is not marked current on the security page")
	}
}

func TestAdminsPage(t *testing.T) {
	h, b := adminOverviewHarness(t)
	ops := h.user("ops", store.RoleAdmin, 0)
	if err := h.store.SetDisabled(context.Background(), ops.ID, true); err != nil {
		t.Fatal(err)
	}
	body := b.do("GET", "/admin/admins", nil).Body.String()
	for _, want := range []string{"root-admin", "ops", `<span class="badge failed">disabled</span>`, "you",
		"192.0.2.10", "paddock admin add", `<a class="whoami" href="/security">root-admin <span class="badge">admin</span></a>`,
		`href="/admin/admins" aria-current="page"`} {
		if !strings.Contains(body, want) {
			t.Errorf("admins page lacks %q", want)
		}
	}

	h.user("alice", store.RoleOwner, 3)
	owner := h.browser()
	owner.login("alice", ownerPassword)
	if rec := owner.do("GET", "/admin/admins", nil); rec.Code != http.StatusNotFound {
		t.Errorf("owner reached the admins page: %d", rec.Code)
	}
}

func TestStatusTilesLinkToTheirPages(t *testing.T) {
	h, b := adminOverviewHarness(t)
	h.user("ops", store.RoleAdmin, 0)
	h.user("alice", store.RoleOwner, 3)
	body := b.do("GET", "/admin/status", nil).Body.String()
	for _, want := range []string{
		`<a class="tile" href="/admin/php"><span class="tile-label">PHP versions</span><span class="tile-text">8.2, 8.3</span></a>`,
		`<a class="tile" href="/admin/owners"><span class="tile-label">Owners</span><span class="tile-value">2</span></a>`,
		`<a class="tile" href="/admin/admins"><span class="tile-label">Admins</span><span class="tile-value">2</span></a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("status page lacks %q", want)
		}
	}
}

func TestDashboardTilesLinkToTheirPages(t *testing.T) {
	_, b := adminOverviewHarness(t)
	body := b.do("GET", "/dashboard", nil).Body.String()
	for _, want := range []string{
		`<a class="tile" href="/admin/owners"><span class="tile-label">Owners</span>`,
		`<a class="tile" href="/admin/php"><span class="tile-label">PHP</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("admin dashboard lacks %q", want)
		}
	}
}

func TestOwnerDashboardVhostsTileLinksToVhosts(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	h.agent.on("vhost.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []ops.VhostView{}, nil })
	h.agent.on("owner.get", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.OwnerView{ID: 3, Name: "Acme Ltd"}, nil
	})
	b := h.browser()
	b.login("alice", ownerPassword)
	if body := b.do("GET", "/dashboard", nil).Body.String(); !strings.Contains(body, `<a class="tile" href="/vhosts"><span class="tile-label">Vhosts</span>`) {
		t.Errorf("owner dashboard does not link the vhosts tile:\n%s", body)
	}
}

func vhostPage(t *testing.T) string {
	t.Helper()
	_, b := vhostBrowser(t)
	return b.do("GET", "/vhosts/v00006", nil).Body.String()
}

func vhostBrowser(t *testing.T) (*harness, *browser) {
	t.Helper()
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	h.agent.on("vhost.get", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.VhostDetail{VhostView: ops.VhostView{ID: "v00006", OwnerID: 3, PHPVersion: "8.4", Status: "active", Primary: "shop.example.com"},
			Databases: []string{"v00006_shop"}, DBUsers: []ops.DBUserView{{Name: "v00006_report", Grants: "read"}},
			Access: &ops.AccessView{Account: "v00006", Keys: []ops.KeyView{{Fingerprint: "SHA256:k1", PublicKey: "ssh-ed25519 AAAA"}}}}, nil
	})
	h.agent.on("php.version.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []string{"8.4"}, nil })
	h.agent.on("host.ssh.keys", func(*api.Actor, string, json.RawMessage) (any, error) { return []ops.HostKeyView{}, nil })
	b := h.browser()
	b.login("alice", ownerPassword)
	return h, b
}

func TestVhostPageHasBreadcrumbsAndAPageHead(t *testing.T) {
	body := vhostPage(t)
	for _, want := range []string{
		`<nav class="crumbs" aria-label="Breadcrumb"><a href="/vhosts">Vhosts</a> <span aria-current="page">shop.example.com</span></nav>`,
		`<div class="page-head">`, `<h1>shop.example.com</h1>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("vhost page lacks %q", want)
		}
	}
}

func TestVhostPageAsksBeforeDeleting(t *testing.T) {
	body := vhostPage(t)
	for _, want := range []string{
		`data-confirm="Delete database v00006_shop and all its data?"`,
		`data-confirm="Delete DB user v00006_report?"`,
		`data-confirm="Remove key SHA256:k1?"`,
		`data-confirm="Remove SFTP account v00006 and its keys?"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("vhost page lacks %q", want)
		}
	}
}

func TestOwnerPageHasBreadcrumbsAndAPageHead(t *testing.T) {
	h, b := adminOverviewHarness(t)
	h.agent.on("owner.get", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.OwnerView{ID: 3, Name: "Acme Ltd"}, nil
	})
	body := b.do("GET", "/admin/owners/3", nil).Body.String()
	for _, want := range []string{
		`<nav class="crumbs" aria-label="Breadcrumb"><a href="/admin/owners">Owners</a> <span aria-current="page">Acme Ltd</span></nav>`,
		`<div class="page-head">`, `<h1>Acme Ltd</h1>`, `<div class="actions"><form method="post" action="/admin/owners/3/impersonate"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("owner page lacks %q", want)
		}
	}
}

func TestNewVhostPageHasBreadcrumbs(t *testing.T) {
	h := newHarness(t)
	h.user("alice", store.RoleOwner, 3)
	h.agent.on("php.version.list", func(*api.Actor, string, json.RawMessage) (any, error) { return []string{"8.4"}, nil })
	h.agent.on("owner.get", func(*api.Actor, string, json.RawMessage) (any, error) { return ops.OwnerView{ID: 3}, nil })
	b := h.browser()
	b.login("alice", ownerPassword)
	want := `<nav class="crumbs" aria-label="Breadcrumb"><a href="/vhosts">Vhosts</a> <span aria-current="page">New vhost</span></nav>`
	if body := b.do("GET", "/vhosts/new", nil).Body.String(); !strings.Contains(body, want) {
		t.Errorf("new vhost page lacks breadcrumbs:\n%s", body)
	}
}

func TestScriptAsksBeforeConfirmedSubmits(t *testing.T) {
	h := newHarness(t)
	if body := h.browser().do("GET", "/static/app.js", nil).Body.String(); !strings.Contains(body, `"data-confirm"`) || !strings.Contains(body, "window.confirm") {
		t.Error("app.js does not ask before submitting a form with data-confirm")
	}
}

func TestStatusPageShowsVhostHealth(t *testing.T) {
	h, b := adminOverviewHarness(t)
	valid := time.Date(2027, 2, 15, 10, 0, 0, 0, time.UTC)
	soon := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	h.agent.on("server.health", func(*api.Actor, string, json.RawMessage) (any, error) {
		return []ops.VhostHealth{
			{ID: "v00001", OwnerID: 3, Primary: "shop.example.com", Status: "active", Backend: ops.UnitActive, FPM: ops.UnitInactive,
				Cert: ops.CertStatus{Source: "acme", NotAfter: &valid}},
			{ID: "v00002", OwnerID: 4, Primary: "blog.example.org", Status: "suspended",
				Cert: ops.CertStatus{Source: "acme", Error: "urn:ietf:params:acme:error:dns"}},
			{ID: "v00003", OwnerID: 3, Primary: "soon.example.com", Status: "active", Backend: ops.UnitActive, FPM: ops.UnitActive,
				Cert: ops.CertStatus{Source: "acme", NotAfter: &soon}},
			{ID: "v00004", OwnerID: 3, Primary: "new.example.com", Status: "active", Backend: ops.UnitActive, FPM: ops.UnitActive,
				Cert: ops.CertStatus{Source: "acme"}},
		}, nil
	})
	body := b.do("GET", "/admin/status", nil).Body.String()
	for _, want := range []string{
		`<span class="tile-label">Problems</span><span class="tile-value">3</span>`,
		`<span class="badge active">valid until 2027-02-15</span>`,
		`<span class="badge failed">expires 2026-11-25</span>`,
		`<span class="badge failed">error</span> <span class="muted">urn:ietf:params:acme:error:dns</span>`,
		`<span class="badge">pending</span>`,
		`<span class="badge active">running</span>`, `<span class="badge failed">stopped</span>`,
		`<a href="/admin/owners/4">Blue Fox</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("status page lacks %q", want)
		}
	}
}

func TestStatusPageWithoutHealth(t *testing.T) {
	_, b := adminOverviewHarness(t)
	body := b.do("GET", "/admin/status", nil).Body.String()
	if !strings.Contains(body, "The agent could not report vhost health.") || strings.Contains(body, ">Problems<") {
		t.Errorf("status page without health:\n%s", body)
	}
}

func TestHealthRowLabelsAnUploadedCertificate(t *testing.T) {
	until := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	row := healthRow(ops.VhostHealth{Cert: ops.CertStatus{Source: "upload", NotAfter: &until}}, nil, time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC))
	if row.CertLabel != "uploaded, valid until 2027-06-01" || row.CertClass != "active" || row.Problem {
		t.Errorf("row = %+v", row)
	}
}

func TestAdminDashboardDomainsOpenTheVhost(t *testing.T) {
	_, b := adminOverviewHarness(t)
	body := b.do("GET", "/dashboard", nil).Body.String()
	for _, want := range []string{`<form method="post" action="/admin/owners/3/impersonate" class="inline">`,
		`<input type="hidden" name="next" value="/vhosts/v00001"><button type="submit" class="link">shop.example.com</button></form>`} {
		if !strings.Contains(body, want) {
			t.Errorf("admin dashboard does not open the vhost from its domain, lacks %q", want)
		}
	}
}

func TestLockedAdminDashboardShowsDomainsAsText(t *testing.T) {
	h, b := adminOverviewHarness(t)
	h.agent.on("owner.list", func(*api.Actor, string, json.RawMessage) (any, error) {
		return nil, api.Errorf(api.CodeTOTPRequired, "admin code required")
	})
	if body := b.do("GET", "/dashboard", nil).Body.String(); strings.Contains(body, `class="link">shop.example.com`) {
		t.Error("locked admin dashboard offers a domain link that would need an admin code")
	}
}

func TestVhostPageShowsHowToConnectToEachDatabase(t *testing.T) {
	body := vhostPage(t)
	for _, want := range []string{
		`<div class="item-main"><strong><code>v00006_shop</code></strong>` +
			`<span class="item-detail"><span class="label">DSN</span> <code>mysql:unix_socket=/var/lib/mysql/mysql.sock;dbname=v00006_shop</code></span></div>`,
		`user <code>v00006</code>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("vhost page lacks %q", want)
		}
	}
}

func TestNewPasswordPageKeepsTheConnectionDetails(t *testing.T) {
	h, b := vhostBrowser(t)
	h.agent.on("dbuser.password.reset", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.DBCredentials{User: "v00006", Password: "s3cret-once"}, nil
	})
	body := b.do("POST", "/vhosts/v00006/dbpassword", url.Values{}).Body.String()
	for _, want := range []string{"s3cret-once", "sftp v00006@panel.example.com", "mysql:unix_socket=/var/lib/mysql/mysql.sock;dbname=v00006_shop"} {
		if !strings.Contains(body, want) {
			t.Errorf("new password page lacks %q", want)
		}
	}
}

func TestVhostListsShowTheDomainBeforeTheID(t *testing.T) {
	h, admin := adminOverviewHarness(t)
	h.agent.on("owner.get", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.OwnerView{ID: 3, Name: "Acme Ltd"}, nil
	})
	h.agent.on("server.health", func(*api.Actor, string, json.RawMessage) (any, error) {
		return []ops.VhostHealth{{ID: "v00001", OwnerID: 3, Primary: "shop.example.com", Status: "active"}}, nil
	})
	h.user("alice", store.RoleOwner, 3)
	owner := h.browser()
	owner.login("alice", ownerPassword)
	for _, tc := range []struct {
		b    *browser
		path string
		want string
	}{
		{admin, "/dashboard", `shop.example.com</button></form> <code class="muted">v00001</code>`},
		{admin, "/admin/owners/3", `shop.example.com <code class="muted">v00001</code>`},
		{admin, "/admin/status", `shop.example.com <code class="muted">v00001</code>`},
		{owner, "/dashboard", `shop.example.com</a> <code class="muted">v00001</code>`},
		{owner, "/vhosts", `shop.example.com</a> <code class="muted">v00001</code>`},
	} {
		if body := tc.b.do("GET", tc.path, nil).Body.String(); !strings.Contains(body, tc.want) {
			t.Errorf("%s lacks %q", tc.path, tc.want)
		}
	}
}

func TestVhostPageOffersPHPToCopy(t *testing.T) {
	body := vhostPage(t)
	php := `$db = new PDO(&#39;mysql:unix_socket=&#39; . getenv(&#39;DB_SOCKET&#39;) . &#39;;dbname=v00006_shop&#39;, getenv(&#39;DB_USER&#39;));`
	for _, want := range []string{
		`<button type="button" class="secondary small" data-copy="` + php + `" hidden>Copy PHP</button>`,
		`<pre class="wrap"><code>` + php + `</code></pre>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("vhost page lacks %q", want)
		}
	}
}

func TestScriptCopiesToTheClipboard(t *testing.T) {
	h := newHarness(t)
	body := h.browser().do("GET", "/static/app.js", nil).Body.String()
	for _, want := range []string{"data-copy", "navigator.clipboard.writeText"} {
		if !strings.Contains(body, want) {
			t.Errorf("app.js lacks %q", want)
		}
	}
}

func TestAdminDashboardVhostTilesLink(t *testing.T) {
	_, b := adminOverviewHarness(t)
	body := b.do("GET", "/dashboard", nil).Body.String()
	for _, want := range []string{
		`<a class="tile" href="/vhosts"><span class="tile-label">Vhosts</span>`,
		`<a class="tile" href="/vhosts?status=active"><span class="tile-label">Active</span>`,
		`<a class="tile" href="/vhosts?status=suspended"><span class="tile-label">Suspended</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("admin dashboard lacks %q", want)
		}
	}
}

func TestVhostsPageFiltersByStatus(t *testing.T) {
	_, b := adminOverviewHarness(t)
	body := b.do("GET", "/vhosts?status=suspended", nil).Body.String()
	if !strings.Contains(body, "blog.example.org") || strings.Contains(body, "shop.example.com") {
		t.Errorf("suspended filter shows the wrong vhosts:\n%s", body)
	}
	if !strings.Contains(body, `Showing suspended vhosts. <a href="/vhosts">Show all</a>`) {
		t.Error("filtered page does not say so or link back to all vhosts")
	}
	body = b.do("GET", "/vhosts?status=bogus", nil).Body.String()
	if !strings.Contains(body, "blog.example.org") || !strings.Contains(body, "shop.example.com") || strings.Contains(body, "Show all") {
		t.Error("an unknown status filters the list")
	}
}

func TestPagesShowTheMariaDBVersion(t *testing.T) {
	h, b := vhostBrowser(t)
	h.agent.on("db.server.version", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.DBServerView{Product: "MariaDB", Version: "10.11.10"}, nil
	})
	if body := b.do("GET", "/vhosts/v00006", nil).Body.String(); !strings.Contains(body, `<h2 class="with-badge">Databases <span class="badge server">MariaDB 10.11.10</span></h2>`) {
		t.Error("vhost page does not show the MariaDB version")
	}

	h2, admin := adminOverviewHarness(t)
	h2.agent.on("db.server.version", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.DBServerView{Product: "MariaDB", Version: "10.11.10"}, nil
	})
	if body := admin.do("GET", "/admin/status", nil).Body.String(); !strings.Contains(body, `<span class="tile-label">MariaDB</span><span class="tile-text">10.11.10</span>`) {
		t.Error("status page does not show the MariaDB version")
	}
}

func TestVhostLogsPage(t *testing.T) {
	h, b := vhostBrowser(t)
	var asked ops.VhostLogArgs
	h.agent.on("vhost.log.tail", func(_ *api.Actor, _ string, raw json.RawMessage) (any, error) {
		if err := json.Unmarshal(raw, &asked); err != nil {
			return nil, err
		}
		return ops.VhostLog{Lines: []string{`[error] <script>alert(1)</script>`, "PHP Warning: x"}, Truncated: true}, nil
	})
	if body := b.do("GET", "/vhosts/v00006", nil).Body.String(); !strings.Contains(body, `<a class="button secondary" href="/vhosts/v00006/logs">Logs</a>`) {
		t.Error("vhost page does not link to its logs")
	}
	body := b.do("GET", "/vhosts/v00006/logs?log=php&lines=500", nil).Body.String()
	if asked != (ops.VhostLogArgs{VhostID: "v00006", Log: "php", Lines: 500}) {
		t.Errorf("asked the agent for %+v", asked)
	}
	for _, want := range []string{
		`<a href="/vhosts">Vhosts</a> <a href="/vhosts/v00006">shop.example.com</a> <span aria-current="page">Logs</span>`,
		`<a href="/vhosts/v00006/logs?log=php&amp;lines=500" aria-current="page">PHP errors</a>`,
		`&lt;script&gt;alert(1)&lt;/script&gt;`,
		"Showing the last 2 lines.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("logs page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("a log line reached the page unescaped")
	}

	b.do("GET", "/vhosts/v00006/logs?log=bogus&lines=7", nil)
	if asked.Log != "error" || asked.Lines != 200 {
		t.Errorf("unknown values were passed on: %+v", asked)
	}
}

func TestVhostPHPSettingsForm(t *testing.T) {
	h, b := vhostBrowser(t)
	h.agent.on("vhost.get", func(*api.Actor, string, json.RawMessage) (any, error) {
		return ops.VhostDetail{VhostView: ops.VhostView{ID: "v00006", OwnerID: 3, PHPVersion: "8.4", Status: "active", Primary: "shop.example.com"},
			PHP: ops.PHPSettingsView{MemoryLimitMB: 256, UploadMaxMB: 32, MaxExecutionS: 60, MemoryCapMB: 2048}}, nil
	})
	body := b.do("GET", "/vhosts/v00006", nil).Body.String()
	for _, want := range []string{
		`action="/vhosts/v00006/php/settings"`,
		`<input name="memory_limit_mb" type="number" min="32" max="2048" value="256" required>`,
		`<input name="upload_max_mb" type="number" min="1" max="512" value="32" required>`,
		`<input name="max_execution_s" type="number" min="1" max="300" value="60" required>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("vhost page lacks %q", want)
		}
	}

	var asked ops.VhostPHPSettingsArgs
	h.agent.on("vhost.php.settings", func(_ *api.Actor, _ string, raw json.RawMessage) (any, error) {
		if err := json.Unmarshal(raw, &asked); err != nil {
			return nil, err
		}
		return api.JobResult{JobID: "0123456789abcdef0123456789abcdef"}, nil
	})
	rec := b.do("POST", "/vhosts/v00006/php/settings", url.Values{"memory_limit_mb": {"512"}, "upload_max_mb": {"64"}, "max_execution_s": {"120"}})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/jobs/") {
		t.Errorf("POST = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if asked != (ops.VhostPHPSettingsArgs{VhostID: "v00006", MemoryLimitMB: 512, UploadMaxMB: 64, MaxExecutionS: 120}) {
		t.Errorf("asked the agent for %+v", asked)
	}
}

func TestVhostPageSwitchesBackToLetsEncrypt(t *testing.T) {
	h, b := vhostBrowser(t)
	detail := func(source string) func(*api.Actor, string, json.RawMessage) (any, error) {
		return func(*api.Actor, string, json.RawMessage) (any, error) {
			return ops.VhostDetail{VhostView: ops.VhostView{ID: "v00006", OwnerID: 3, PHPVersion: "8.4", Status: "active", Primary: "shop.example.com"},
				Cert: ops.CertStatus{Source: state.CertSource(source)}}, nil
		}
	}
	const form = `action="/vhosts/v00006/cert/acme"`
	h.agent.on("vhost.get", detail("acme"))
	if body := b.do("GET", "/vhosts/v00006", nil).Body.String(); strings.Contains(body, form) {
		t.Error("a vhost already on Let's Encrypt offers to switch to it")
	}
	h.agent.on("vhost.get", detail("upload"))
	body := b.do("GET", "/vhosts/v00006", nil).Body.String()
	if !strings.Contains(body, form) || !strings.Contains(body, `data-confirm="Switch shop.example.com to Let's Encrypt?`) {
		t.Errorf("an uploaded certificate has no way back to Let's Encrypt:\n%s", body)
	}

	var asked ops.VhostIDArgs
	h.agent.on("cert.acme", func(_ *api.Actor, _ string, raw json.RawMessage) (any, error) {
		if err := json.Unmarshal(raw, &asked); err != nil {
			return nil, err
		}
		return ops.CertStatus{Source: state.CertACME}, nil
	})
	rec := b.do("POST", "/vhosts/v00006/cert/acme", url.Values{})
	if rec.Code != http.StatusSeeOther || asked.VhostID != "v00006" {
		t.Errorf("POST = %d, asked for %+v", rec.Code, asked)
	}
}

func TestOwnerDisablesAndEnablesFromTheVhostPage(t *testing.T) {
	h, b := vhostBrowser(t)
	page := func(status, by string) string {
		h.agent.on("vhost.get", func(*api.Actor, string, json.RawMessage) (any, error) {
			return ops.VhostDetail{VhostView: ops.VhostView{ID: "v00006", OwnerID: 3, PHPVersion: "8.4", Status: state.VhostStatus(status),
				SuspendedBy: by, Primary: "shop.example.com"}}, nil
		})
		return b.do("GET", "/vhosts/v00006", nil).Body.String()
	}
	if body := page("active", ""); !strings.Contains(body, `action="/vhosts/v00006/disable" class="inline" data-confirm="Disable shop.example.com?`) {
		t.Error("an active vhost offers no Disable")
	}
	body := page("suspended", "owner")
	if !strings.Contains(body, `action="/vhosts/v00006/enable"`) || !strings.Contains(body, `<span class="badge suspended">disabled</span>`) {
		t.Error("a vhost its owner disabled offers no Enable or is not shown as disabled")
	}
	body = page("suspended", "admin")
	if strings.Contains(body, "/vhosts/v00006/enable") || !strings.Contains(body, "Suspended by an admin.") {
		t.Error("an admin suspension offers the owner an Enable")
	}

	var called []string
	for _, op := range []string{"vhost.disable", "vhost.enable"} {
		h.agent.on(op, func(_ *api.Actor, _ string, raw json.RawMessage) (any, error) {
			called = append(called, op+" "+string(raw))
			return api.JobResult{JobID: "0123456789abcdef0123456789abcdef"}, nil
		})
	}
	for _, path := range []string{"/vhosts/v00006/disable", "/vhosts/v00006/enable"} {
		if rec := b.do("POST", path, url.Values{}); rec.Code != http.StatusSeeOther {
			t.Errorf("POST %s = %d", path, rec.Code)
		}
	}
	if !slices.Equal(called, []string{`vhost.disable {"vhost_id":"v00006"}`, `vhost.enable {"vhost_id":"v00006"}`}) {
		t.Errorf("agent calls = %q", called)
	}
}

func TestAdminDashboardSuspendsAndResumesVhosts(t *testing.T) {
	h, b := adminOverviewHarness(t)
	body := b.do("GET", "/dashboard", nil).Body.String()
	for _, want := range []string{
		`action="/admin/vhosts/v00001/suspend" class="inline" data-confirm="Suspend shop.example.com?`,
		`action="/admin/vhosts/v00002/resume" class="inline"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("admin dashboard lacks %q", want)
		}
	}
	if strings.Contains(body, "/admin/vhosts/v00001/resume") || strings.Contains(body, "/admin/vhosts/v00002/suspend") {
		t.Error("a vhost offers the action matching the state it is already in")
	}

	var called []string
	for _, op := range []string{"vhost.suspend", "vhost.resume"} {
		h.agent.on(op, func(actor *api.Actor, _ string, raw json.RawMessage) (any, error) {
			var args ops.VhostIDArgs
			if err := json.Unmarshal(raw, &args); err != nil {
				return nil, err
			}
			called = append(called, op+" "+args.VhostID+" "+string(actor.Role))
			return api.JobResult{JobID: "0123456789abcdef0123456789abcdef"}, nil
		})
	}
	for _, path := range []string{"/admin/vhosts/v00001/suspend", "/admin/vhosts/v00002/resume"} {
		if rec := b.do("POST", path, url.Values{}); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/jobs/") {
			t.Errorf("POST %s = %d %q", path, rec.Code, rec.Header().Get("Location"))
		}
	}
	if !slices.Equal(called, []string{"vhost.suspend v00001 admin", "vhost.resume v00002 admin"}) {
		t.Errorf("agent calls = %q", called)
	}
}
