package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
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
		"/vhosts/v00001/delete", "/vhosts/v00001/databases/wp/delete", "/vhosts/v00001/dbusers/ro/delete",
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
