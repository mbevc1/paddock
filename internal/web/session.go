package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/web/store"
)

// Session settings (§11.3).
const (
	cookieName      = "__Host-pd_session"
	ownerIdle       = 30 * time.Minute
	adminIdle       = 15 * time.Minute
	absoluteLife    = 12 * time.Hour
	stepUpWindow    = 5 * time.Minute
	touchInterval   = time.Minute
	tokenBytes      = 32
	csrfField       = "csrf"
	csrfHeader      = "X-CSRF-Token"
	maxFormBytes    = 256 << 10
	userAgentMaxLen = 200
)

// Identity is the signed-in user behind a request.
type Identity struct {
	User    store.User
	Session store.Session
	// Pending means the password passed and the second factor has not.
	Pending bool
	// MustEnroll means an admin requires TOTP for this owner and none is enrolled yet.
	MustEnroll bool
}

// Admin reports whether the user is an admin.
func (i *Identity) Admin() bool { return i.User.Role == store.RoleAdmin }

// Impersonating returns the owner an admin acts as, or 0.
func (i *Identity) Impersonating() int64 {
	if !i.Admin() {
		return 0
	}
	return i.Session.Impersonating
}

// OwnerID returns the owner whose resources the user works on: their own, or the one an
// admin impersonates.
func (i *Identity) OwnerID() int64 {
	if i.Admin() {
		return i.Session.Impersonating
	}
	return i.User.OwnerID
}

// Can reports whether the user holds a permission.
func (i *Identity) Can(p Permission) bool {
	if i == nil || i.Pending {
		return p == PermPublic
	}
	return grants[api.Role(i.User.Role)][p]
}

// Actor is how the agent sees this user: an admin, an owner, or an admin acting as an owner.
func (i *Identity) Actor() *api.Actor {
	switch {
	case i.Impersonating() != 0:
		return &api.Actor{UserID: i.User.ID, Role: api.RoleOwner, OwnerID: i.Impersonating(), ImpersonatedBy: i.User.ID}
	case i.Admin():
		return &api.Actor{UserID: i.User.ID, Role: api.RoleAdmin}
	default:
		return &api.Actor{UserID: i.User.ID, Role: api.RoleOwner, OwnerID: i.User.OwnerID}
	}
}

type identityKey struct{}

func identityFrom(r *http.Request) *Identity {
	id, _ := r.Context().Value(identityKey{}).(*Identity)
	return id
}

func randomToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// startSession issues a new session for user, replacing the request's old one if any. mfa
// says the second factor has passed (or none is needed).
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u store.User, mfa bool, impersonating int64) (*Identity, error) {
	if old, err := r.Cookie(cookieName); err == nil {
		if err := s.store.DeleteSession(r.Context(), hashToken(old.Value)); err != nil {
			return nil, err
		}
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	now := s.now()
	ua := r.UserAgent()
	if len(ua) > userAgentMaxLen {
		ua = ua[:userAgentMaxLen]
	}
	se := store.Session{TokenHash: hashToken(token), UserID: u.ID, CreatedAt: now, LastSeen: now, IP: clientIP(r),
		UserAgent: ua, AuthAt: now, CSRFToken: csrf, Impersonating: impersonating}
	if mfa {
		se.MFAAt = now
	}
	if err := s.store.CreateSession(r.Context(), se); err != nil {
		return nil, err
	}
	setSessionCookie(w, token)
	return newIdentity(se, u), nil
}

func newIdentity(se store.Session, u store.User) *Identity {
	id := &Identity{User: u, Session: se, Pending: se.MFAAt.IsZero()}
	id.MustEnroll = !id.Pending && u.Role == store.RoleOwner && u.TOTPRequired && u.TOTPSecret == nil
	return id
}

// loadIdentity returns the request's live session, or nil. Expired or orphaned sessions are
// deleted.
func (s *Server) loadIdentity(r *http.Request) (*Identity, error) {
	c, err := r.Cookie(cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if c.Value == "" {
		return nil, nil
	}
	ctx := r.Context()
	hash := hashToken(c.Value)
	se, err := s.store.GetSession(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u, err := s.store.GetUser(ctx, se.UserID)
	if errors.Is(err, store.ErrNotFound) || err == nil && u.Disabled {
		return nil, s.store.DeleteSession(ctx, hash)
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	idle := ownerIdle
	if u.Role == store.RoleAdmin {
		idle = adminIdle
	}
	if now.Sub(se.LastSeen) > idle || now.Sub(se.CreatedAt) > absoluteLife {
		return nil, s.store.DeleteSession(ctx, hash)
	}
	if now.Sub(se.LastSeen) > touchInterval {
		if err := s.store.TouchSession(ctx, hash, now); err != nil {
			return nil, err
		}
		se.LastSeen = now
	}
	return newIdentity(se, u), nil
}

var stateChanging = map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}

// guard wraps a route: it identifies the user, enforces the route's permission, checks
// Origin and the CSRF token on state-changing requests, and asks for step-up when needed.
func (s *Server) guard(rt Route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.loadIdentity(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if stateChanging[r.Method] {
			if r.Header.Get("Origin") != s.origin {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		}
		switch rt.Perm {
		case PermPublic:
		case PermPending:
			if id == nil || !id.Pending {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		default:
			if id == nil || id.Pending {
				toLogin(w, r)
				return
			}
			if !id.Can(rt.Perm) {
				http.NotFound(w, r)
				return
			}
			if id.MustEnroll && !strings.HasPrefix(r.URL.Path, "/security") && r.URL.Path != "/logout" {
				http.Redirect(w, r, "/security", http.StatusSeeOther)
				return
			}
		}
		if stateChanging[r.Method] && id != nil {
			token := r.Header.Get(csrfHeader)
			if token == "" {
				token = r.PostFormValue(csrfField)
			}
			if subtle.ConstantTimeCompare([]byte(token), []byte(id.Session.CSRFToken)) != 1 {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		if rt.StepUp && s.now().Sub(id.Session.AuthAt) > stepUpWindow {
			next := r.URL.Path
			if r.Method != http.MethodGet {
				next = localReferer(r)
			}
			http.Redirect(w, r, "/reauth?next="+url.QueryEscape(next), http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), identityKey{}, id)
		ctx = context.WithValue(ctx, codeUseKey{}, &codeUse{})
		rt.Handler(w, r.WithContext(ctx))
	})
}

// toLogin sends a request without a session to the login page, which returns the user to the
// page they were on: the requested page, or for a form post or an htmx request the page that
// made it. htmx gets HX-Redirect, so the whole tab moves rather than one fragment.
func toLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.RequestURI()
	htmx := r.Header.Get("HX-Request") == "true"
	if r.Method != http.MethodGet || htmx {
		next = localReferer(r)
	}
	target := "/login"
	if next = safeNext(next); next != "/" {
		target += "?next=" + url.QueryEscape(next)
	}
	if htmx {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// afterLogin is where a signed-in user goes: a safe next path, or the dashboard.
func afterLogin(next string) string {
	if next = safeNext(next); next == "/" {
		return "/dashboard"
	}
	return next
}

// withNext appends a next path to path when there is one worth keeping.
func withNext(path, next string) string {
	if next = safeNext(next); next == "/" {
		return path
	}
	return path + "?next=" + url.QueryEscape(next)
}

// localReferer returns the path of a same-origin Referer, or "/".
func localReferer(r *http.Request) string {
	u, err := url.Parse(r.Referer())
	if err != nil || u.Path == "" {
		return "/"
	}
	return safeNext(u.Path)
}

// safeNext keeps redirects on the panel: a path starting with one slash, nothing else.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		return "/"
	}
	return next
}
