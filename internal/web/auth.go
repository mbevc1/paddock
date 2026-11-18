package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/web/store"
)

const (
	enrollTTL     = 10 * time.Minute
	totpIssuer    = "Paddock"
	maxUsernameIn = 64
)

// pendingSecrets holds TOTP secrets during enrollment, before the user proves they saved one.
type pendingSecrets struct {
	mu      sync.Mutex
	secrets map[string]pendingSecret
	now     func() time.Time
}

type pendingSecret struct {
	secret  []byte
	expires time.Time
}

func newPendingSecrets(now func() time.Time) *pendingSecrets {
	return &pendingSecrets{secrets: map[string]pendingSecret{}, now: now}
}

func (p *pendingSecrets) put(session string, secret []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for k, v := range p.secrets {
		if now.After(v.expires) {
			delete(p.secrets, k)
		}
	}
	p.secrets[session] = pendingSecret{secret: secret, expires: now.Add(enrollTTL)}
}

func (p *pendingSecrets) get(session string) ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.secrets[session]
	if !ok || p.now().After(v.expires) {
		return nil, false
	}
	return v.secret, true
}

func (p *pendingSecrets) drop(session string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.secrets, session)
}

func (s *Server) authRoutes(rt *Router) {
	rt.Handle(Route{Method: "GET", Pattern: "/{$}", Perm: PermPublic, Handler: s.home})
	rt.Handle(Route{Method: "GET", Pattern: "/login", Perm: PermPublic, Handler: s.loginPage})
	rt.Handle(Route{Method: "POST", Pattern: "/login", Perm: PermPublic, Handler: s.login})
	rt.Handle(Route{Method: "GET", Pattern: "/login/totp", Perm: PermPending, Handler: s.totpPage})
	rt.Handle(Route{Method: "POST", Pattern: "/login/totp", Perm: PermPending, Handler: s.loginTOTP})
	rt.Handle(Route{Method: "POST", Pattern: "/logout", Perm: PermSelf, Handler: s.logout})
	rt.Handle(Route{Method: "GET", Pattern: "/reauth", Perm: PermSelf, Handler: s.reauthPage})
	rt.Handle(Route{Method: "POST", Pattern: "/reauth", Perm: PermSelf, Handler: s.reauth})
	rt.Handle(Route{Method: "GET", Pattern: "/security", Perm: PermSelf, Handler: s.securityPage})
	rt.Handle(Route{Method: "POST", Pattern: "/security/password", Perm: PermSelf, StepUp: true, Handler: s.changePassword})
	rt.Handle(Route{Method: "POST", Pattern: "/security/totp/begin", Perm: PermSelf, StepUp: true, Handler: s.beginTOTP})
	rt.Handle(Route{Method: "POST", Pattern: "/security/totp/confirm", Perm: PermSelf, StepUp: true, Handler: s.confirmTOTP})
	rt.Handle(Route{Method: "POST", Pattern: "/security/totp/disable", Perm: PermSelf, StepUp: true, Handler: s.disableTOTP})
	rt.Handle(Route{Method: "POST", Pattern: "/security/recovery", Perm: PermSelf, StepUp: true, Handler: s.newRecoveryCodes})
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	id, err := s.loadIdentity(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	switch {
	case id == nil:
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case id.Pending:
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "login.html", Page{Title: "Sign in"})
}

const loginFailed = "Wrong username or password."

func (s *Server) loginRefused(w http.ResponseWriter, r *http.Request, msg string) {
	s.render(w, r, http.StatusUnauthorized, "login.html", Page{Title: "Sign in", Error: msg})
}

func waitMessage(d time.Duration) string {
	return fmt.Sprintf("Too many failed attempts. Try again in %s.", d.Round(time.Second))
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	if len(username) > maxUsernameIn {
		username = username[:maxUsernameIn]
	}
	keys := []string{"ip:" + clientIP(r), "user:" + strings.ToLower(username)}
	if wait := s.limiter.Wait(keys...); wait > 0 {
		s.loginRefused(w, r, waitMessage(wait))
		return
	}
	u, err := s.store.GetUserByName(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		auth.VerifyDummy(password)
		s.loginFailure(w, r, 0, username, keys)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ok, rehash, err := auth.VerifyPassword(password, u.PasswordHash)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok || u.Disabled {
		s.loginFailure(w, r, u.ID, username, keys)
		return
	}
	if rehash {
		if h, err := auth.HashPassword(password); err == nil {
			if err := s.store.SetPasswordHash(ctx, u.ID, h); err != nil {
				s.log.Error("rehash failed", "err", err)
			}
		}
	}
	needsSecond := u.Role == store.RoleAdmin || u.TOTPSecret != nil
	if _, err := s.startSession(w, r, u, !needsSecond, 0); err != nil {
		s.serverError(w, r, err)
		return
	}
	if needsSecond {
		// The second factor still decides; the IP limiter key is kept until it passes.
		s.limiter.Succeed(keys[1])
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
		return
	}
	s.loginSuccess(w, r, u, keys)
}

func (s *Server) loginFailure(w http.ResponseWriter, r *http.Request, userID int64, username string, keys []string) {
	s.limiter.Fail(keys...)
	if err := s.store.AddLoginEvent(r.Context(), userID, username, clientIP(r), false); err != nil {
		s.log.Error("login event failed", "err", err)
	}
	s.loginRefused(w, r, loginFailed)
}

// loginSuccess records the login, tells the user about a new IP, and opens the dashboard.
func (s *Server) loginSuccess(w http.ResponseWriter, r *http.Request, u store.User, keys []string) {
	ctx := r.Context()
	s.limiter.Succeed(keys...)
	ip := clientIP(r)
	known, err := s.store.KnownIP(ctx, u.ID, ip)
	if err != nil {
		s.log.Error("login history failed", "err", err)
	}
	if err := s.store.AddLoginEvent(ctx, u.ID, u.Username, ip, true); err != nil {
		s.log.Error("login event failed", "err", err)
	}
	if !known {
		s.notifyUser(ctx, u.ID, "login_new_ip", "Sign-in from a new address: "+ip)
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) totpPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "totp.html", Page{Title: "Second factor"})
}

func (s *Server) loginTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFrom(r)
	u := id.User
	keys := []string{"ip:" + clientIP(r), "user:" + strings.ToLower(u.Username)}
	if wait := s.limiter.Wait(keys...); wait > 0 {
		s.render(w, r, http.StatusUnauthorized, "totp.html", Page{Title: "Second factor", Error: waitMessage(wait)})
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	recovery := strings.TrimSpace(r.PostFormValue("recovery"))
	ok, err := s.checkSecondFactor(r, u, code, recovery)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.limiter.Fail(keys...)
		if err := s.store.AddLoginEvent(ctx, u.ID, u.Username, clientIP(r), false); err != nil {
			s.log.Error("login event failed", "err", err)
		}
		s.render(w, r, http.StatusUnauthorized, "totp.html", Page{Title: "Second factor", Error: "That code did not work."})
		return
	}
	if _, err := s.startSession(w, r, u, true, 0); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.loginSuccess(w, r, u, keys)
}

// checkSecondFactor verifies a TOTP code, or for owners a recovery code. Admin codes are
// checked by the agent, which alone holds admins' secrets and opens their admin window.
func (s *Server) checkSecondFactor(r *http.Request, u store.User, code, recovery string) (bool, error) {
	ctx := r.Context()
	if u.Role == store.RoleAdmin {
		if code == "" {
			return false, nil
		}
		err := s.agent.Call(ctx, "admin.totp.verify", nil, "", ops.TOTPVerifyArgs{UserID: u.ID, Code: code}, nil)
		if e := api.AsError(err); e != nil && (e.Code == api.CodeTOTPInvalid || e.Code == api.CodeForbidden) {
			return false, nil
		}
		return err == nil, err
	}
	if recovery != "" {
		return s.store.UseRecoveryCode(ctx, u.ID, auth.HashRecoveryCode(recovery))
	}
	if u.TOTPSecret == nil {
		return false, nil
	}
	step, ok := auth.VerifyTOTP(u.TOTPSecret, code, s.now())
	if !ok {
		return false, nil
	}
	return s.store.UseTOTPStep(ctx, u.ID, step)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSession(r.Context(), identityFrom(r).Session.TokenHash); err != nil {
		s.serverError(w, r, err)
		return
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) reauthPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "reauth.html", Page{Title: "Confirm it is you", Data: safeNext(r.URL.Query().Get("next"))})
}

// reauth refreshes the session's step-up time after a password check.
func (s *Server) reauth(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	next := safeNext(r.PostFormValue("next"))
	keys := []string{"ip:" + clientIP(r), "user:" + strings.ToLower(id.User.Username)}
	if wait := s.limiter.Wait(keys...); wait > 0 {
		s.render(w, r, http.StatusUnauthorized, "reauth.html", Page{Title: "Confirm it is you", Error: waitMessage(wait), Data: next})
		return
	}
	ok, _, err := auth.VerifyPassword(r.PostFormValue("password"), id.User.PasswordHash)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.limiter.Fail(keys...)
		s.render(w, r, http.StatusUnauthorized, "reauth.html", Page{Title: "Confirm it is you", Error: "Wrong password.", Data: next})
		return
	}
	s.limiter.Succeed(keys...)
	if err := s.store.MarkSessionAuth(r.Context(), id.Session.TokenHash, s.now()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// SecurityData is what the security page shows.
type SecurityData struct {
	TOTPEnrolled  bool
	TOTPRequired  bool
	PendingURI    string
	RecoveryLeft  int
	RecoveryCodes []string
	IsAdmin       bool
}

func (s *Server) securityData(r *http.Request) (SecurityData, error) {
	id := identityFrom(r)
	d := SecurityData{TOTPEnrolled: id.User.TOTPSecret != nil, TOTPRequired: id.User.TOTPRequired, IsAdmin: id.Admin()}
	if secret, ok := s.enroll.get(id.Session.TokenHash); ok {
		d.PendingURI = auth.TOTPURI(totpIssuer, id.User.Username, secret)
	}
	left, err := s.store.RecoveryCodesLeft(r.Context(), id.User.ID)
	d.RecoveryLeft = left
	return d, err
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.securityData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	page := Page{Title: "Security", Data: d}
	if identityFrom(r).MustEnroll {
		page.Error = "Your account requires a second factor. Set one up to continue."
	}
	s.render(w, r, http.StatusOK, "security.html", page)
}

func (s *Server) securityError(w http.ResponseWriter, r *http.Request, msg string) {
	d, err := s.securityData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusUnprocessableEntity, "security.html", Page{Title: "Security", Error: msg, Data: d})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFrom(r)
	current, next := r.PostFormValue("current"), r.PostFormValue("new")
	if ok, _, err := auth.VerifyPassword(current, id.User.PasswordHash); err != nil || !ok {
		s.securityError(w, r, "The current password is wrong.")
		return
	}
	if next != r.PostFormValue("confirm") {
		s.securityError(w, r, "The new passwords do not match.")
		return
	}
	if err := auth.CheckPasswordPolicy(next, id.User.Username); err != nil {
		s.securityError(w, r, strings.TrimPrefix(err.Error(), auth.ErrWeakPassword.Error()+": "))
		return
	}
	h, err := auth.HashPassword(next)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SetPasswordHash(ctx, id.User.ID, h); err != nil {
		s.serverError(w, r, err)
		return
	}
	// Other sessions may belong to whoever knew the old password.
	if err := s.store.DeleteUserSessions(ctx, id.User.ID, id.Session.TokenHash); err != nil {
		s.serverError(w, r, err)
		return
	}
	redirectFlash(w, r, "/security", "Password changed. Other sessions were signed out.")
}

func (s *Server) beginTOTP(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	if id.Admin() {
		s.securityError(w, r, "Admin second factors are managed with paddock admin totp-reset on the server.")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.enroll.put(id.Session.TokenHash, secret)
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFrom(r)
	secret, ok := s.enroll.get(id.Session.TokenHash)
	if !ok {
		s.securityError(w, r, "The setup expired. Start again.")
		return
	}
	step, ok := auth.VerifyTOTP(secret, strings.TrimSpace(r.PostFormValue("code")), s.now())
	if !ok {
		s.securityError(w, r, "That code did not match. Check the clock on your device and try again.")
		return
	}
	if err := s.store.SetTOTPSecret(ctx, id.User.ID, secret); err != nil {
		s.serverError(w, r, err)
		return
	}
	if _, err := s.store.UseTOTPStep(ctx, id.User.ID, step); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.enroll.drop(id.Session.TokenHash)
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, id.User.ID, hashes); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.showRecoveryCodes(w, r, codes, "Second factor enabled. Store these recovery codes now; they are shown only once.")
}

func (s *Server) showRecoveryCodes(w http.ResponseWriter, r *http.Request, codes []string, flash string) {
	id := identityFrom(r)
	u, err := s.store.GetUser(r.Context(), id.User.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	id.User = u
	d, err := s.securityData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.RecoveryCodes = codes
	s.render(w, r, http.StatusOK, "security.html", Page{Title: "Security", Flash: flash, Data: d})
}

func (s *Server) disableTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := identityFrom(r)
	if id.Admin() || id.User.TOTPRequired {
		s.securityError(w, r, "Your account requires a second factor.")
		return
	}
	if err := s.store.SetTOTPSecret(ctx, id.User.ID, nil); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, id.User.ID, nil); err != nil {
		s.serverError(w, r, err)
		return
	}
	redirectFlash(w, r, "/security", "Second factor turned off.")
}

func (s *Server) newRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	if id.User.TOTPSecret == nil {
		s.securityError(w, r, "Set up a second factor first.")
		return
	}
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.ReplaceRecoveryCodes(r.Context(), id.User.ID, hashes); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.showRecoveryCodes(w, r, codes, "New recovery codes created; the old ones no longer work.")
}
