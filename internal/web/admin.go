package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/auth"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/validate"
	"github.com/mbevc1/paddock/internal/web/store"
)

// Version is the running panel's version, shown on the status page.
var Version = "dev"

func (s *Server) adminRoutes(rt *Router) {
	rt.Handle(Route{Method: "POST", Pattern: "/admin/unlock", Perm: PermServer, Handler: s.adminUnlock})
	rt.Handle(Route{Method: "GET", Pattern: "/admin/owners", Perm: PermOwners, Handler: s.ownersPage})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/owners", Perm: PermOwners, Handler: s.createOwner})
	rt.Handle(Route{Method: "GET", Pattern: "/admin/owners/{id}", Perm: PermOwners, Handler: s.ownerPage})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/owners/{id}/limits", Perm: PermOwners, Handler: s.setLimits})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/owners/{id}/totp", Perm: PermOwners, Handler: s.requireTOTP})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/owners/{id}/users/{uid}/password", Perm: PermOwners, StepUp: true, Handler: s.resetUserPassword})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/owners/{id}/delete", Perm: PermOwners, StepUp: true, Handler: s.deleteOwner})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/owners/{id}/impersonate", Perm: PermImpersonate, Handler: s.impersonate})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/impersonate/stop", Perm: PermImpersonate, Handler: s.stopImpersonating})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/vhosts/{id}/suspend", Perm: PermOwners, Handler: s.suspendVhost})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/vhosts/{id}/resume", Perm: PermOwners, Handler: s.resumeVhost})
	rt.Handle(Route{Method: "GET", Pattern: "/admin/php", Perm: PermPHP, Handler: s.phpPage})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/php", Perm: PermPHP, Handler: s.changePHP})
	rt.Handle(Route{Method: "GET", Pattern: "/admin/status", Perm: PermServer, Handler: s.statusPage})
	rt.Handle(Route{Method: "GET", Pattern: "/admin/admins", Perm: PermServer, Handler: s.adminsPage})
	rt.Handle(Route{Method: "GET", Pattern: "/admin/audit", Perm: PermAudit, Handler: s.auditPage})
}

// codeUse tracks whether a request already sent its TOTP code to the agent.
type codeUse struct{ sent bool }

type codeUseKey struct{}

// adminCall runs an admin operation. The form's TOTP code, if any, goes with the request's
// first admin call only: the agent accepts each code once, and that call opens the admin's
// 10-minute window, which covers the request's later calls.
func (s *Server) adminCall(r *http.Request, op string, args, result any) error {
	id := identityFrom(r)
	actor := &api.Actor{UserID: id.User.ID, Role: api.RoleAdmin}
	code := strings.TrimSpace(r.PostFormValue("totp"))
	if use, ok := r.Context().Value(codeUseKey{}).(*codeUse); ok {
		if use.sent {
			code = ""
		} else if code != "" {
			use.sent = true
		}
	}
	return s.agent.Call(r.Context(), op, actor, code, args, result)
}

// adminRead runs an admin read; when the agent wants a fresh code it shows the unlock form.
func (s *Server) adminRead(w http.ResponseWriter, r *http.Request, op string, args, result any) bool {
	err := s.adminCall(r, op, args, result)
	if err == nil {
		return true
	}
	if e := api.AsError(err); e != nil && (e.Code == api.CodeTOTPRequired || e.Code == api.CodeTOTPInvalid) {
		s.render(w, r, http.StatusOK, "admin_unlock.html", Page{Title: "Confirm admin access", Data: r.URL.RequestURI()})
		return false
	}
	s.agentFailed(w, r, "/dashboard", err)
	return false
}

// adminUnlock checks a TOTP code with the agent, which opens the admin's window.
func (s *Server) adminUnlock(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	next := safeNext(r.PostFormValue("next"))
	err := s.agent.Call(r.Context(), "admin.totp.verify", nil, "", ops.TOTPVerifyArgs{UserID: id.User.ID, Code: strings.TrimSpace(r.PostFormValue("code"))}, nil)
	if err != nil {
		s.render(w, r, http.StatusUnauthorized, "admin_unlock.html", Page{Title: "Confirm admin access", Error: "That code did not work.", Data: next})
		return
	}
	if err := s.store.MarkSessionAuth(r.Context(), id.Session.TokenHash, s.now()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// OwnersData is what the owners page shows; NewPassword is a created user's first password.
type OwnersData struct {
	Owners      []ops.OwnerView
	VhostCounts map[int64]int
	NewUser     string
	NewPassword string
}

func (s *Server) ownersPage(w http.ResponseWriter, r *http.Request) {
	var owners []ops.OwnerView
	if !s.adminRead(w, r, "owner.list", struct{}{}, &owners) {
		return
	}
	var vhosts []ops.VhostView
	if err := s.agentCall(r, "vhost.list", ops.VhostListArgs{}, &vhosts); err != nil {
		s.agentFailed(w, r, "/dashboard", err)
		return
	}
	counts := map[int64]int{}
	for _, v := range vhosts {
		counts[v.OwnerID]++
	}
	s.render(w, r, http.StatusOK, "owners.html", Page{Title: "Owners", Data: OwnersData{Owners: owners, VhostCounts: counts}})
}

// createOwner creates the owner in the agent and the owner's first panel user here, with a
// random password shown once.
func (s *Server) createOwner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := strings.TrimSpace(r.PostFormValue("name"))
	username := strings.TrimSpace(r.PostFormValue("username"))
	if err := validate.Username(username); err != nil {
		redirectError(w, r, "/admin/owners", err.Error())
		return
	}
	if _, err := s.store.GetUserByName(ctx, username); err == nil {
		redirectError(w, r, "/admin/owners", "That username is taken.")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	// A chosen password is checked before the owner exists, so a weak one creates nothing.
	password := r.PostFormValue("password")
	chosen := password != ""
	if chosen {
		if err := auth.CheckPasswordPolicy(password, username); err != nil {
			redirectError(w, r, "/admin/owners", strings.TrimPrefix(err.Error(), auth.ErrWeakPassword.Error()+": "))
			return
		}
	}
	var created ops.OwnerCreated
	if err := s.adminCall(r, "owner.create", ops.OwnerCreateArgs{Name: name}, &created); err != nil {
		s.agentFailed(w, r, "/admin/owners", err)
		return
	}
	if !chosen {
		var err error
		if password, err = auth.RandomPassword(); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	user, err := s.store.CreateUser(ctx, username, store.RoleOwner, created.OwnerID, hash)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SetMustChangePassword(ctx, user.ID, requestReset(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	var owners []ops.OwnerView
	if err := s.adminCall(r, "owner.list", struct{}{}, &owners); err != nil {
		s.agentFailed(w, r, "/admin/owners", err)
		return
	}
	if chosen {
		s.render(w, r, http.StatusOK, "owners.html", Page{Title: "Owners", Flash: "Owner created. The user signs in with the password you chose.",
			Data: OwnersData{Owners: owners}})
		return
	}
	s.render(w, r, http.StatusOK, "owners.html", Page{Title: "Owners", Flash: "Owner created. Give the user this password; it is shown only once.",
		Data: OwnersData{Owners: owners, NewUser: username, NewPassword: password}})
}

// OwnerData is what the owner page shows; Reset is a password an admin just reset.
type OwnerData struct {
	Owner       ops.OwnerView
	Users       []store.User
	Vhosts      []ops.VhostView
	PHPVersions []string
	Reset       *PasswordReset
}

// PasswordReset is a user's new password, shown once.
type PasswordReset struct {
	Username, Password string
}

// ownerData loads what the owner page shows; on failure it has answered the request.
func (s *Server) ownerData(w http.ResponseWriter, r *http.Request, oid int64) (OwnerData, bool) {
	var d OwnerData
	if !s.adminRead(w, r, "owner.get", ops.OwnerIDArgs{OwnerID: oid}, &d.Owner) {
		return d, false
	}
	if !s.adminRead(w, r, "vhost.list", ops.VhostListArgs{OwnerID: oid}, &d.Vhosts) {
		return d, false
	}
	if !s.adminRead(w, r, "php.version.list", struct{}{}, &d.PHPVersions) {
		return d, false
	}
	users, err := s.store.ListUsers(r.Context(), oid)
	if err != nil {
		s.serverError(w, r, err)
		return d, false
	}
	d.Users = users
	return d, true
}

func (s *Server) ownerPage(w http.ResponseWriter, r *http.Request) {
	oid, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	d, ok := s.ownerData(w, r, oid)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "owner.html", Page{Title: d.Owner.Name, Data: d})
}

// resetUserPassword gives one of the owner's users the password the admin chose, or a random
// one shown once, and ends all of that user's sessions. Admins' passwords are reset on the server.
func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	oid, ok := pathID(r)
	uid, err := strconv.ParseInt(r.PathValue("uid"), 10, 64)
	if !ok || err != nil || uid <= 0 {
		http.NotFound(w, r)
		return
	}
	u, err := s.store.GetUser(ctx, uid)
	if err != nil || u.Role != store.RoleOwner || u.OwnerID != oid {
		http.NotFound(w, r)
		return
	}
	password := r.PostFormValue("password")
	chosen := password != ""
	if chosen {
		if err := auth.CheckPasswordPolicy(password, u.Username); err != nil {
			redirectError(w, r, ownerPath(oid), strings.TrimPrefix(err.Error(), auth.ErrWeakPassword.Error()+": "))
			return
		}
	}
	d, ok := s.ownerData(w, r, oid)
	if !ok {
		return
	}
	if !chosen {
		if password, err = auth.RandomPassword(); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SetPasswordHash(ctx, u.ID, hash); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.SetMustChangePassword(ctx, u.ID, requestReset(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.store.DeleteUserSessions(ctx, u.ID, ""); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("password reset by an admin", "admin", identityFrom(r).User.Username, "user", u.Username)
	if chosen {
		s.render(w, r, http.StatusOK, "owner.html", Page{Title: d.Owner.Name, Data: d,
			Flash: "Password set for " + u.Username + ". Their sessions were ended."})
		return
	}
	d.Reset = &PasswordReset{Username: u.Username, Password: password}
	s.render(w, r, http.StatusOK, "owner.html", Page{Title: d.Owner.Name, Data: d})
}

// requestReset reports whether the admin asked the user to choose a new password at the next
// sign-in.
func requestReset(r *http.Request) bool { return r.PostFormValue("request_reset") != "" }

func ownerPath(oid int64) string { return "/admin/owners/" + strconv.FormatInt(oid, 10) }

// formLimits reads the limit fields an admin filled in; empty fields keep their value.
func formLimits(r *http.Request) (ops.LimitsArgs, error) {
	var l ops.LimitsArgs
	ints := map[string]**int{
		"max_vhosts": &l.MaxVhosts, "disk_mb": &l.DiskMB, "max_databases": &l.MaxDatabases, "max_db_users": &l.MaxDBUsers,
		"max_access_accounts": &l.MaxAccessAccounts, "memory_max_mb": &l.MemoryMaxMB, "cpu_quota_pct": &l.CPUQuotaPct,
		"tasks_max": &l.TasksMax, "pm_max_children": &l.PMMaxChildren, "max_user_connections": &l.MaxUserConnections,
	}
	for field, dst := range ints {
		v := strings.TrimSpace(r.PostFormValue(field))
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return l, errors.New(field + " must be a number")
		}
		*dst = &n
	}
	php := r.PostForm["php_versions"]
	l.PHPVersions = &php
	return l, nil
}

func (s *Server) setLimits(w http.ResponseWriter, r *http.Request) {
	oid, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	limits, err := formLimits(r)
	if err != nil {
		redirectError(w, r, ownerPath(oid), err.Error())
		return
	}
	if err := s.adminCall(r, "owner.limits.set", ops.OwnerLimitsArgs{OwnerID: oid, Limits: limits}, nil); err != nil {
		s.agentFailed(w, r, ownerPath(oid), err)
		return
	}
	redirectFlash(w, r, ownerPath(oid), "Limits saved.")
}

// requireTOTP makes a second factor mandatory, or optional, for the owner's users.
func (s *Server) requireTOTP(w http.ResponseWriter, r *http.Request) {
	oid, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	required := r.PostFormValue("required") == "on"
	users, err := s.store.ListUsers(r.Context(), oid)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, u := range users {
		if err := s.store.SetTOTPRequired(r.Context(), u.ID, required); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	redirectFlash(w, r, ownerPath(oid), "Second-factor requirement saved.")
}

func (s *Server) deleteOwner(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	oid, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := s.adminCall(r, "owner.delete", ops.OwnerIDArgs{OwnerID: oid}, nil); err != nil {
		s.agentFailed(w, r, ownerPath(oid), err)
		return
	}
	users, err := s.store.ListUsers(ctx, oid)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, u := range users {
		if err := s.store.DeleteUser(ctx, u.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	redirectFlash(w, r, "/admin/owners", "Owner deleted.")
}

// impersonate starts acting as an owner. The session token is rotated, the owner's users are
// told, and every agent call from now on names both identities.
func (s *Server) impersonate(w http.ResponseWriter, r *http.Request) {
	oid, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	id := identityFrom(r)
	var owner ops.OwnerView
	if err := s.adminCall(r, "owner.get", ops.OwnerIDArgs{OwnerID: oid}, &owner); err != nil {
		s.agentFailed(w, r, ownerPath(oid), err)
		return
	}
	if err := s.rotateSession(w, r, oid); err != nil {
		s.serverError(w, r, err)
		return
	}
	users, err := s.store.ListUsers(r.Context(), oid)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, u := range users {
		s.notifyUser(r.Context(), u.ID, "impersonation", "Admin "+id.User.Username+" started acting on your account.")
	}
	dest := "/dashboard"
	if next := r.PostFormValue("next"); next != "" {
		dest = next
	}
	redirectFlash(w, r, dest, "You are acting as "+owner.Name+".")
}

func (s *Server) stopImpersonating(w http.ResponseWriter, r *http.Request) {
	if err := s.rotateSession(w, r, 0); err != nil {
		s.serverError(w, r, err)
		return
	}
	redirectFlash(w, r, "/admin/owners", "You are acting as yourself again.")
}

// rotateSession replaces the session with a fresh token on a privilege change, keeping the
// step-up time.
func (s *Server) rotateSession(w http.ResponseWriter, r *http.Request, impersonating int64) error {
	id := identityFrom(r)
	next, err := s.startSession(w, r, id.User, true, impersonating)
	if err != nil {
		return err
	}
	return s.store.MarkSessionAuth(r.Context(), next.Session.TokenHash, id.Session.AuthAt)
}

func (s *Server) phpPage(w http.ResponseWriter, r *http.Request) {
	var versions []string
	if !s.adminRead(w, r, "php.version.list", struct{}{}, &versions) {
		return
	}
	s.render(w, r, http.StatusOK, "php.html", Page{Title: "PHP versions", Data: versions})
}

func (s *Server) suspendVhost(w http.ResponseWriter, r *http.Request) {
	s.adminJob(w, r, "vhost.suspend", ops.VhostIDArgs{VhostID: r.PathValue("id")}, "/dashboard")
}

func (s *Server) resumeVhost(w http.ResponseWriter, r *http.Request) {
	s.adminJob(w, r, "vhost.resume", ops.VhostIDArgs{VhostID: r.PathValue("id")}, "/dashboard")
}

// adminJob starts a long admin operation and shows its progress page, which returns to back.
func (s *Server) adminJob(w http.ResponseWriter, r *http.Request, op string, args any, back string) {
	var job api.JobResult
	if err := s.adminCall(r, op, args, &job); err != nil {
		s.agentFailed(w, r, back, err)
		return
	}
	http.Redirect(w, r, "/jobs/"+job.JobID+"?next="+url.QueryEscape(back), http.StatusSeeOther)
}

func (s *Server) changePHP(w http.ResponseWriter, r *http.Request) {
	op := "php.version.install"
	if r.PostFormValue("action") == "remove" {
		op = "php.version.remove"
	}
	s.adminJob(w, r, op, ops.PHPVersionArgs{Version: r.PostFormValue("version")}, "/admin/php")
}

// StatusData is what the server status page shows.
type StatusData struct {
	Version     string
	AgentOK     bool
	PHPVersions []string
	Owners      int
	Admins      int
	// DBServer is empty when the agent could not read it.
	DBServer ops.DBServerView
	// HealthOK is false when the agent could not report Health.
	HealthOK bool
	Health   []HealthRow
	Problems int
}

// HealthRow is one vhost on the status page, with its certificate and services summarized.
type HealthRow struct {
	ops.VhostHealth
	OwnerName string
	CertLabel string
	CertClass string
	Problem   bool
}

func healthRow(v ops.VhostHealth, owners map[int64]string, now time.Time) HealthRow {
	row := HealthRow{VhostHealth: v, OwnerName: owners[v.OwnerID]}
	c := v.Cert
	switch {
	case c.Error != "":
		row.CertLabel, row.CertClass, row.Problem = "error", "failed", true
	case c.NotAfter == nil:
		row.CertLabel = "pending"
	case c.NotAfter.Sub(now) < ops.CertWarnWindow:
		row.CertLabel, row.CertClass, row.Problem = "expires "+c.NotAfter.UTC().Format(time.DateOnly), "failed", true
	default:
		row.CertLabel, row.CertClass = "valid until "+c.NotAfter.UTC().Format(time.DateOnly), "active"
	}
	if c.Source == state.CertUpload && c.Error == "" {
		row.CertLabel = "uploaded, " + row.CertLabel
	}
	for _, u := range []ops.UnitState{v.Backend, v.FPM} {
		if u == ops.UnitInactive || u == ops.UnitUnknown {
			row.Problem = true
		}
	}
	return row
}

// AdminRow is one admin on the admins page; Last is nil before their first sign-in.
type AdminRow struct {
	User store.User
	Last *store.LoginRecord
}

// AdminsData is what the admins page shows; Me is the viewer's user ID.
type AdminsData struct {
	Admins []AdminRow
	Me     int64
}

// adminsPage lists the admins from web.db. Root manages them with paddock admin on the server,
// so the page has no actions.
func (s *Server) adminsPage(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context(), 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	last, err := s.store.LastLogins(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := AdminsData{Me: identityFrom(r).User.ID}
	for _, u := range users {
		if u.Role != store.RoleAdmin {
			continue
		}
		row := AdminRow{User: u}
		if l, ok := last[u.ID]; ok {
			row.Last = &l
		}
		d.Admins = append(d.Admins, row)
	}
	s.render(w, r, http.StatusOK, "admins.html", Page{Title: "Admins", Data: d})
}

func (s *Server) statusPage(w http.ResponseWriter, r *http.Request) {
	d := StatusData{Version: Version}
	d.AgentOK = s.adminCall(r, "php.version.list", struct{}{}, &d.PHPVersions) == nil
	if err := s.adminCall(r, "db.server.version", struct{}{}, &d.DBServer); err != nil {
		s.log.Warn("reading the MariaDB version failed", "err", err)
	}
	var owners []ops.OwnerView
	if !s.adminRead(w, r, "owner.list", struct{}{}, &owners) {
		return
	}
	d.Owners = len(owners)
	users, err := s.store.ListUsers(r.Context(), 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, u := range users {
		if u.Role == store.RoleAdmin {
			d.Admins++
		}
	}
	var health []ops.VhostHealth
	if err := s.adminCall(r, "server.health", struct{}{}, &health); err != nil {
		s.log.Warn("reading server health failed", "err", err)
	} else {
		names := make(map[int64]string, len(owners))
		for _, o := range owners {
			names[o.ID] = o.Name
		}
		d.HealthOK = true
		for _, v := range health {
			row := healthRow(v, names, s.now())
			if row.Problem {
				d.Problems++
			}
			d.Health = append(d.Health, row)
		}
	}
	s.render(w, r, http.StatusOK, "status.html", Page{Title: "Server status", Data: d})
}

// AuditData is one page of the audit log; Older is the cursor for the next page.
type AuditData struct {
	Entries []state.AuditEntry
	Older   int64
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	var entries []state.AuditEntry
	if !s.adminRead(w, r, "audit.list", ops.AuditListArgs{Before: before, Limit: 50}, &entries) {
		return
	}
	d := AuditData{Entries: entries}
	if len(entries) == 50 {
		d.Older = entries[len(entries)-1].ID
	}
	s.render(w, r, http.StatusOK, "audit.html", Page{Title: "Audit log", Data: d})
}
