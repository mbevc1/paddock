package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

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
	rt.Handle(Route{Method: "POST", Pattern: "/admin/owners/{id}/delete", Perm: PermOwners, StepUp: true, Handler: s.deleteOwner})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/owners/{id}/impersonate", Perm: PermImpersonate, Handler: s.impersonate})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/impersonate/stop", Perm: PermImpersonate, Handler: s.stopImpersonating})
	rt.Handle(Route{Method: "GET", Pattern: "/admin/php", Perm: PermPHP, Handler: s.phpPage})
	rt.Handle(Route{Method: "POST", Pattern: "/admin/php", Perm: PermPHP, Handler: s.changePHP})
	rt.Handle(Route{Method: "GET", Pattern: "/admin/status", Perm: PermServer, Handler: s.statusPage})
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
	var created ops.OwnerCreated
	if err := s.adminCall(r, "owner.create", ops.OwnerCreateArgs{Name: name}, &created); err != nil {
		s.agentFailed(w, r, "/admin/owners", err)
		return
	}
	password, err := auth.RandomPassword()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if _, err := s.store.CreateUser(ctx, username, store.RoleOwner, created.OwnerID, hash); err != nil {
		s.serverError(w, r, err)
		return
	}
	var owners []ops.OwnerView
	if err := s.adminCall(r, "owner.list", struct{}{}, &owners); err != nil {
		s.agentFailed(w, r, "/admin/owners", err)
		return
	}
	s.render(w, r, http.StatusOK, "owners.html", Page{Title: "Owners", Flash: "Owner created. Give the user this password; it is shown only once.",
		Data: OwnersData{Owners: owners, NewUser: username, NewPassword: password}})
}

// OwnerData is what the owner page shows.
type OwnerData struct {
	Owner       ops.OwnerView
	Users       []store.User
	Vhosts      []ops.VhostView
	PHPVersions []string
}

func (s *Server) ownerPage(w http.ResponseWriter, r *http.Request) {
	oid, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	var d OwnerData
	if !s.adminRead(w, r, "owner.get", ops.OwnerIDArgs{OwnerID: oid}, &d.Owner) {
		return
	}
	if !s.adminRead(w, r, "vhost.list", ops.VhostListArgs{OwnerID: oid}, &d.Vhosts) {
		return
	}
	if !s.adminRead(w, r, "php.version.list", struct{}{}, &d.PHPVersions) {
		return
	}
	users, err := s.store.ListUsers(r.Context(), oid)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Users = users
	s.render(w, r, http.StatusOK, "owner.html", Page{Title: d.Owner.Name, Data: d})
}

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
	redirectFlash(w, r, "/dashboard", "You are acting as "+owner.Name+".")
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

func (s *Server) changePHP(w http.ResponseWriter, r *http.Request) {
	op := "php.version.install"
	if r.PostFormValue("action") == "remove" {
		op = "php.version.remove"
	}
	var job api.JobResult
	if err := s.adminCall(r, op, ops.PHPVersionArgs{Version: r.PostFormValue("version")}, &job); err != nil {
		s.agentFailed(w, r, "/admin/php", err)
		return
	}
	http.Redirect(w, r, "/jobs/"+job.JobID+"?next=/admin/php", http.StatusSeeOther)
}

// StatusData is what the server status page shows.
type StatusData struct {
	Version     string
	AgentOK     bool
	PHPVersions []string
	Owners      int
	Users       int
}

func (s *Server) statusPage(w http.ResponseWriter, r *http.Request) {
	d := StatusData{Version: Version}
	d.AgentOK = s.adminCall(r, "php.version.list", struct{}{}, &d.PHPVersions) == nil
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
	d.Users = len(users)
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
