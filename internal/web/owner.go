package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/agent/ops"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/mariadb"
	"github.com/mbevc1/paddock/internal/state"
)

var jobIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (s *Server) ownerRoutes(rt *Router) {
	rt.Handle(Route{Method: "GET", Pattern: "/dashboard", Perm: PermSelf, Handler: s.dashboard})
	rt.Handle(Route{Method: "GET", Pattern: "/jobs/{id}", Perm: PermSelf, Handler: s.jobPage})

	rt.Handle(Route{Method: "GET", Pattern: "/vhosts", Perm: PermVhosts, Handler: s.vhostsPage})
	rt.Handle(Route{Method: "GET", Pattern: "/vhosts/new", Perm: PermVhosts, Handler: s.newVhostPage})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts", Perm: PermVhosts, Handler: s.createVhost})
	rt.Handle(Route{Method: "GET", Pattern: "/vhosts/{id}", Perm: PermVhosts, Handler: s.vhostPage})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/aliases", Perm: PermVhosts, Handler: s.updateAliases})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/php", Perm: PermVhosts, Handler: s.switchPHP})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/delete", Perm: PermVhosts, StepUp: true, Handler: s.deleteVhost})

	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/databases", Perm: PermDatabases, Handler: s.createDatabase})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/databases/{suffix}/delete", Perm: PermDatabases, StepUp: true, Handler: s.deleteDatabase})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/dbusers", Perm: PermDatabases, Handler: s.createDBUser})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/dbusers/{suffix}/delete", Perm: PermDatabases, StepUp: true, Handler: s.deleteDBUser})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/dbusers/{suffix}/password", Perm: PermDatabases, StepUp: true, Handler: s.resetDBPassword})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/dbpassword", Perm: PermDatabases, StepUp: true, Handler: s.resetDBPassword})

	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/access", Perm: PermAccess, StepUp: true, Handler: s.createAccess})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/access/delete", Perm: PermAccess, StepUp: true, Handler: s.deleteAccess})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/keys", Perm: PermAccess, StepUp: true, Handler: s.addKey})
	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/keys/remove", Perm: PermAccess, StepUp: true, Handler: s.removeKey})

	rt.Handle(Route{Method: "POST", Pattern: "/vhosts/{id}/cert", Perm: PermCerts, Handler: s.uploadCert})
}

// agentFailed answers an agent error: not_found becomes a 404, so other owners' IDs look like
// missing ones; anything else goes back to the form with the agent's message.
func (s *Server) agentFailed(w http.ResponseWriter, r *http.Request, back string, err error) {
	e := api.AsError(err)
	switch {
	case e != nil && e.Code == api.CodeNotFound:
		s.render(w, r, http.StatusNotFound, "error.html", Page{Title: "Not found", Error: "Not found."})
	case e != nil && (e.Code == api.CodeTOTPRequired || e.Code == api.CodeTOTPInvalid):
		redirectError(w, r, back, "Enter a current code from your authenticator to confirm admin actions.")
	case e == nil:
		s.serverError(w, r, err)
	default:
		redirectError(w, r, back, agentMessage(err))
	}
}

func redirectError(w http.ResponseWriter, r *http.Request, path, msg string) {
	target := safeNext(path)
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	http.Redirect(w, r, target+sep+"error="+url.QueryEscape(msg), http.StatusSeeOther) // #nosec G710 -- safeNext keeps the target a local path.
}

// startJob runs a long agent operation and shows its progress page.
func (s *Server) startJob(w http.ResponseWriter, r *http.Request, op string, args any, back, next string) {
	var job api.JobResult
	if err := s.agentCall(r, op, args, &job); err != nil {
		s.agentFailed(w, r, back, err)
		return
	}
	http.Redirect(w, r, "/jobs/"+job.JobID+"?next="+url.QueryEscape(safeNext(next)), http.StatusSeeOther)
}

// JobData is what the job page shows.
type JobData struct {
	ID   string
	Next string
	Job  agent.JobView
	Done bool
}

func (s *Server) jobPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !jobIDPattern.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	var v agent.JobView
	if err := s.agentCall(r, "job.get", map[string]string{"job_id": id}, &v); err != nil {
		s.agentFailed(w, r, next, err)
		return
	}
	done := v.Status == state.JobSucceeded || v.Status == state.JobFailed
	if v.Status == state.JobSucceeded && r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", next+"?flash="+url.QueryEscape("Done."))
	}
	s.render(w, r, http.StatusOK, "job.html", Page{Title: "Working", Data: JobData{ID: id, Next: next, Job: v, Done: done}})
}

// DashboardData is what the dashboard shows.
type DashboardData struct {
	Vhosts    []ops.VhostView
	Usage     *ops.OwnerUsage
	Owner     *ops.OwnerView
	AdminHome bool
	Admin     *AdminOverview
}

// AdminOverview is the admin's dashboard. Owners and PHP versions are admin operations, so
// they show only while the admin window is open; Locked says it is not.
type AdminOverview struct {
	Locked      bool
	OwnerNames  map[int64]string
	PHPVersions []string
	Active      int
	Suspended   int
	Other       int
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	d := DashboardData{AdminHome: id.Admin() && id.Impersonating() == 0}
	if d.AdminHome {
		s.adminDashboard(w, r, d)
		return
	}
	if err := s.agentCall(r, "vhost.list", ops.VhostListArgs{}, &d.Vhosts); err != nil {
		s.agentFailed(w, r, "/security", err)
		return
	}
	var owner ops.OwnerView
	if err := s.agentCall(r, "owner.get", ops.OwnerIDArgs{OwnerID: id.OwnerID()}, &owner); err == nil {
		d.Owner = &owner
	}
	var usage ops.OwnerUsage
	if err := s.agentCall(r, "usage.get", ops.UsageArgs{OwnerID: id.OwnerID()}, &usage); err == nil {
		d.Usage = &usage
	}
	s.render(w, r, http.StatusOK, "dashboard.html", Page{Title: "Dashboard", Data: d, Error: r.URL.Query().Get("error")})
}

func (s *Server) vhostsPage(w http.ResponseWriter, r *http.Request) {
	var list []ops.VhostView
	if err := s.agentCall(r, "vhost.list", ops.VhostListArgs{}, &list); err != nil {
		s.agentFailed(w, r, "/dashboard", err)
		return
	}
	s.render(w, r, http.StatusOK, "vhosts.html", Page{Title: "Vhosts", Data: list, Error: r.URL.Query().Get("error")})
}

// NewVhostData is what the create form offers.
type NewVhostData struct {
	PHPVersions []string
	NeedsOwner  bool
}

func (s *Server) newVhostPage(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	d := NewVhostData{NeedsOwner: id.OwnerID() == 0}
	if err := s.agentCall(r, "php.version.list", struct{}{}, &d.PHPVersions); err != nil {
		s.agentFailed(w, r, "/vhosts", err)
		return
	}
	s.render(w, r, http.StatusOK, "vhost_new.html", Page{Title: "New vhost", Data: d, Error: r.URL.Query().Get("error")})
}

// domainList splits a form field of domains separated by spaces, commas, or new lines.
func domainList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

func (s *Server) createVhost(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	if id.OwnerID() == 0 {
		redirectError(w, r, "/vhosts/new", "Admins create vhosts while acting as an owner: open the owner and choose Act as owner.")
		return
	}
	args := ops.VhostCreateArgs{
		OwnerID:       id.OwnerID(),
		PrimaryDomain: strings.TrimSpace(r.PostFormValue("primary")),
		Aliases:       domainList(r.PostFormValue("aliases")),
		PHPVersion:    r.PostFormValue("php"),
		Database:      strings.TrimSpace(r.PostFormValue("database")),
	}
	s.startJob(w, r, "vhost.create", args, "/vhosts/new", "/vhosts")
}

// vhostPageData loads what the vhost page shows; on failure it has answered the request.
func (s *Server) vhostPageData(w http.ResponseWriter, r *http.Request) (VhostPageData, bool) {
	var d ops.VhostDetail
	if err := s.agentCall(r, "vhost.get", ops.VhostIDArgs{VhostID: r.PathValue("id")}, &d); err != nil {
		s.agentFailed(w, r, "/vhosts", err)
		return VhostPageData{}, false
	}
	var versions []string
	if err := s.agentCall(r, "php.version.list", struct{}{}, &versions); err != nil {
		s.agentFailed(w, r, "/vhosts", err)
		return VhostPageData{}, false
	}
	data := VhostPageData{Vhost: d, PHPVersions: versions, SSHHost: s.cfg.Hostname, DBSocket: mariadb.Socket}
	if d.Access != nil {
		if err := s.agentCall(r, "host.ssh.keys", struct{}{}, &data.HostKeys); err != nil {
			s.log.Warn("reading SSH host keys failed", "err", err)
		}
	}
	if err := s.agentCall(r, "db.server.version", struct{}{}, &data.DBServer); err != nil {
		s.log.Warn("reading the MariaDB version failed", "err", err)
	}
	return data, true
}

func (s *Server) vhostPage(w http.ResponseWriter, r *http.Request) {
	data, ok := s.vhostPageData(w, r)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "vhost.html", Page{Title: data.Vhost.Primary, Data: data, Error: r.URL.Query().Get("error")})
}

// VhostPageData is what the vhost page shows; Secret carries a password shown once.
type VhostPageData struct {
	Vhost       ops.VhostDetail
	PHPVersions []string
	Secret      *ops.DBCredentials
	// SSHHost is where SFTP clients connect: the panel's hostname, which names this server.
	SSHHost  string
	HostKeys []ops.HostKeyView
	DBSocket string
	// DBServer is empty when the agent could not read it.
	DBServer ops.DBServerView
}

func vhostPath(r *http.Request) string { return "/vhosts/" + url.PathEscape(r.PathValue("id")) }

func (s *Server) updateAliases(w http.ResponseWriter, r *http.Request) {
	args := ops.VhostUpdateArgs{VhostID: r.PathValue("id"), Aliases: domainList(r.PostFormValue("aliases"))}
	s.startJob(w, r, "vhost.update", args, vhostPath(r), vhostPath(r))
}

func (s *Server) switchPHP(w http.ResponseWriter, r *http.Request) {
	args := ops.VhostPHPSwitchArgs{VhostID: r.PathValue("id"), Version: r.PostFormValue("php")}
	s.startJob(w, r, "vhost.php.switch", args, vhostPath(r), vhostPath(r))
}

func (s *Server) deleteVhost(w http.ResponseWriter, r *http.Request) {
	args := ops.VhostDeleteArgs{VhostID: r.PathValue("id"), Confirm: strings.TrimSpace(r.PostFormValue("confirm"))}
	s.startJob(w, r, "vhost.delete", args, vhostPath(r), "/vhosts")
}

// simpleAction runs a quick agent operation and returns to the vhost page with a message.
func (s *Server) simpleAction(w http.ResponseWriter, r *http.Request, op string, args any, flash string) {
	if err := s.agentCall(r, op, args, nil); err != nil {
		s.agentFailed(w, r, vhostPath(r), err)
		return
	}
	redirectFlash(w, r, vhostPath(r), flash)
}

func (s *Server) createDatabase(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, "db.create", ops.DBArgs{VhostID: r.PathValue("id"), Suffix: r.PostFormValue("suffix")}, "Database created.")
}

func (s *Server) deleteDatabase(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, "db.delete", ops.DBArgs{VhostID: r.PathValue("id"), Suffix: r.PathValue("suffix")}, "Database deleted.")
}

func (s *Server) deleteDBUser(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, "dbuser.delete", ops.DBArgs{VhostID: r.PathValue("id"), Suffix: r.PathValue("suffix")}, "DB user deleted.")
}

// showSecret renders the vhost page with a password the user sees only once.
func (s *Server) showSecret(w http.ResponseWriter, r *http.Request, creds ops.DBCredentials, flash string) {
	data, ok := s.vhostPageData(w, r)
	if !ok {
		return
	}
	data.Secret = &creds
	s.render(w, r, http.StatusOK, "vhost.html", Page{Title: data.Vhost.Primary, Flash: flash, Data: data})
}

func (s *Server) createDBUser(w http.ResponseWriter, r *http.Request) {
	args := ops.DBUserCreateArgs{VhostID: r.PathValue("id"), Suffix: r.PostFormValue("suffix"), Grants: mariadb.Privileges(r.PostFormValue("grants"))}
	var creds ops.DBCredentials
	if err := s.agentCall(r, "dbuser.create", args, &creds); err != nil {
		s.agentFailed(w, r, vhostPath(r), err)
		return
	}
	s.showSecret(w, r, creds, "DB user created. Copy the password now; it is shown only once.")
}

func (s *Server) resetDBPassword(w http.ResponseWriter, r *http.Request) {
	var creds ops.DBCredentials
	if err := s.agentCall(r, "dbuser.password.reset", ops.DBArgs{VhostID: r.PathValue("id"), Suffix: r.PathValue("suffix")}, &creds); err != nil {
		s.agentFailed(w, r, vhostPath(r), err)
		return
	}
	s.showSecret(w, r, creds, "New password set. Copy it now; it is shown only once.")
}

func (s *Server) createAccess(w http.ResponseWriter, r *http.Request) {
	args := ops.AccessCreateArgs{VhostID: r.PathValue("id"), Password: r.PostFormValue("password")}
	if k := strings.TrimSpace(r.PostFormValue("key")); k != "" {
		args.Keys = []string{k}
	}
	s.startJob(w, r, "access.create", args, vhostPath(r), vhostPath(r))
}

func (s *Server) deleteAccess(w http.ResponseWriter, r *http.Request) {
	s.startJob(w, r, "access.delete", ops.VhostIDArgs{VhostID: r.PathValue("id")}, vhostPath(r), vhostPath(r))
}

func (s *Server) addKey(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, "access.key.add", ops.AccessKeyArgs{Account: r.PathValue("id"), PublicKey: strings.TrimSpace(r.PostFormValue("key"))}, "Key added.")
}

func (s *Server) removeKey(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, "access.key.remove", ops.AccessKeyArgs{Account: r.PathValue("id"), PublicKey: r.PostFormValue("key")}, "Key removed.")
}

func (s *Server) uploadCert(w http.ResponseWriter, r *http.Request) {
	args := ops.CertUploadArgs{VhostID: r.PathValue("id"), ChainPEM: r.PostFormValue("chain"), KeyPEM: r.PostFormValue("key")}
	s.simpleAction(w, r, "cert.upload", args, "Certificate installed.")
}

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request, d DashboardData) {
	if err := s.agentCall(r, "vhost.list", ops.VhostListArgs{}, &d.Vhosts); err != nil {
		s.agentFailed(w, r, "/security", err)
		return
	}
	ov := &AdminOverview{OwnerNames: map[int64]string{}}
	for _, v := range d.Vhosts {
		switch v.Status {
		case "active":
			ov.Active++
		case "suspended":
			ov.Suspended++
		default:
			ov.Other++
		}
	}
	var owners []ops.OwnerView
	err := s.adminCall(r, "owner.list", struct{}{}, &owners)
	if e := api.AsError(err); e != nil && (e.Code == api.CodeTOTPRequired || e.Code == api.CodeTOTPInvalid) {
		ov.Locked = true
	} else if err != nil {
		s.agentFailed(w, r, "/security", err)
		return
	} else {
		for _, o := range owners {
			ov.OwnerNames[o.ID] = o.Name
		}
		if err := s.adminCall(r, "php.version.list", struct{}{}, &ov.PHPVersions); err != nil {
			s.agentFailed(w, r, "/security", err)
			return
		}
	}
	d.Admin = ov
	s.render(w, r, http.StatusOK, "dashboard.html", Page{Title: "Dashboard", Data: d})
}
