package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

// Page is what every template receives.
type Page struct {
	Title    string
	Identity *Identity
	Flash    string
	Error    string
	Unread   int
	Data     any
}

// Can lets templates show only the actions the user may take: {{if .Can "vhost.manage"}}.
func (p Page) Can(perm string) bool { return p.Identity.Can(Permission(perm)) }

// CSRF returns the session's CSRF token for forms.
func (p Page) CSRF() string {
	if p.Identity == nil {
		return ""
	}
	return p.Identity.Session.CSRFToken
}

// HXHeaders is the hx-headers value that sends the CSRF token with every htmx request.
func (p Page) HXHeaders() string { return fmt.Sprintf(`{"%s": "%s"}`, csrfHeader, p.CSRF()) }

var funcs = template.FuncMap{
	"time": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"mb":   func(b int64) string { return fmt.Sprintf("%.1f MB", float64(b)/(1<<20)) },
	"join": strings.Join,
	"has": func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	},
	// suffix returns the part of a database or DB user name after "<vhost id>_".
	"suffix": func(name, vhostID string) string { return strings.TrimPrefix(name, vhostID+"_") },
}

// parsePages builds one template set per page, each with the shared layout.
func parsePages() (map[string]*template.Template, error) {
	entries, err := fs.Glob(templateFiles, "templates/*.html")
	if err != nil {
		return nil, err
	}
	pages := map[string]*template.Template{}
	for _, e := range entries {
		name := strings.TrimPrefix(e, "templates/")
		if name == "layout.html" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(templateFiles, "templates/layout.html", e)
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		pages[name] = t
	}
	return pages, nil
}

// render writes a page with the layout. Templates that define "fragment" can be rendered alone
// for htmx requests.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, p Page) {
	t, ok := s.pages[page]
	if !ok {
		s.serverError(w, r, fmt.Errorf("no template %s", page))
		return
	}
	if p.Identity == nil {
		p.Identity = identityFrom(r)
	}
	if p.Identity != nil && !p.Identity.Pending {
		if n, err := s.store.UnreadCount(r.Context(), p.Identity.User.ID); err == nil {
			p.Unread = n
		}
	}
	if p.Flash == "" {
		p.Flash = r.URL.Query().Get("flash")
	}
	if p.Error == "" {
		p.Error = r.URL.Query().Get("error")
	}
	root := "layout"
	if r.Header.Get("HX-Request") == "true" && t.Lookup("fragment") != nil {
		root = "fragment"
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, root, p); err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// redirectFlash sends the browser to a local path with a message to show.
func redirectFlash(w http.ResponseWriter, r *http.Request, path, flash string) {
	target := safeNext(path)
	if flash != "" {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target += sep + "flash=" + template.URLQueryEscaper(flash)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
