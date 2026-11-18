package web

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/web/store"
)

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static
var staticFiles embed.FS

// Config holds the panel's network settings.
type Config struct {
	// Hostname is the panel's DNS name; it fixes the origin used for CSRF checks and redirects.
	Hostname     string
	TLSAddr      string
	RedirectAddr string
}

// CertSource provides the panel's TLS certificate and says when it is publicly trusted.
type CertSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Trusted() bool
}

// Server is the panel.
type Server struct {
	cfg     Config
	origin  string
	agent   Agent
	store   *store.Store
	certs   CertSource
	log     *slog.Logger
	now     func() time.Time
	pages   map[string]*template.Template
	limiter *limiter
	enroll  *pendingSecrets
	hub     *hub
	handler http.Handler
}

// Deps are the server's collaborators.
type Deps struct {
	Agent Agent
	Store *store.Store
	Certs CertSource
	Log   *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// New builds the server and its routes. It fails if any route lacks a permission.
func New(cfg Config, d Deps) (*Server, error) {
	if cfg.Hostname == "" {
		return nil, errors.New("panel hostname is required")
	}
	port := "8443"
	if _, p, err := net.SplitHostPort(cfg.TLSAddr); err == nil && p != "" {
		port = p
	}
	s := &Server{cfg: cfg, agent: d.Agent, store: d.Store, certs: d.Certs, log: d.Log, now: d.Now}
	s.origin = "https://" + cfg.Hostname
	if port != "443" {
		s.origin += ":" + port
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.limiter = newLimiter(s.now)
	s.enroll = newPendingSecrets(s.now)
	s.hub = newHub()
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	s.pages = pages

	rt := &Router{guard: s.guard}
	s.routes(rt)
	h, err := rt.Build()
	if err != nil {
		return nil, err
	}
	trusted := func() bool { return s.certs != nil && s.certs.Trusted() }
	s.handler = securityHeaders(h, trusted)
	return s, nil
}

// Handler returns the panel's HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes(rt *Router) {
	static, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.StripPrefix("/static/", http.FileServerFS(static))
	rt.Handle(Route{Method: "GET", Pattern: "/static/", Perm: PermPublic, Handler: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fileServer.ServeHTTP(w, r)
	}})
	s.authRoutes(rt)
	s.ownerRoutes(rt)
	s.adminRoutes(rt)
	s.notificationRoutes(rt)
}

// Run serves HTTPS on TLSAddr and the redirect on RedirectAddr until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	if s.certs == nil {
		return errors.New("no certificate source")
	}
	tlsSrv := &http.Server{
		Addr:              s.cfg.TLSAddr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.certs.GetCertificate},
	}
	redirect := &http.Server{
		Addr:              s.cfg.RedirectAddr,
		Handler:           securityHeaders(redirectHandler(s.origin), nil),
		ReadHeaderTimeout: 10 * time.Second,
	}
	var lc net.ListenConfig
	tlsLn, err := lc.Listen(ctx, "tcp", s.cfg.TLSAddr)
	if err != nil {
		return fmt.Errorf("panel HTTPS address %s: %w", s.cfg.TLSAddr, err)
	}
	redirectLn, err := lc.Listen(ctx, "tcp", s.cfg.RedirectAddr)
	if err != nil {
		_ = tlsLn.Close()
		return fmt.Errorf("panel redirect address %s: %w", s.cfg.RedirectAddr, err)
	}
	s.log.Info("panel listening", "hostname", s.cfg.Hostname, "https", tlsLn.Addr().String(),
		"redirect", redirectLn.Addr().String(), "version", Version)
	errs := make(chan error, 2)
	go func() { errs <- tlsSrv.ServeTLS(tlsLn, "", "") }()
	go func() { errs <- redirect.Serve(redirectLn) }()
	go s.cleanupLoop(ctx)
	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			_ = tlsSrv.Close()
			_ = redirect.Close()
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	s.hub.closeAll()
	return errors.Join(tlsSrv.Shutdown(shutdown), redirect.Shutdown(shutdown))
}

func (s *Server) cleanupLoop(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if _, err := s.store.DeleteSessionsBefore(ctx, s.now().Add(-absoluteLife)); err != nil {
				s.log.Error("session cleanup failed", "err", err)
			}
		}
	}
}

// agentCall runs an agent operation for the request's user.
func (s *Server) agentCall(r *http.Request, op string, args, result any) error {
	return s.agent.Call(r.Context(), op, identityFrom(r).Actor(), "", args, result)
}

// agentMessage turns an agent error into text for the page. Internal errors stay generic.
func agentMessage(err error) string {
	if e := api.AsError(err); e != nil && e.Code != api.CodeInternal {
		return e.Message
	}
	return "The request failed. Try again, or ask an admin to check the agent log."
}

// pathID reads the route's numeric {id}.
func pathID(r *http.Request) (int64, bool) {
	v, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return v, err == nil && v > 0
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

var _ = fmt.Sprintf
