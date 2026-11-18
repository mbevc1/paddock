package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mbevc1/paddock/internal/acme"
	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/validate"
	"github.com/mbevc1/paddock/internal/web"
	"github.com/mbevc1/paddock/internal/web/store"
)

const (
	defaultWebDir  = "/var/lib/paddock/web"
	defaultACMESck = "/run/paddock/acme.sock"
	eventsInterval = 5 * time.Second
)

func runWeb(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := flag.NewFlagSet("web", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hostname := fs.String("hostname", "", "panel hostname (required)")
	dir := fs.String("dir", defaultWebDir, "directory holding web.db, the panel key, and the ACME cache")
	socket := fs.String("socket", agent.SocketPath, "agent socket path")
	listen := fs.String("listen", ":8443", "HTTPS listen address")
	redirect := fs.String("redirect", ":8080", "plain HTTP redirect listen address")
	acmeSocket := fs.String("acme-socket", defaultACMESck, "socket answering ACME HTTP-01 challenges")
	acmeEmail := fs.String("acme-email", "", "contact address for Let's Encrypt")
	acmeDirectory := fs.String("acme-directory", "", "ACME directory URL (default Let's Encrypt production)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %q", fs.Args())
	}
	host, err := validate.Domain(*hostname)
	if err != nil {
		return fmt.Errorf("-hostname: %w", err)
	}
	if os.Geteuid() == 0 {
		return errors.New("the web process must not run as root; run it as user paddock")
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))

	st, err := store.Open(ctx, filepath.Join(*dir, "web.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	self, err := loadOrCreateSelfSigned(*dir, host, log)
	if err != nil {
		return err
	}
	certs := acme.New(acme.Config{Hostname: host, CacheDir: filepath.Join(*dir, "acme"), Email: *acmeEmail,
		DirectoryURL: *acmeDirectory, SelfSigned: self, Log: log})

	web.Version = version
	srv, err := web.New(web.Config{Hostname: host, TLSAddr: *listen, RedirectAddr: *redirect},
		web.Deps{Agent: web.DialAgent{Socket: *socket}, Store: st, Certs: certs, Log: log})
	if err != nil {
		return err
	}
	go func() {
		if err := certs.ServeChallenges(ctx, *acmeSocket); err != nil {
			log.Error("ACME challenge socket failed", "err", err)
		}
	}()
	certs.Prefetch()
	go srv.PollEvents(ctx, eventsInterval)
	log.Info("panel listening", "hostname", host, "https", *listen, "redirect", *redirect, "version", version)
	return srv.Run(ctx)
}

// loadOrCreateSelfSigned reads the panel's self-signed certificate, making one if paddock
// setup has not.
func loadOrCreateSelfSigned(dir, host string, log *slog.Logger) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "panel.crt"), filepath.Join(dir, "panel.key")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return pair, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return tls.Certificate{}, err
	}
	certPEM, keyPEM, fp, err := acme.SelfSigned(host, localIPs(), time.Now())
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil { // #nosec G306 -- a public certificate.
		return tls.Certificate{}, err
	}
	log.Info("created a self-signed panel certificate", "sha256", fp)
	return tls.X509KeyPair(certPEM, keyPEM)
}

func localIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.IsGlobalUnicast() {
			ips = append(ips, n.IP)
		}
	}
	return ips
}
