package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/validate"
)

const (
	certFileMode = 0o644
	keyFileMode  = 0o600
	// mdStatusURL is the front Apache's status listener, which the loopback rule keeps to root.
	mdStatusURL      = "http://127.0.0.1:81/md-status"
	maxMDStatusBytes = 4 << 20
)

// CertUploadArgs are the arguments of cert.upload.
type CertUploadArgs struct {
	VhostID  string `json:"vhost_id"`
	ChainPEM string `json:"chain_pem"`
	KeyPEM   string `json:"key_pem"`
}

// CertStatus is cert.status's result.
type CertStatus struct {
	Source   state.CertSource `json:"source"`
	NotAfter *time.Time       `json:"not_after,omitempty"`
	// State and Error come from mod_md for ACME certificates.
	State string `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
}

// MDRenewedArgs are the arguments of front.md-renewed.
type MDRenewedArgs struct {
	Domains []string `json:"domains"`
}

// MDDomain is one managed domain as mod_md's md-status reports it.
type MDDomain struct {
	Name     string
	State    string
	NotAfter time.Time
	Error    string
	// Staged is a finished renewal whose certificate waits for the front Apache to reload.
	Staged bool
	// RenewalRun identifies the renewal, so each one is activated once.
	RenewalRun string
}

// registerCerts adds cert.upload and cert.status (owner) and front.md-renewed (root, for
// paddock agent-notify run by hand; the usage scan activates renewals on its own).
func registerCerts(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "cert.upload", Class: agent.ClassOwner, Secrets: []string{"key_pem"},
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[CertUploadArgs](c)
			if err != nil {
				return nil, err
			}
			return uploadCert(ctx, store, h, c.Actor, args)
		}})

	r.Register(agent.Op{Name: "cert.status", Class: agent.ClassOwner,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[VhostIDArgs](c)
			if err != nil {
				return nil, err
			}
			return certStatus(ctx, store, h, c.Actor, args.VhostID)
		}})

	r.Register(agent.Op{Name: "front.md-renewed", Class: agent.ClassRoot,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[MDRenewedArgs](c)
			if err != nil {
				return nil, err
			}
			for _, d := range args.Domains {
				if _, err := validate.Domain(d); err != nil {
					return nil, api.Errorf(api.CodeInvalidArgument, "%v", err)
				}
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			return nil, activateRenewed(ctx, store, h, args.Domains)
		}})
}

// activateRenewed reloads the front Apache, which puts mod_md's staged certificates in use,
// and tells each domain's owner. The caller holds h.mu.
func activateRenewed(ctx context.Context, store *state.Store, h *Host, domains []string) error {
	if err := h.run(ctx, apachectl, "configtest"); err != nil {
		return h.applyFailed("checking the front config", err)
	}
	if err := h.run(ctx, systemctl, "reload", "httpd.service"); err != nil {
		return h.applyFailed("reloading the front Apache", err)
	}
	for _, d := range domains {
		sv, err := store.VhostByDomain(ctx, d)
		if err != nil {
			continue
		}
		if _, err := store.AppendEvent(ctx, state.Event{Kind: state.EventCertRenewed, OwnerID: sv.OwnerID,
			VhostN: sv.N, Message: "certificate renewed for " + d}); err != nil {
			return err
		}
	}
	return nil
}

// activateStaged activates mod_md's finished renewals. mod_md's notify command runs as the
// apache user, which the agent does not accept, so the usage scan watches md-status instead.
// The caller holds h.mu.
func activateStaged(ctx context.Context, store *state.Store, h *Host) error {
	domains, err := h.mdStatus(ctx)
	if err != nil {
		// A front Apache that is down must not stop the rest of the scan; the next one retries.
		h.logger().Warn("reading md-status failed", "err", err)
		return nil
	}
	var due []string
	for _, d := range domains {
		if d.Staged && h.activated[d.Name] != d.RenewalRun {
			due = append(due, d.Name)
		}
	}
	if len(due) == 0 {
		return nil
	}
	if err := activateRenewed(ctx, store, h, due); err != nil {
		return err
	}
	if h.activated == nil {
		h.activated = map[string]string{}
	}
	for _, d := range domains {
		if d.Staged {
			h.activated[d.Name] = d.RenewalRun
		}
	}
	return nil
}

// frontOptions returns the front variant for a vhost: its certificate source and whether it
// answers 503.
func frontOptions(ctx context.Context, store *state.Store, n int, suspended bool) (render.FrontOptions, error) {
	c, err := store.GetCert(ctx, n)
	if err != nil {
		return render.FrontOptions{}, err
	}
	tls := render.TLSACME
	if c.Source == state.CertUpload {
		tls = render.TLSUpload
	}
	return render.FrontOptions{TLS: tls, Suspended: suspended}, nil
}

func uploadCert(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args CertUploadArgs) (any, error) {
	sv, err := loadVhost(ctx, store, actor, args.VhostID)
	if err != nil {
		return nil, err
	}
	v, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return nil, err
	}
	bundle, err := validate.CertificateBundle(args.ChainPEM, args.KeyPEM, append([]string{v.Primary()}, v.Aliases()...), h.now())
	if err != nil {
		return nil, api.Errorf(api.CodeInvalidArgument, "%v", err)
	}

	sv, err = lockedVhost(ctx, store, h, sv.N)
	if err != nil {
		return nil, err
	}
	defer h.mu.Unlock()
	if sv.Status != state.VhostActive && sv.Status != state.VhostSuspended {
		return nil, api.Errorf(api.CodeConflict, "vhost %s is %s", sv.ID, sv.Status)
	}
	undo := &rollback{h: h}
	chainPath, keyPath := render.CertPaths(v)
	for _, f := range []render.File{
		{Path: chainPath, Data: bundle.ChainPEM, Mode: certFileMode},
		{Path: keyPath, Data: bundle.KeyPEM, Mode: keyFileMode},
	} {
		change, err := h.Files.Write(f)
		if err != nil {
			undo.run(ctx)
			return nil, h.applyFailed("writing "+f.Path, err)
		}
		undo.add(func(context.Context) error { return change.Restore() })
	}
	opts := render.FrontOptions{TLS: render.TLSUpload, Suspended: sv.Status == state.VhostSuspended}
	if err := applyFront(ctx, h, undo, v, opts); err != nil {
		undo.run(ctx)
		return nil, err
	}
	if err := store.SetCert(ctx, sv.N, state.Cert{Source: state.CertUpload, NotAfter: bundle.NotAfter, Fingerprint: bundle.Fingerprint}); err != nil {
		undo.run(ctx)
		return nil, err
	}
	notAfter := bundle.NotAfter
	return CertStatus{Source: state.CertUpload, NotAfter: &notAfter}, nil
}

func certStatus(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, vhostID string) (any, error) {
	sv, err := loadVhost(ctx, store, actor, vhostID)
	if err != nil {
		return nil, err
	}
	c, err := store.GetCert(ctx, sv.N)
	if err != nil {
		return nil, err
	}
	out := CertStatus{Source: c.Source}
	if !c.NotAfter.IsZero() {
		out.NotAfter = &c.NotAfter
	}
	if c.Source != state.CertACME {
		return out, nil
	}
	v, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return nil, err
	}
	domains, err := h.mdStatus(ctx)
	if err != nil {
		h.logger().Warn("reading md-status failed", "err", err)
		out.Error = "certificate status unavailable"
		return out, nil
	}
	for _, d := range domains {
		if d.Name != v.Primary() {
			continue
		}
		out.State, out.Error = d.State, d.Error
		if !d.NotAfter.IsZero() {
			out.NotAfter = &d.NotAfter
		}
	}
	return out, nil
}

func (h *Host) mdStatus(ctx context.Context) ([]MDDomain, error) {
	if h.MDStatus != nil {
		return h.MDStatus(ctx)
	}
	return fetchMDStatus(ctx, localClient, mdStatusURL)
}

// localClient talks to the front Apache on loopback and ignores proxy settings.
var localClient = &http.Client{Transport: &http.Transport{Proxy: nil}}

// fetchMDStatus reads mod_md's JSON status. Its layout differs between mod_md releases, so
// fields are looked up leniently and missing ones stay empty.
func fetchMDStatus(ctx context.Context, client *http.Client, url string) ([]MDDomain, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("md-status answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMDStatusBytes))
	if err != nil {
		return nil, err
	}
	return parseMDStatus(body)
}

func parseMDStatus(body []byte) ([]MDDomain, error) {
	var doc struct {
		Domains []map[string]any `json:"managed-domains"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("md-status is not JSON: %w", err)
	}
	out := make([]MDDomain, 0, len(doc.Domains))
	for _, m := range doc.Domains {
		d := MDDomain{Name: str(m["name"])}
		if s, ok := m["state-descr"]; ok {
			d.State = str(s)
		} else if s, ok := m["state"]; ok {
			d.State = fmt.Sprint(s)
		}
		d.NotAfter = certUntil(m["cert"])
		if renewal, ok := m["renewal"].(map[string]any); ok {
			d.Staged = renewal["finished"] == true
			d.RenewalRun = str(renewal["last-run"])
			if last, ok := renewal["last"].(map[string]any); ok {
				d.Error = str(last["problem"])
				if d.Error == "" {
					d.Error = str(last["detail"])
				}
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// certUntil finds the earliest valid.until below a cert object, which mod_md nests either
// directly or per key type ("rsa", "secp256r1").
func certUntil(v any) time.Time {
	cert, ok := v.(map[string]any)
	if !ok {
		return time.Time{}
	}
	candidates := []any{cert}
	for _, sub := range cert {
		candidates = append(candidates, sub)
	}
	var earliest time.Time
	for _, c := range candidates {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		valid, ok := m["valid"].(map[string]any)
		if !ok {
			continue
		}
		t, err := http.ParseTime(str(valid["until"]))
		if err != nil {
			t, err = time.Parse(time.RFC3339, str(valid["until"]))
		}
		if err == nil && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t.UTC()
		}
	}
	return earliest
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
