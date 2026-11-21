package ops

import (
	"context"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/state"
)

// UnitState is a systemd unit's state on the status page.
type UnitState string

// Unit states reported by server.health.
const (
	UnitActive   UnitState = "active"
	UnitInactive UnitState = "inactive"
	UnitUnknown  UnitState = "unknown"
)

// VhostHealth is one vhost's certificate and service state. Backend and FPM are empty for a
// vhost that is not active, whose units are expected to be stopped.
type VhostHealth struct {
	ID         string            `json:"id"`
	OwnerID    int64             `json:"owner_id"`
	Primary    string            `json:"primary"`
	PHPVersion string            `json:"php_version"`
	Status     state.VhostStatus `json:"status"`
	Cert       CertStatus        `json:"cert"`
	Backend    UnitState         `json:"backend,omitempty"`
	FPM        UnitState         `json:"fpm,omitempty"`
}

func registerHealth(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "server.health", Class: agent.ClassAdmin, Handler: func(ctx context.Context, _ *agent.Call) (any, error) {
		return serverHealth(ctx, store, h)
	}})
}

func serverHealth(ctx context.Context, store *state.Store, h *Host) ([]VhostHealth, error) {
	vhosts, err := store.ListVhosts(ctx, 0)
	if err != nil {
		return nil, err
	}
	md, mdErr := h.mdStatus(ctx)
	if mdErr != nil {
		h.logger().Warn("reading md-status failed", "err", mdErr)
	}
	byName := make(map[string]MDDomain, len(md))
	for _, d := range md {
		byName[d.Name] = d
	}
	out := make([]VhostHealth, 0, len(vhosts))
	for _, sv := range vhosts {
		view, err := vhostView(ctx, store, sv)
		if err != nil {
			return nil, err
		}
		vh := VhostHealth{ID: sv.ID, OwnerID: sv.OwnerID, Primary: view.Primary, PHPVersion: sv.PHPVersion, Status: sv.Status}
		c, err := store.GetCert(ctx, sv.N)
		if err != nil {
			return nil, err
		}
		vh.Cert.Source = c.Source
		if !c.NotAfter.IsZero() {
			vh.Cert.NotAfter = &c.NotAfter
		}
		if c.Source == state.CertACME {
			if mdErr != nil {
				vh.Cert.Error = "certificate status unavailable"
			} else if d, ok := byName[view.Primary]; ok {
				vh.Cert.State, vh.Cert.Error = d.State, d.Error
				if !d.NotAfter.IsZero() {
					vh.Cert.NotAfter = &d.NotAfter
				}
			}
		}
		if sv.Status == state.VhostActive {
			v, err := renderedVhost(ctx, store, sv)
			if err != nil {
				return nil, err
			}
			vh.Backend = h.unitState(ctx, v.HTTPDUnit())
			vh.FPM = h.unitState(ctx, v.FPMUnit())
		}
		out = append(out, vh)
	}
	return out, nil
}

func (h *Host) unitState(ctx context.Context, unit string) UnitState {
	err := h.run(ctx, systemctl, "is-active", "--quiet", unit)
	switch {
	case err == nil:
		return UnitActive
	case exitCode(err) == systemctlNotActive:
		return UnitInactive
	default:
		h.logger().Warn("checking a unit failed", "unit", unit, "err", err)
		return UnitUnknown
	}
}
