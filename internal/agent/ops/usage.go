package ops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/mariadb"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
	"github.com/mbevc1/paddock/internal/validate"
)

// CertWarnWindow is how long before expiry a certificate counts as expiring.
const CertWarnWindow = 14 * 24 * time.Hour

const (
	quotaWarnPercent    = 90
	quotaEnforcePercent = 100
	// eventRepeat keeps a recurring condition, such as an expiring certificate, to one event
	// a day.
	eventRepeat     = 24 * time.Hour
	maxEventsPage   = 500
	defaultEventsPg = 100
)

// UsageArgs select whose usage usage.get reports: one vhost's owner or an owner.
type UsageArgs struct {
	VhostID string `json:"vhost_id,omitempty"`
	OwnerID int64  `json:"owner_id,omitempty"`
}

// VhostUsage is one vhost's disk and database use in bytes.
type VhostUsage struct {
	VhostID   string `json:"vhost_id"`
	DiskBytes int64  `json:"disk_bytes"`
	DBBytes   int64  `json:"db_bytes"`
}

// OwnerUsage is an owner's use against their disk limit (§5: files of all vhosts plus
// database sizes).
type OwnerUsage struct {
	OwnerID    int64        `json:"owner_id"`
	Vhosts     []VhostUsage `json:"vhosts"`
	TotalBytes int64        `json:"total_bytes"`
	LimitBytes int64        `json:"limit_bytes"`
}

// Percent returns the share of the limit in use, rounded down.
func (u OwnerUsage) Percent() int64 {
	if u.LimitBytes <= 0 {
		return 0
	}
	return u.TotalBytes * 100 / u.LimitBytes
}

// EventsListArgs are the arguments of events.list.
type EventsListArgs struct {
	Since int64 `json:"since"`
	Limit int   `json:"limit,omitempty"`
}

// EventsPage is events.list's result; Next is the cursor for the following call.
type EventsPage struct {
	Events []state.Event `json:"events"`
	Next   int64         `json:"next"`
}

func registerUsage(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "usage.get", Class: agent.ClassOwner, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[UsageArgs](c)
		if err != nil {
			return nil, err
		}
		ownerID := args.OwnerID
		if args.VhostID != "" {
			sv, err := loadVhost(ctx, store, c.Actor, args.VhostID)
			if err != nil {
				return nil, err
			}
			ownerID = sv.OwnerID
		}
		if err := checkOwnerID(ownerID); err != nil {
			return nil, err
		}
		if err := scopeOwner(c.Actor, ownerID); err != nil {
			return nil, err
		}
		m, err := measure(ctx, h)
		if err != nil {
			return nil, h.applyFailed("measuring usage", err)
		}
		return ownerUsage(ctx, store, ownerID, m)
	}})

	r.Register(agent.Op{Name: "events.list", Class: agent.ClassSystem, Handler: func(ctx context.Context, c *agent.Call) (any, error) {
		args, err := agent.DecodeArgs[EventsListArgs](c)
		if err != nil {
			return nil, err
		}
		limit := args.Limit
		if limit <= 0 {
			limit = defaultEventsPg
		}
		limit = min(limit, maxEventsPage)
		events, err := store.ListEvents(ctx, args.Since, limit)
		if err != nil {
			return nil, err
		}
		page := EventsPage{Events: events, Next: args.Since}
		if len(events) > 0 {
			page.Next = events[len(events)-1].ID
		}
		if page.Events == nil {
			page.Events = []state.Event{}
		}
		return page, nil
	}})
}

// measurement is one reading of disk use per XFS project and database size per vhost ID.
type measurement struct {
	disk map[int]int64
	db   map[string]int64
}

func measure(ctx context.Context, h *Host) (measurement, error) {
	res, err := h.Run.Run(ctx, []string{xfsQuota, "-x", "-c", "report -p -N -n -b", BaseWWW}, system.Opts{})
	if err != nil {
		return measurement{}, err
	}
	disk, err := parseProjectReport(res.Stdout)
	if err != nil {
		return measurement{}, err
	}
	rows, err := h.db().Query(ctx, mariadb.AllDatabaseSizes())
	if err != nil {
		return measurement{}, err
	}
	db := map[string]int64{}
	for _, row := range rows {
		if len(row) != 2 {
			return measurement{}, fmt.Errorf("unexpected database size row %q", row)
		}
		size, err := strconv.ParseInt(row[1], 10, 64)
		if err != nil {
			return measurement{}, fmt.Errorf("database size %q: %w", row[1], err)
		}
		vhostID, _, _ := strings.Cut(row[0], "_")
		db[vhostID] += size
	}
	return measurement{disk: disk, db: db}, nil
}

// parseProjectReport reads "xfs_quota report -p -N -n -b" lines such as
// "#12  2048  0  1048576  00 [--------]", where blocks are KiB.
func parseProjectReport(out []byte) (map[int]int64, error) {
	usage := map[int]int64{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "#") {
			continue
		}
		project, err := strconv.Atoi(strings.TrimPrefix(fields[0], "#"))
		if err != nil {
			return nil, fmt.Errorf("project %q: %w", fields[0], err)
		}
		kib, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("blocks %q: %w", fields[1], err)
		}
		usage[project] = kib * 1024
	}
	return usage, sc.Err()
}

func ownerUsage(ctx context.Context, store *state.Store, ownerID int64, m measurement) (OwnerUsage, error) {
	limits, err := store.GetLimits(ctx, ownerID)
	if err != nil {
		return OwnerUsage{}, err
	}
	vhosts, err := store.ListVhosts(ctx, ownerID)
	if err != nil {
		return OwnerUsage{}, err
	}
	u := OwnerUsage{OwnerID: ownerID, LimitBytes: int64(limits.DiskMB) << 20, Vhosts: []VhostUsage{}}
	for _, v := range vhosts {
		vu := VhostUsage{VhostID: v.ID, DiskBytes: m.disk[v.N], DBBytes: m.db[v.ID]}
		u.Vhosts = append(u.Vhosts, vu)
		u.TotalBytes += vu.DiskBytes + vu.DBBytes
	}
	return u, nil
}

// ScanUsage measures every owner once: it warns at 90 % of the disk limit and, at 100 %,
// freezes each vhost's files at their current size and revokes database writes (§9), undoing
// both once the owner is back under the limit. It also warns about certificates expiring
// within 14 days.
func ScanUsage(ctx context.Context, store *state.Store, h *Host) error {
	m, err := measure(ctx, h)
	if err != nil {
		return err
	}
	owners, err := store.ListOwners(ctx)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var errs []error
	for _, o := range owners {
		if err := enforceOwner(ctx, store, h, o.ID, m); err != nil {
			errs = append(errs, fmt.Errorf("owner %d: %w", o.ID, err))
		}
	}
	if err := checkCertExpiry(ctx, store, h); err != nil {
		errs = append(errs, err)
	}
	if err := activateStaged(ctx, store, h); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func enforceOwner(ctx context.Context, store *state.Store, h *Host, ownerID int64, m measurement) error {
	u, err := ownerUsage(ctx, store, ownerID, m)
	if err != nil {
		return err
	}
	q, err := store.GetQuotaState(ctx, ownerID)
	if err != nil {
		return err
	}
	pct := u.Percent()
	next := q
	event := func(kind state.EventKind, msg string) error {
		_, err := store.AppendEvent(ctx, state.Event{Kind: kind, OwnerID: ownerID, Message: msg})
		return err
	}
	switch {
	case pct >= quotaWarnPercent && !q.Warned:
		next.Warned = true
		if err := event(state.EventQuotaWarning, fmt.Sprintf("disk use at %d%% of %d MB", pct, u.LimitBytes>>20)); err != nil {
			return err
		}
	case pct < quotaWarnPercent && q.Warned:
		next.Warned = false
	}
	switch {
	case pct >= quotaEnforcePercent && !q.Enforced:
		if err := setWriteLimits(ctx, store, h, u, true); err != nil {
			return err
		}
		next.Enforced = true
		if err := event(state.EventQuotaExceeded, "disk limit reached: database writes revoked and files frozen"); err != nil {
			return err
		}
	case pct < quotaEnforcePercent && q.Enforced:
		if err := setWriteLimits(ctx, store, h, u, false); err != nil {
			return err
		}
		next.Enforced = false
		if err := event(state.EventQuotaCleared, "back under the disk limit: writes restored"); err != nil {
			return err
		}
	}
	if next != q {
		return store.SetQuotaState(ctx, ownerID, next)
	}
	return nil
}

// setWriteLimits freezes (enforce) or releases the owner's vhosts: XFS hard limits at the
// current size or back at disk_mb, and database write privileges revoked or restored.
func setWriteLimits(ctx context.Context, store *state.Store, h *Host, u OwnerUsage, enforce bool) error {
	limitMB := u.LimitBytes >> 20
	for _, vu := range u.Vhosts {
		n, err := validate.VhostID(vu.VhostID)
		if err != nil {
			return err
		}
		limit := fmt.Sprintf("limit -p bhard=%dm %d", limitMB, n)
		if enforce {
			limit = fmt.Sprintf("limit -p bhard=%dk %d", max(vu.DiskBytes>>10, 1), n)
		}
		if err := h.run(ctx, xfsQuota, "-x", "-c", limit, BaseWWW); err != nil {
			return h.applyFailed("setting the disk limit of "+vu.VhostID, err)
		}
		dbs, err := store.ListDatabases(ctx, n)
		if err != nil {
			return err
		}
		users, err := store.ListDBUsers(ctx, n)
		if err != nil {
			return err
		}
		var writers []string
		for _, du := range users {
			if du.Grants == string(mariadb.PrivilegesAll) {
				writers = append(writers, du.Name)
			}
		}
		var stmts []string
		if enforce {
			stmts, err = mariadb.RevokeWrites(vu.VhostID, dbs, writers)
		} else {
			stmts, err = mariadb.RestoreWrites(vu.VhostID, dbs, writers)
		}
		if err != nil {
			return err
		}
		if err := h.db().ExecEach(ctx, stmts, mariadb.NoSuchGrant, mariadb.NoSuchTableGrant); err != nil {
			return h.applyFailed("changing database writes of "+vu.VhostID, err)
		}
	}
	return nil
}

// checkCertExpiry records one event a day per vhost whose certificate expires within 14
// days: uploaded certificates from state, ACME ones from md-status, where a near expiry means
// renewal is failing.
func checkCertExpiry(ctx context.Context, store *state.Store, h *Host) error {
	vhosts, err := store.ListVhosts(ctx, 0)
	if err != nil {
		return err
	}
	now := h.now()
	var managed map[string]time.Time
	for _, sv := range vhosts {
		c, err := store.GetCert(ctx, sv.N)
		if err != nil {
			return err
		}
		notAfter := c.NotAfter
		if c.Source == state.CertACME {
			if managed == nil {
				managed = map[string]time.Time{}
				domains, err := h.mdStatus(ctx)
				if err != nil {
					h.logger().Warn("reading md-status failed", "err", err)
				}
				for _, d := range domains {
					managed[d.Name] = d.NotAfter
				}
			}
			v, err := renderedVhost(ctx, store, sv)
			if err != nil {
				return err
			}
			notAfter = managed[v.Primary()]
		}
		if notAfter.IsZero() || notAfter.Sub(now) > CertWarnWindow {
			continue
		}
		recent, err := store.EventSince(ctx, state.EventCertExpiring, sv.N, now.Add(-eventRepeat))
		if err != nil {
			return err
		}
		if recent {
			continue
		}
		msg := fmt.Sprintf("certificate of %s expires %s", sv.ID, notAfter.UTC().Format(time.RFC3339))
		if _, err := store.AppendEvent(ctx, state.Event{Time: now, Kind: state.EventCertExpiring, OwnerID: sv.OwnerID, VhostN: sv.N, Message: msg}); err != nil {
			return err
		}
	}
	return nil
}

// UsageLoop runs ScanUsage every interval until ctx ends, logging failures.
func UsageLoop(ctx context.Context, store *state.Store, h *Host, interval time.Duration, log *slog.Logger) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if err := ScanUsage(ctx, store, h); err != nil && ctx.Err() == nil {
			log.Error("usage scan failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
