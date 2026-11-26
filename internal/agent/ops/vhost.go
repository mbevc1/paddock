package ops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"time"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/validate"
)

// ArchiveRetention is how long the tree of a deleted vhost is kept.
const ArchiveRetention = 7 * 24 * time.Hour

// Exit codes of shadow-utils that mean the user or group is already gone.
const (
	userdelNoSuchUser  = 6
	groupdelNoSuchGrp  = 6
	systemctlNotActive = 3
)

// VhostCreateArgs are the arguments of vhost.create.
type VhostCreateArgs struct {
	OwnerID       int64    `json:"owner_id"`
	PrimaryDomain string   `json:"primary_domain"`
	Aliases       []string `json:"aliases,omitempty"`
	PHPVersion    string   `json:"php_version"`
	// Database, when set, is the suffix of an empty database created with the vhost.
	Database string `json:"database,omitempty"`
}

// VhostDeleteArgs are the arguments of vhost.delete. Confirm must repeat the vhost's primary
// domain.
type VhostDeleteArgs struct {
	VhostID string `json:"vhost_id"`
	Confirm string `json:"confirm"`
}

// VhostResult names the vhost an operation acted on.
type VhostResult struct {
	VhostID string `json:"vhost_id"`
}

// RegisterVhosts adds the vhost lifecycle operations (create, delete, PHP switch, suspend,
// resume), which run as jobs, and the certificate operations.
func RegisterVhosts(r *agent.Registry, store *state.Store, h *Host) {
	registerVhostState(r, store, h)
	registerCerts(r, store, h)
	registerDatabases(r, store, h)
	registerAccess(r, store, h)
	registerUsage(r, store, h)
	registerReconcile(r, store, h)
	registerReads(r, store, h)
	registerHealth(r, store, h)
	registerLogs(r, store, h)
	r.Register(agent.Op{Name: "vhost.create", Class: agent.ClassOwner, Long: true,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[VhostCreateArgs](c)
			if err != nil {
				return nil, err
			}
			id, err := createVhost(ctx, store, h, c.Actor, args)
			if err != nil {
				return nil, err
			}
			return VhostResult{VhostID: id}, nil
		}})

	r.Register(agent.Op{Name: "vhost.delete", Class: agent.ClassOwner, Long: true,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[VhostDeleteArgs](c)
			if err != nil {
				return nil, err
			}
			if err := deleteVhost(ctx, store, h, c.Actor, args); err != nil {
				return nil, err
			}
			return VhostResult{VhostID: args.VhostID}, nil
		}})
}

// scopeOwner refuses an owner acting for another owner. Admins act for anyone.
func scopeOwner(actor *api.Actor, ownerID int64) error {
	if actor.Role == api.RoleOwner && actor.OwnerID != ownerID {
		return api.Errorf(api.CodeForbidden, "owners act only on their own account")
	}
	return nil
}

// loadVhost returns a vhost the actor may see; others' vhosts look missing.
func loadVhost(ctx context.Context, store *state.Store, actor *api.Actor, vhostID string) (state.Vhost, error) {
	n, err := validate.VhostID(vhostID)
	if err != nil {
		return state.Vhost{}, api.Errorf(api.CodeInvalidArgument, "%v", err)
	}
	v, err := store.GetVhost(ctx, n)
	if errors.Is(err, state.ErrNotFound) || err == nil && actor.Role == api.RoleOwner && v.OwnerID != actor.OwnerID {
		return state.Vhost{}, api.Errorf(api.CodeNotFound, "vhost %s not found", vhostID)
	}
	return v, err
}

func canonicalDomains(primary string, aliases []string) (string, []string, error) {
	p, err := validate.Domain(primary)
	if err != nil {
		return "", nil, api.Errorf(api.CodeInvalidArgument, "%v", err)
	}
	seen := map[string]bool{p: true}
	out := make([]string, 0, len(aliases))
	for _, a := range aliases {
		d, err := validate.Domain(a)
		if err != nil {
			return "", nil, api.Errorf(api.CodeInvalidArgument, "%v", err)
		}
		if seen[d] {
			return "", nil, api.Errorf(api.CodeInvalidArgument, "domain %s listed twice", d)
		}
		seen[d] = true
		out = append(out, d)
	}
	return p, out, nil
}

func checkPHPAllowed(ctx context.Context, store *state.Store, limits state.Limits, version string) error {
	if err := validate.PHPVersion(version); err != nil {
		return api.Errorf(api.CodeInvalidArgument, "%v", err)
	}
	installed, err := store.ListPHPVersions(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(installed, version) {
		return api.Errorf(api.CodeInvalidArgument, "PHP %s is not installed", version)
	}
	if len(limits.PHPVersions) > 0 && !slices.Contains(limits.PHPVersions, version) {
		return api.Errorf(api.CodeForbidden, "PHP %s is not allowed for this owner", version)
	}
	return nil
}

// vhostFiles renders every file of a vhost from §7, front config excluded.
func vhostFiles(v render.Vhost, l render.Limits) ([]render.File, error) {
	var files []render.File
	add := func(f render.File, err error) error {
		if err != nil {
			return err
		}
		files = append(files, f)
		return nil
	}
	if err := add(render.BackendHTTPD(v)); err != nil {
		return nil, err
	}
	if err := add(render.FPM(v)); err != nil {
		return nil, err
	}
	dropIns, err := render.SandboxDropIns(v)
	if err != nil {
		return nil, err
	}
	files = append(files, dropIns...)
	if err := add(render.OwnerSlice(l)); err != nil {
		return nil, err
	}
	if err := add(render.UserSliceDropIn(v, l)); err != nil {
		return nil, err
	}
	if err := add(render.Tmpfiles(v)); err != nil {
		return nil, err
	}
	mount, err := render.JailMount(v)
	if err != nil {
		return nil, err
	}
	return append(files, mount), nil
}

func renderInputs(v state.Vhost, primary string, aliases []string, l state.Limits) (render.Vhost, render.Limits, error) {
	rv, err := render.NewVhost(v.N, v.OwnerID, v.PHPVersion, primary, aliases, l.PMMaxChildren)
	if err != nil {
		return render.Vhost{}, render.Limits{}, err
	}
	rl, err := render.NewLimits(v.OwnerID, l.MemoryMaxMB, l.CPUQuotaPct, l.TasksMax)
	return rv, rl, err
}

// renderedVhost builds the render inputs of a recorded vhost from its domains and its
// owner's current limits.
func renderedVhost(ctx context.Context, store *state.Store, sv state.Vhost) (render.Vhost, error) {
	domains, err := store.Domains(ctx, sv.N)
	if err != nil {
		return render.Vhost{}, err
	}
	var primary string
	var aliases []string
	for _, d := range domains {
		if d.Primary {
			primary = d.Name
		} else {
			aliases = append(aliases, d.Name)
		}
	}
	limits, err := store.GetLimits(ctx, sv.OwnerID)
	if err != nil {
		return render.Vhost{}, err
	}
	v, _, err := renderInputs(sv, primary, aliases, limits)
	return v, err
}

var vhostSubdirs = []struct {
	name string
	mode fs.FileMode
}{{"public", 0o750}, {"private", 0o700}, {"logs", 0o700}, {"tmp", 0o700}, {"sessions", 0o700}}

// createVhost runs the §8 create sequence. Each completed step registers its undo, and a
// failure runs them in reverse, so a failed create leaves nothing behind but a used number.
func createVhost(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args VhostCreateArgs) (string, error) {
	if err := checkOwnerID(args.OwnerID); err != nil {
		return "", err
	}
	if err := scopeOwner(actor, args.OwnerID); err != nil {
		return "", err
	}
	primary, aliases, err := canonicalDomains(args.PrimaryDomain, args.Aliases)
	if err != nil {
		return "", err
	}
	limits, err := store.GetLimits(ctx, args.OwnerID)
	if err != nil {
		return "", err
	}
	if err := checkPHPAllowed(ctx, store, limits, args.PHPVersion); err != nil {
		return "", err
	}
	if args.Database != "" {
		// The vhost ID is not known yet; any valid one checks the suffix.
		if _, err := validate.DatabaseName("v00001", args.Database); err != nil {
			return "", invalidArg(err)
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	sv, err := store.CreateVhost(ctx, args.OwnerID, args.PHPVersion, primary, aliases)
	if errors.Is(err, state.ErrConflict) {
		return "", api.Errorf(api.CodeConflict, "a domain is already in use")
	}
	if err != nil {
		return "", err
	}
	undo := &rollback{h: h}
	undo.add(func(ctx context.Context) error { return store.DeleteVhost(ctx, sv.N) })

	v, l, err := renderInputs(sv, primary, aliases, limits)
	if err != nil {
		undo.run(ctx)
		return "", err
	}
	if err := applyVhost(ctx, h, undo, sv, v, l, limits.DiskMB); err != nil {
		undo.run(ctx)
		return "", err
	}
	if err := createPrimaryDBUser(ctx, h, undo, sv.ID, limits.MaxUserConnections); err != nil {
		undo.run(ctx)
		return "", err
	}
	if args.Database != "" {
		if err := createVhostDatabase(ctx, store, h, undo, sv, args.Database); err != nil {
			undo.run(ctx)
			return "", err
		}
	}
	if err := store.SetVhostStatus(ctx, sv.N, state.VhostActive); err != nil {
		undo.run(ctx)
		return "", err
	}
	return sv.ID, nil
}

func applyVhost(ctx context.Context, h *Host, undo *rollback, sv state.Vhost, v render.Vhost, l render.Limits, diskMB int) error {
	id, uid := sv.ID, strconv.Itoa(sv.UID)
	step := func(what string, argv ...string) error {
		if err := h.run(ctx, argv...); err != nil {
			return h.applyFailed(what, err)
		}
		return nil
	}

	if err := step("creating group "+id, groupadd, "-g", uid, id); err != nil {
		return err
	}
	undo.add(func(ctx context.Context) error {
		// userdel, undone first, already removes the user's private group.
		if err := h.run(ctx, groupdel, id); err != nil && exitCode(err) != groupdelNoSuchGrp {
			return err
		}
		return nil
	})
	// No subordinate ID ranges: they would overlap the UIDs of other vhosts.
	if err := step("creating user "+id, useradd, "-u", uid, "-g", uid, "-M", "-d", BaseWWW+"/"+id,
		"-s", "/sbin/nologin", "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", id); err != nil {
		return err
	}
	undo.add(func(ctx context.Context) error { return h.run(ctx, userdel, id) })

	if err := h.FS.Mkdir(BaseWWW, id, 0o700, sv.UID, sv.UID); err != nil {
		return h.applyFailed("creating "+BaseWWW+"/"+id, err)
	}
	undo.add(func(context.Context) error { return h.FS.RemoveTree(BaseWWW, id) })
	for _, d := range vhostSubdirs {
		if err := h.FS.Mkdir(BaseWWW, id+"/"+d.name, d.mode, sv.UID, sv.UID); err != nil {
			return h.applyFailed("creating "+d.name, err)
		}
	}

	project := strconv.Itoa(sv.N)
	if err := step("assigning XFS project", xfsQuota, "-x", "-c", "project -s -p "+BaseWWW+"/"+id+" "+project, BaseWWW); err != nil {
		return err
	}
	undo.add(func(ctx context.Context) error {
		return h.run(ctx, xfsQuota, "-x", "-c", "project -C -p "+BaseWWW+"/"+id+" "+project, BaseWWW)
	})
	if err := step("setting disk limit", xfsQuota, "-x", "-c", fmt.Sprintf("limit -p bhard=%dm %s", diskMB, project), BaseWWW); err != nil {
		return err
	}
	undo.add(func(ctx context.Context) error {
		return h.run(ctx, xfsQuota, "-x", "-c", "limit -p bhard=0 "+project, BaseWWW)
	})
	if err := step("labeling "+id, restorecon, "-RF", BaseWWW+"/"+id); err != nil {
		return err
	}

	files, err := vhostFiles(v, l)
	if err != nil {
		return err
	}
	for _, f := range files {
		change, err := h.Files.Write(f)
		if err != nil {
			return h.applyFailed("writing "+f.Path, err)
		}
		undo.add(func(context.Context) error { return change.Restore() })
	}
	tmpfiles, err := render.Tmpfiles(v)
	if err != nil {
		return err
	}
	if err := step("creating the FPM socket directory", systemdTmpfiles, "--create", tmpfiles.Path); err != nil {
		return err
	}
	undo.add(func(context.Context) error { return h.FS.RemoveTree(BaseFPMRun, id) })

	fpm, err := h.Platform.PHPFPMBinary(sv.PHPVersion)
	if err != nil {
		return err
	}
	// php-fpm -t refuses to test a pool without a user when run as root.
	if err := step("checking the FPM config", setpriv, "--reuid="+uid, "--regid="+uid, "--clear-groups", "--",
		fpm, "-t", "--fpm-config", "/etc/paddock/fpm/"+id+".conf"); err != nil {
		return err
	}
	if err := step("checking the backend config", httpd, "-t", "-f", "/etc/paddock/httpd/"+id+".conf"); err != nil {
		return err
	}

	if err := h.FS.Mkdir(BaseJail, id, 0o755, 0, 0); err != nil {
		return h.applyFailed("creating the jail", err)
	}
	undo.add(func(context.Context) error { return h.FS.RemoveTree(BaseJail, id) })
	if err := h.FS.Mkdir(BaseJail, id+"/site", 0o755, 0, 0); err != nil {
		return h.applyFailed("creating the jail", err)
	}

	userUnit := "user@" + uid + ".service"
	if err := step("masking "+userUnit, systemctl, "mask", userUnit); err != nil {
		return err
	}
	undo.add(func(ctx context.Context) error { return h.run(ctx, systemctl, "unmask", userUnit) })
	if err := step("reloading systemd", systemctl, "daemon-reload"); err != nil {
		return err
	}
	undo.add(func(ctx context.Context) error { return h.run(ctx, systemctl, "daemon-reload") })

	// A failed enable --now can leave the unit enabled, so its undo is registered first.
	mount := render.MountUnitName(BaseJail + "/" + id + "/site")
	for _, unit := range []string{mount, v.FPMUnit(), v.HTTPDUnit()} {
		undo.add(func(ctx context.Context) error { return h.run(ctx, systemctl, "disable", "--now", unit) })
		if err := step("starting "+unit, systemctl, "enable", "--now", unit); err != nil {
			return err
		}
		if unit == v.FPMUnit() {
			if err := h.waitSocket(ctx, v); err != nil {
				return h.applyFailed("starting "+unit, err)
			}
		}
	}

	return applyFront(ctx, h, undo, v, render.FrontOptions{TLS: render.TLSACME})
}

// applyFront writes the front vhost, checks the whole front config, and reloads Apache. A
// failed check restores the previous file before Apache ever reads it.
func applyFront(ctx context.Context, h *Host, undo *rollback, v render.Vhost, opts render.FrontOptions) error {
	front, err := render.Front(v, opts)
	if err != nil {
		return err
	}
	change, err := h.Files.Write(front)
	if err != nil {
		return h.applyFailed("writing "+front.Path, err)
	}
	if err := h.run(ctx, apachectl, "configtest"); err != nil {
		if rerr := change.Restore(); rerr != nil {
			h.logger().Error("restoring the front config failed", "err", rerr)
		}
		return h.applyFailed("checking the front config", err)
	}
	if err := h.run(ctx, systemctl, "reload", "httpd.service"); err != nil {
		if rerr := change.Restore(); rerr != nil {
			h.logger().Error("restoring the front config failed", "err", rerr)
		}
		return h.applyFailed("reloading the front Apache", err)
	}
	undo.add(func(ctx context.Context) error {
		if err := change.Restore(); err != nil {
			return err
		}
		return h.run(ctx, systemctl, "reload", "httpd.service")
	})
	return nil
}

// deleteVhost runs the §8 delete sequence. Deletion is not rolled back; instead every step
// accepts work already done, so a failed delete can be rerun to completion.
func deleteVhost(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args VhostDeleteArgs) error {
	sv, err := loadVhost(ctx, store, actor, args.VhostID)
	if err != nil {
		return err
	}
	v, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return err
	}
	if args.Confirm != v.Primary() {
		return api.Errorf(api.CodeInvalidArgument, "confirm must repeat the primary domain")
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if err := store.SetVhostStatus(ctx, sv.N, state.VhostDeleting); err != nil {
		return err
	}
	if err := teardownVhost(ctx, store, h, sv, v); err != nil {
		if serr := store.SetVhostStatus(ctx, sv.N, state.VhostFailed); serr != nil {
			h.logger().Error("recording the failed delete", "err", serr)
		}
		return err
	}
	return store.DeleteVhost(ctx, sv.N)
}

// stopUnit disables and stops a unit, accepting a unit that is already gone as long as it
// is not running.
func (h *Host) stopUnit(ctx context.Context, unit string) error {
	err := h.run(ctx, systemctl, "disable", "--now", unit)
	if err == nil {
		return nil
	}
	active := h.run(ctx, systemctl, "is-active", "--quiet", unit)
	if exitCode(active) == systemctlNotActive {
		return nil
	}
	return h.applyFailed("stopping "+unit, err)
}

func teardownVhost(ctx context.Context, store *state.Store, h *Host, sv state.Vhost, v render.Vhost) error {
	id, uid := sv.ID, strconv.Itoa(sv.UID)
	mount := render.MountUnitName(BaseJail + "/" + id + "/site")
	for _, unit := range []string{v.HTTPDUnit(), v.FPMUnit(), mount} {
		if err := h.stopUnit(ctx, unit); err != nil {
			return err
		}
	}

	front, err := render.Front(v, render.FrontOptions{TLS: render.TLSACME})
	if err != nil {
		return err
	}
	if change, err := h.Files.Remove(front.Path); err != nil {
		return h.applyFailed("removing "+front.Path, err)
	} else if change.Changed() {
		if err := h.run(ctx, apachectl, "configtest"); err != nil {
			if rerr := change.Restore(); rerr != nil {
				h.logger().Error("restoring the front config failed", "err", rerr)
			}
			return h.applyFailed("checking the front config", err)
		}
		if err := h.run(ctx, systemctl, "reload", "httpd.service"); err != nil {
			return h.applyFailed("reloading the front Apache", err)
		}
	}

	chain, key := render.CertPaths(v)
	for _, f := range append(ownFiles(v), chain, key) {
		if _, err := h.Files.Remove(f); err != nil {
			return h.applyFailed("removing "+f, err)
		}
	}
	if err := h.run(ctx, systemctl, "unmask", "user@"+uid+".service"); err != nil {
		return h.applyFailed("unmasking user@"+uid+".service", err)
	}
	if err := h.run(ctx, systemctl, "daemon-reload"); err != nil {
		return h.applyFailed("reloading systemd", err)
	}

	if acct, err := store.AccessAccountOf(ctx, sv.N); err == nil {
		if err := teardownAccess(ctx, store, h, sv, acct); err != nil {
			return err
		}
	} else if !errors.Is(err, state.ErrNotFound) {
		return err
	}
	if err := h.FS.RemoveTree(BaseJail, id); err != nil {
		return h.applyFailed("removing the jail", err)
	}
	if err := archiveTree(ctx, h, sv); err != nil {
		return err
	}
	if err := h.FS.RemoveTree(BaseFPMRun, id); err != nil {
		return h.applyFailed("removing the FPM socket directory", err)
	}
	if err := dropVhostDatabases(ctx, store, h, sv); err != nil {
		return err
	}
	if err := h.run(ctx, userdel, id); err != nil && exitCode(err) != userdelNoSuchUser {
		return h.applyFailed("removing user "+id, err)
	}
	if err := h.run(ctx, groupdel, id); err != nil && exitCode(err) != groupdelNoSuchGrp {
		return h.applyFailed("removing group "+id, err)
	}
	if err := h.FS.PruneOlder(BaseArchive, h.now().Add(-ArchiveRetention)); err != nil {
		h.logger().Error("pruning old archives failed", "err", err)
	}
	return nil
}

// ownFiles lists the vhost's own rendered files; the owner slice is shared and stays.
func ownFiles(v render.Vhost) []string {
	return []string{
		"/etc/paddock/httpd/" + v.ID() + ".conf",
		"/etc/paddock/fpm/" + v.ID() + ".conf",
		"/etc/systemd/system/" + v.HTTPDUnit() + ".d/10-sandbox.conf",
		"/etc/systemd/system/" + v.FPMUnit() + ".d/10-sandbox.conf",
		fmt.Sprintf("/etc/systemd/system/user-%d.slice.d/limits.conf", v.UID()),
		"/etc/tmpfiles.d/paddock-" + v.ID() + ".conf",
		"/etc/systemd/system/" + render.MountUnitName(BaseJail+"/"+v.ID()+"/site"),
	}
}

// archiveTree saves the vhost's files under the archive directory, releases its XFS project,
// and removes the tree. A tree already gone means an earlier run got this far.
func archiveTree(ctx context.Context, h *Host, sv state.Vhost) error {
	id := sv.ID
	exists, err := h.FS.Exists(BaseWWW, id)
	if err != nil {
		return h.applyFailed("inspecting "+BaseWWW+"/"+id, err)
	}
	if !exists {
		return nil
	}
	if err := h.FS.EnsureBase(BaseArchive, 0o700); err != nil {
		return h.applyFailed("creating the archive directory", err)
	}
	name := fmt.Sprintf("%s/%s-%s.tar.gz", BaseArchive, id, h.now().UTC().Format("20060102T150405Z"))
	if err := h.run(ctx, tar, "--create", "--gzip", "--numeric-owner", "--xattrs", "--selinux", "--acls",
		"--file", name, "--directory", BaseWWW, id); err != nil {
		return h.applyFailed("archiving "+id, err)
	}
	project := strconv.Itoa(sv.N)
	if err := h.run(ctx, xfsQuota, "-x", "-c", "limit -p bhard=0 "+project, BaseWWW); err != nil {
		return h.applyFailed("clearing the disk limit", err)
	}
	if err := h.run(ctx, xfsQuota, "-x", "-c", "project -C -p "+BaseWWW+"/"+id+" "+project, BaseWWW); err != nil {
		return h.applyFailed("releasing the XFS project", err)
	}
	if err := h.FS.RemoveTree(BaseWWW, id); err != nil {
		return h.applyFailed("removing "+BaseWWW+"/"+id, err)
	}
	return nil
}
