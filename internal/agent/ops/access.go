package ops

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mbevc1/paddock/internal/agent"
	"github.com/mbevc1/paddock/internal/api"
	"github.com/mbevc1/paddock/internal/render"
	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/system"
	"github.com/mbevc1/paddock/internal/validate"
)

const (
	usermod  = "/usr/sbin/usermod"
	chpasswd = "/usr/sbin/chpasswd" // #nosec G101 -- a program path, not a credential.
	pkill    = "/usr/bin/pkill"
	// pkillNoMatch is pkill's exit code when no process matched.
	pkillNoMatch = 1
)

// AccessCreateArgs are the arguments of access.create. The SFTP account is named after the
// vhost: sshd chroots it to /srv/jail/<account> (§7.5), so each vhost has at most one.
type AccessCreateArgs struct {
	VhostID  string   `json:"vhost_id"`
	Password string   `json:"password,omitempty"`
	Keys     []string `json:"keys,omitempty"`
}

// AccessKeyArgs are the arguments of access.key.add and access.key.remove.
type AccessKeyArgs struct {
	Account   string `json:"account"`
	PublicKey string `json:"public_key"`
}

// AccessKeyResult identifies a key by its fingerprint.
type AccessKeyResult struct {
	Fingerprint string `json:"fingerprint"`
}

func registerAccess(r *agent.Registry, store *state.Store, h *Host) {
	r.Register(agent.Op{Name: "access.create", Class: agent.ClassOwner, Long: true,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[AccessCreateArgs](c)
			if err != nil {
				return nil, err
			}
			return nil, createAccess(ctx, store, h, c.Actor, args)
		}})
	r.Register(agent.Op{Name: "access.delete", Class: agent.ClassOwner, Long: true,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[VhostIDArgs](c)
			if err != nil {
				return nil, err
			}
			return nil, deleteAccess(ctx, store, h, c.Actor, args.VhostID)
		}})
	r.Register(agent.Op{Name: "access.key.add", Class: agent.ClassOwner,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[AccessKeyArgs](c)
			if err != nil {
				return nil, err
			}
			return changeKeys(ctx, store, h, c.Actor, args, true)
		}})
	r.Register(agent.Op{Name: "access.key.remove", Class: agent.ClassOwner,
		Handler: func(ctx context.Context, c *agent.Call) (any, error) {
			args, err := agent.DecodeArgs[AccessKeyArgs](c)
			if err != nil {
				return nil, err
			}
			return changeKeys(ctx, store, h, c.Actor, args, false)
		}})
}

// canonicalKey validates a key and returns its authorized_keys form and SHA-256 fingerprint.
func canonicalKey(line string) (string, string, error) {
	canon, err := validate.SSHPublicKey(line)
	if err != nil {
		return "", "", invalidArg(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(canon))
	if err != nil {
		return "", "", invalidArg(err)
	}
	return canon, ssh.FingerprintSHA256(pub), nil
}

// writeAuthorizedKeys renders the account's authorized_keys file from state.
func writeAuthorizedKeys(ctx context.Context, store *state.Store, h *Host, v render.Vhost) (*render.Change, error) {
	keys, err := store.ListSSHKeys(ctx, v.ID())
	if err != nil {
		return nil, err
	}
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = k.PublicKey
	}
	f, err := render.AuthorizedKeys(v, lines)
	if err != nil {
		return nil, err
	}
	change, err := h.Files.Write(f)
	if err != nil {
		return nil, h.applyFailed("writing "+f.Path, err)
	}
	return change, nil
}

func createAccess(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args AccessCreateArgs) error {
	if args.Password == "" && len(args.Keys) == 0 {
		return api.Errorf(api.CodeInvalidArgument, "give a password, keys, or both")
	}
	if args.Password != "" {
		if err := validate.AccessPassword(args.Password); err != nil {
			return invalidArg(err)
		}
	}
	type key struct{ line, fp string }
	keys := make([]key, 0, len(args.Keys))
	for _, k := range args.Keys {
		line, fp, err := canonicalKey(k)
		if err != nil {
			return err
		}
		keys = append(keys, key{line, fp})
	}

	sv, err := usableVhost(ctx, store, h, actor, args.VhostID)
	if err != nil {
		return err
	}
	defer h.mu.Unlock()
	v, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return err
	}
	if err := store.CreateAccessAccount(ctx, sv.N, sv.ID); err != nil {
		if errors.Is(err, state.ErrConflict) {
			return api.Errorf(api.CodeConflict, "vhost %s already has an access account", sv.ID)
		}
		return err
	}
	undo := &rollback{h: h}
	undo.add(func(ctx context.Context) error { return store.DeleteAccessAccount(ctx, sv.ID) })
	fail := func(err error) error {
		undo.run(ctx)
		return err
	}

	for _, k := range keys {
		if err := store.AddSSHKey(ctx, sv.ID, k.line, k.fp); err != nil && !errors.Is(err, state.ErrConflict) {
			return fail(err)
		}
	}
	defer func() {
		for _, k := range keys {
			keyAddedEvent(ctx, store, h, sv, k.fp)
		}
	}()
	change, err := writeAuthorizedKeys(ctx, store, h, v)
	if err != nil {
		return fail(err)
	}
	undo.add(func(context.Context) error { return change.Restore() })

	undo.add(func(ctx context.Context) error {
		return h.run(ctx, usermod, "-s", "/sbin/nologin", "-G", "", "-L", sv.ID)
	})
	if err := h.run(ctx, usermod, "-s", "/sbin/nologin", "-G", "paddock-sftp", sv.ID); err != nil {
		return fail(h.applyFailed("enabling login for "+sv.ID, err))
	}
	if args.Password != "" {
		_, err := h.Run.Run(ctx, []string{chpasswd}, system.Opts{Stdin: strings.NewReader(sv.ID + ":" + args.Password + "\n")})
		if err != nil {
			return fail(h.applyFailed("setting the password of "+sv.ID, err))
		}
	}
	return nil
}

func deleteAccess(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, vhostID string) error {
	sv, err := usableVhost(ctx, store, h, actor, vhostID)
	if err != nil {
		return err
	}
	defer h.mu.Unlock()
	acct, err := store.AccessAccountOf(ctx, sv.N)
	if errors.Is(err, state.ErrNotFound) {
		return api.Errorf(api.CodeNotFound, "vhost %s has no access account", sv.ID)
	}
	if err != nil {
		return err
	}
	return teardownAccess(ctx, store, h, sv, acct)
}

// teardownAccess locks the account, ends its SSH sessions, and removes its keys. Every step
// accepts work already done.
func teardownAccess(ctx context.Context, store *state.Store, h *Host, sv state.Vhost, acct state.AccessAccount) error {
	if err := h.run(ctx, usermod, "-s", "/sbin/nologin", "-G", "", "-L", sv.ID); err != nil {
		return h.applyFailed("locking "+sv.ID, err)
	}
	// Sessions run as the vhost UID like FPM and Apache, so only sshd processes are ended.
	if err := h.run(ctx, pkill, "--uid", strconv.Itoa(sv.UID), "--exact", "sshd"); err != nil && exitCode(err) != pkillNoMatch {
		return h.applyFailed("ending SSH sessions of "+sv.ID, err)
	}
	if _, err := h.Files.Remove("/etc/ssh/authorized_keys/" + sv.ID); err != nil {
		return h.applyFailed("removing the authorized keys of "+sv.ID, err)
	}
	return store.DeleteAccessAccount(ctx, acct.Name)
}

func changeKeys(ctx context.Context, store *state.Store, h *Host, actor *api.Actor, args AccessKeyArgs, add bool) (any, error) {
	line, fp, err := canonicalKey(args.PublicKey)
	if err != nil {
		return nil, err
	}
	sv, err := usableVhost(ctx, store, h, actor, args.Account)
	if err != nil {
		return nil, err
	}
	defer h.mu.Unlock()
	if _, err := store.AccessAccountOf(ctx, sv.N); err != nil {
		return nil, api.Errorf(api.CodeNotFound, "account %s not found", args.Account)
	}
	if add {
		err = store.AddSSHKey(ctx, sv.ID, line, fp)
		if errors.Is(err, state.ErrConflict) {
			return nil, api.Errorf(api.CodeConflict, "key %s is already authorized", fp)
		}
	} else {
		err = store.RemoveSSHKey(ctx, sv.ID, fp)
		if errors.Is(err, state.ErrNotFound) {
			return nil, api.Errorf(api.CodeNotFound, "key %s is not authorized", fp)
		}
	}
	if err != nil {
		return nil, err
	}
	v, err := renderedVhost(ctx, store, sv)
	if err != nil {
		return nil, err
	}
	if _, err := writeAuthorizedKeys(ctx, store, h, v); err != nil {
		var undoErr error
		if add {
			undoErr = store.RemoveSSHKey(ctx, sv.ID, fp)
		} else {
			undoErr = store.AddSSHKey(ctx, sv.ID, line, fp)
		}
		if undoErr != nil {
			h.logger().Error("restoring the key list failed", "err", undoErr)
		}
		return nil, err
	}
	if add {
		keyAddedEvent(ctx, store, h, sv, fp)
	}
	return AccessKeyResult{Fingerprint: fp}, nil
}

// keyAddedEvent tells the owner a key can now log in (§11.5); only a stored account counts.
func keyAddedEvent(ctx context.Context, store *state.Store, h *Host, sv state.Vhost, fp string) {
	if _, err := store.AccessAccountOf(ctx, sv.N); err != nil {
		return
	}
	if _, err := store.AppendEvent(ctx, state.Event{Kind: state.EventSSHKeyAdded, OwnerID: sv.OwnerID, VhostN: sv.N,
		Message: "SSH key " + fp + " added to " + sv.ID}); err != nil {
		h.logger().Error("event write failed", "err", err)
	}
}
