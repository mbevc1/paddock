package ops

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mbevc1/paddock/internal/validate"
)

// Base directories the agent may create in or delete from. Every path HostFS touches is a
// relative name below one of these, opened through os.Root so symlinks cannot lead out.
const (
	BaseWWW     = "/srv/www"
	BaseJail    = "/srv/jail"
	BaseFPMRun  = "/run/paddock/fpm"
	BaseArchive = "/var/lib/paddock/agent/archive"
)

var allowedBases = map[string]bool{BaseWWW: true, BaseJail: true, BaseFPMRun: true, BaseArchive: true}

// HostFS changes directories below the allowed bases. Root prefixes every host path; it is
// "/" on a host and a temp directory in tests.
type HostFS struct {
	Root string
	// Chown sets ownership without following symlinks; nil uses os.Root.Lchown. Tests
	// replace it because they cannot give files away.
	Chown func(r *os.Root, name string, uid, gid int) error
	// MountInfo is the mount table to check before deleting; empty means /proc/self/mountinfo.
	MountInfo string
}

func (f *HostFS) open(base string) (*os.Root, error) {
	if !allowedBases[base] {
		return nil, fmt.Errorf("%w: base %q not allowed", validate.ErrInvalid, base)
	}
	root := f.Root
	if root == "" {
		root = "/"
	}
	return os.OpenRoot(filepath.Join(root, base))
}

func checkRel(rel string) error {
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel || rel == "." ||
		rel == ".." || strings.HasPrefix(rel, "../") || strings.ContainsRune(rel, 0) {
		return fmt.Errorf("%w: relative path %q", validate.ErrInvalid, rel)
	}
	return nil
}

// Mkdir creates base/rel, or fixes an existing directory, with the given mode and owner.
// Parents must exist.
func (f *HostFS) Mkdir(base, rel string, mode fs.FileMode, uid, gid int) error {
	if err := checkRel(rel); err != nil {
		return err
	}
	r, err := f.open(base)
	if err != nil {
		return err
	}
	defer r.Close()
	// os.Root.Mkdir takes permission bits only; Chmod below adds sticky and the like.
	if err := r.Mkdir(rel, mode.Perm()); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	fi, err := r.Lstat(rel)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s/%s is not a directory", validate.ErrInvalid, base, rel)
	}
	chown := f.Chown
	if chown == nil {
		chown = func(r *os.Root, name string, uid, gid int) error { return r.Lchown(name, uid, gid) }
	}
	if err := chown(r, rel, uid, gid); err != nil {
		return err
	}
	// Chmod after chown: chown clears setuid and setgid bits.
	return r.Chmod(rel, mode)
}

// EnsureBase creates an allowed base directory, owned by root, if it is missing.
func (f *HostFS) EnsureBase(base string, mode fs.FileMode) error {
	if !allowedBases[base] {
		return fmt.Errorf("%w: base %q not allowed", validate.ErrInvalid, base)
	}
	root := f.Root
	if root == "" {
		root = "/"
	}
	return os.MkdirAll(filepath.Join(root, base), mode)
}

// Exists reports whether base/rel exists, without following a final symlink.
func (f *HostFS) Exists(base, rel string) (bool, error) {
	if err := checkRel(rel); err != nil {
		return false, err
	}
	r, err := f.open(base)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer r.Close()
	_, err = r.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// RemoveTree deletes base/rel and everything below it. It refuses when anything is mounted
// at or below that path: removal would otherwise reach through bind mounts.
func (f *HostFS) RemoveTree(base, rel string) error {
	if err := checkRel(rel); err != nil {
		return err
	}
	target := filepath.Join(base, rel)
	mounted, err := f.mountedBelow(target)
	if err != nil {
		return err
	}
	if mounted != "" {
		return fmt.Errorf("%w: %s is mounted below %s", validate.ErrInvalid, mounted, target)
	}
	r, err := f.open(base)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer r.Close()
	return r.RemoveAll(rel)
}

// mountedBelow returns a mount point at or below hostPath, or "".
func (f *HostFS) mountedBelow(hostPath string) (string, error) {
	info := f.MountInfo
	if info == "" {
		info = "/proc/self/mountinfo"
	}
	file, err := os.Open(info) // #nosec G304 -- the mount table path is fixed or set by tests.
	if err != nil {
		return "", err
	}
	defer file.Close()
	full := filepath.Join(f.Root, hostPath)
	if f.Root == "" {
		full = hostPath
	}
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		mp := unescapeMount(fields[4])
		if mp == full || strings.HasPrefix(mp, full+"/") {
			return mp, nil
		}
	}
	return "", sc.Err()
}

// unescapeMount decodes the octal escapes (\040 for space) the kernel uses in mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// PruneOlder removes regular files directly in base that were last modified before cutoff.
func (f *HostFS) PruneOlder(base string, cutoff time.Time) error {
	r, err := f.open(base)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer r.Close()
	entries, err := fs.ReadDir(r.FS(), ".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		fi, err := r.Lstat(e.Name())
		if err != nil {
			return err
		}
		if fi.ModTime().Before(cutoff) {
			if err := r.Remove(e.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

// Symlink makes base/rel a symlink to target, replacing a different link. It refuses to
// replace anything that is not a symlink.
func (f *HostFS) Symlink(base, rel, target string) error {
	if err := checkRel(rel); err != nil {
		return err
	}
	r, err := f.open(base)
	if err != nil {
		return err
	}
	defer r.Close()
	if fi, err := r.Lstat(rel); err == nil {
		if fi.Mode()&fs.ModeSymlink == 0 {
			return fmt.Errorf("%w: %s/%s exists and is not a symlink", validate.ErrInvalid, base, rel)
		}
		if cur, err := r.Readlink(rel); err == nil && cur == target {
			return nil
		}
		if err := r.Remove(rel); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return r.Symlink(target, rel)
}
