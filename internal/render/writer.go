package render

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/mbevc1/paddock/internal/validate"
)

const dirMode fs.FileMode = 0o755

// Writer installs rendered files below Root, which is "/" on a host and a temp directory in
// tests.
type Writer struct {
	Root string
}

// Change records one write so it can be undone.
type Change struct {
	path     string
	existed  bool
	prev     []byte
	prevMode fs.FileMode
	changed  bool
}

// Changed reports whether the write altered the file.
func (c *Change) Changed() bool { return c.changed }

// Path returns the file's full path below the writer's root.
func (c *Change) Path() string { return c.path }

func (w Writer) root() string {
	if w.Root == "" {
		return "/"
	}
	return w.Root
}

// resolve maps a host path below the root and refuses symlinks on the way.
func (w Writer) resolve(hostPath string) (string, error) {
	if !filepath.IsAbs(hostPath) || filepath.Clean(hostPath) != hostPath {
		return "", fmt.Errorf("%w: path %q must be clean and absolute", validate.ErrInvalid, hostPath)
	}
	return validate.ContainedPath(w.root(), filepath.Join(w.root(), hostPath))
}

// Write installs f atomically: a temp file in the same directory, fsync, rename, then fsync
// of the directory. An identical existing file is left alone.
func (w Writer) Write(f File) (*Change, error) {
	full, err := w.resolve(f.Path)
	if err != nil {
		return nil, err
	}
	c := &Change{path: full}
	fi, err := os.Lstat(full)
	switch {
	case err == nil:
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %s is not a regular file", validate.ErrInvalid, full)
		}
		c.existed, c.prevMode = true, fi.Mode().Perm()
		if c.prev, err = os.ReadFile(full); err != nil { // #nosec G304 -- full is contained in the writer root.
			return nil, err
		}
		if bytes.Equal(c.prev, f.Data) && c.prevMode == f.Mode {
			return c, nil
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(full), dirMode); err != nil {
		return nil, err
	}
	if err := atomicWrite(full, f.Data, f.Mode); err != nil {
		return nil, err
	}
	c.changed = true
	return c, nil
}

// Remove deletes the file at a host path; a missing file is not an error. The returned
// Change restores it.
func (w Writer) Remove(hostPath string) (*Change, error) {
	full, err := w.resolve(hostPath)
	if err != nil {
		return nil, err
	}
	c := &Change{path: full}
	fi, err := os.Lstat(full)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", validate.ErrInvalid, full)
	}
	if c.prev, err = os.ReadFile(full); err != nil { // #nosec G304 -- full is contained in the writer root.
		return nil, err
	}
	c.existed, c.prevMode = true, fi.Mode().Perm()
	if err := os.Remove(full); err != nil {
		return nil, err
	}
	c.changed = true
	return c, syncDir(filepath.Dir(full))
}

// Restore puts back the file as it was before the change, removing it if it did not exist.
func (c *Change) Restore() error {
	if c == nil || !c.changed {
		return nil
	}
	if c.existed {
		if err := os.MkdirAll(filepath.Dir(c.path), dirMode); err != nil {
			return err
		}
		if err := atomicWrite(c.path, c.prev, c.prevMode); err != nil {
			return err
		}
	} else if err := os.Remove(c.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	c.changed = false
	return syncDir(filepath.Dir(c.path))
}

func atomicWrite(path string, data []byte, mode fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- dir is the parent of a contained path.
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
