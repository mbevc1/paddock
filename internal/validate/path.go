package validate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ContainedPath checks that p is an absolute path inside root (or root itself) and that no
// existing component from root down is a symlink. Missing trailing components are allowed,
// so the result can name a file about to be created. The check is a guard against bad input,
// not against concurrent changes: writers must still open files without following symlinks.
func ContainedPath(root, p string) (string, error) {
	if strings.ContainsRune(root, 0) || strings.ContainsRune(p, 0) {
		return "", invalid("path contains NUL")
	}
	if !filepath.IsAbs(root) || !filepath.IsAbs(p) {
		return "", invalid("path %q and root %q must be absolute", p, root)
	}
	root = filepath.Clean(root)
	clean := filepath.Clean(p)
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", invalid("path %q is outside %q", p, root)
	}

	current := root
	if err := notSymlink(current); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", invalid("root %q does not exist", root)
		}
		return "", err
	}
	if rel == "." {
		return clean, nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := notSymlink(current); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return clean, nil
			}
			return "", err
		}
	}
	return clean, nil
}

func notSymlink(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return invalid("cannot inspect %q", p)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return invalid("path component %q is a symlink", p)
	}
	return nil
}
