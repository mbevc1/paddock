package render

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mbevc1/paddock/internal/validate"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriterWriteAndRestore(t *testing.T) {
	root := t.TempDir()
	w := Writer{Root: root}
	full := filepath.Join(root, "etc", "paddock", "httpd", "v00012.conf")

	c1, err := w.Write(File{Path: "/etc/paddock/httpd/v00012.conf", Data: []byte("one\n"), Mode: 0o644})
	if err != nil || !c1.Changed() || c1.Path() != full {
		t.Fatalf("first write: %+v, %v", c1, err)
	}
	fi, err := os.Stat(full)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, %v", fi.Mode().Perm(), err)
	}

	same, err := w.Write(File{Path: "/etc/paddock/httpd/v00012.conf", Data: []byte("one\n"), Mode: 0o644})
	if err != nil || same.Changed() {
		t.Errorf("identical write changed the file: %v", err)
	}

	c2, err := w.Write(File{Path: "/etc/paddock/httpd/v00012.conf", Data: []byte("two\n"), Mode: 0o600})
	if err != nil || !c2.Changed() || readFile(t, full) != "two\n" {
		t.Fatalf("second write: %v", err)
	}
	if err := c2.Restore(); err != nil {
		t.Fatal(err)
	}
	if readFile(t, full) != "one\n" {
		t.Errorf("restore did not bring back the previous content")
	}
	if fi, _ := os.Stat(full); fi.Mode().Perm() != 0o644 {
		t.Errorf("restore mode = %v", fi.Mode().Perm())
	}
	if err := c2.Restore(); err != nil {
		t.Errorf("second restore: %v", err)
	}

	if err := c1.Restore(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(full); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("restore of a new file left it in place: %v", err)
	}

	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(full), ".*tmp-*"))
	if err != nil || len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}

func TestWriterRefusesSymlinksAndEscapes(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	w := Writer{Root: root}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc", "paddock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "target"), filepath.Join(root, "etc", "link.conf")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"/etc/paddock/httpd/v00012.conf",
		"/etc/link.conf",
		"/etc/../../outside.conf",
		"etc/relative.conf",
	} {
		if _, err := w.Write(File{Path: p, Data: []byte("x"), Mode: 0o644}); !errors.Is(err, validate.ErrInvalid) {
			t.Errorf("Write(%q) err = %v, want ErrInvalid", p, err)
		}
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Errorf("files written outside the root: %v", entries)
	}
}
