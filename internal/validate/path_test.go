package validate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainedPath(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "v00012", "public"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "v00012", "link")); err != nil {
		t.Fatal(err)
	}

	valid := map[string]string{
		root:                                    root,
		filepath.Join(root, "v00012"):           filepath.Join(root, "v00012"),
		filepath.Join(root, "v00012", "public"): filepath.Join(root, "v00012", "public"),
		filepath.Join(root, "v00012", "new.conf"):  filepath.Join(root, "v00012", "new.conf"),
		filepath.Join(root, "v00012", "a", "b"):    filepath.Join(root, "v00012", "a", "b"),
		root + "/v00012/public/../public/./x.conf": filepath.Join(root, "v00012", "public", "x.conf"),
	}
	for in, want := range valid {
		got, err := ContainedPath(root, in)
		if err != nil || got != want {
			t.Errorf("ContainedPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	invalidPaths := []string{
		filepath.Join(root, ".."),
		root + "/../etc/passwd",
		root + "/v00012/../../etc",
		filepath.Dir(root),
		root + "x",
		"v00012/public",
		"",
		root + "/v00012/pub\x00lic",
		filepath.Join(root, "v00012", "link"),
		filepath.Join(root, "v00012", "link", "file"),
	}
	for _, in := range invalidPaths {
		_, err := ContainedPath(root, in)
		assertInvalid(t, err)
	}

	_, err := ContainedPath(filepath.Join(root, "missing"), filepath.Join(root, "missing", "x"))
	assertInvalid(t, err)

	link := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	_, err = ContainedPath(link, filepath.Join(link, "v00012"))
	assertInvalid(t, err)
}
