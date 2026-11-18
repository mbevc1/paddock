package ops

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mbevc1/paddock/internal/validate"
)

type chownCall struct {
	name     string
	uid, gid int
}

func testFS(t *testing.T) (*HostFS, *[]chownCall) {
	t.Helper()
	root := t.TempDir()
	for _, base := range []string{BaseWWW, BaseJail, BaseFPMRun, BaseArchive} {
		if err := os.MkdirAll(filepath.Join(root, base), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	info := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(info, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []chownCall
	return &HostFS{
		Root:      root,
		MountInfo: info,
		Chown: func(_ *os.Root, name string, uid, gid int) error {
			calls = append(calls, chownCall{name, uid, gid})
			return nil
		},
	}, &calls
}

func TestHostFSMkdirAndRemove(t *testing.T) {
	f, calls := testFS(t)
	if err := f.Mkdir(BaseWWW, "v00012", 0o700, 100012, 100012); err != nil {
		t.Fatal(err)
	}
	if err := f.Mkdir(BaseWWW, "v00012/public", 0o750, 100012, 100012); err != nil {
		t.Fatal(err)
	}
	if err := f.Mkdir(BaseWWW, "v00012", 0o700, 100012, 100012); err != nil {
		t.Errorf("Mkdir on an existing directory: %v", err)
	}
	fi, err := os.Stat(filepath.Join(f.Root, BaseWWW, "v00012", "public"))
	if err != nil || fi.Mode().Perm() != 0o750 {
		t.Errorf("public mode = %v, %v", fi.Mode().Perm(), err)
	}
	if len(*calls) != 3 || (*calls)[1] != (chownCall{"v00012/public", 100012, 100012}) {
		t.Errorf("chown calls = %v", *calls)
	}
	if ok, err := f.Exists(BaseWWW, "v00012/public"); !ok || err != nil {
		t.Errorf("Exists = %v, %v", ok, err)
	}

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.Root, BaseWWW, "v00012", "public", "escape")); err != nil {
		t.Fatal(err)
	}
	if err := f.Mkdir(BaseWWW, "v00012/public/escape/new", 0o700, 1, 1); err == nil {
		t.Error("Mkdir followed a symlink out of the base")
	}
	if err := f.RemoveTree(BaseWWW, "v00012"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Errorf("RemoveTree reached through a symlink: %v", err)
	}
	if ok, _ := f.Exists(BaseWWW, "v00012"); ok {
		t.Error("tree still present")
	}
	if err := f.RemoveTree(BaseWWW, "v00012"); err != nil {
		t.Errorf("removing a missing tree: %v", err)
	}
}

func TestHostFSRefusals(t *testing.T) {
	f, _ := testFS(t)
	for _, rel := range []string{"", ".", "..", "../etc", "/etc", "a/../../b", "a\x00b"} {
		if err := f.Mkdir(BaseWWW, rel, 0o700, 1, 1); !errors.Is(err, validate.ErrInvalid) {
			t.Errorf("Mkdir(%q) = %v", rel, err)
		}
		if err := f.RemoveTree(BaseWWW, rel); !errors.Is(err, validate.ErrInvalid) {
			t.Errorf("RemoveTree(%q) = %v", rel, err)
		}
	}
	if err := f.Mkdir("/etc", "x", 0o700, 1, 1); !errors.Is(err, validate.ErrInvalid) {
		t.Errorf("Mkdir outside the bases = %v", err)
	}

	if err := f.Mkdir(BaseJail, "v00012", 0o755, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Mkdir(BaseJail, "v00012/site", 0o755, 0, 0); err != nil {
		t.Fatal(err)
	}
	site := filepath.Join(f.Root, BaseJail, "v00012", "site")
	line := "36 35 98:0 /srv/www/v00012 " + site + " rw,relatime shared:1 - xfs /dev/vdb rw\n"
	if err := os.WriteFile(f.MountInfo, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.RemoveTree(BaseJail, "v00012"); !errors.Is(err, validate.ErrInvalid) {
		t.Errorf("RemoveTree over a mount = %v", err)
	}
	if ok, _ := f.Exists(BaseJail, "v00012/site"); !ok {
		t.Error("jail removed despite the mount")
	}
}

func TestUnescapeMount(t *testing.T) {
	if got := unescapeMount(`/srv/a\040b\134c`); got != `/srv/a b\c` {
		t.Errorf("unescapeMount = %q", got)
	}
}

func TestHostFSPruneOlder(t *testing.T) {
	f, _ := testFS(t)
	dir := filepath.Join(f.Root, BaseArchive)
	now := time.Now()
	for name, age := range map[string]time.Duration{"old.tar.gz": 8 * 24 * time.Hour, "new.tar.gz": time.Hour} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.PruneOlder(BaseArchive, now.Add(-7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.tar.gz")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("old archive kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "new.tar.gz")); err != nil {
		t.Errorf("new archive removed: %v", err)
	}
}

func TestHostFSSymlink(t *testing.T) {
	f, _ := testFS(t)
	if err := f.Mkdir(BaseJail, "v00001", 0o755, 0, 0); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"usr/bin", "usr/bin", "usr/sbin"} {
		if err := f.Symlink(BaseJail, "v00001/bin", target); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := os.Readlink(filepath.Join(f.Root, BaseJail, "v00001", "bin")); err != nil || got != "usr/sbin" {
		t.Errorf("link = %q, %v", got, err)
	}
	if err := f.Mkdir(BaseJail, "v00001/etc", 0o755, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Symlink(BaseJail, "v00001/etc", "/etc"); !errors.Is(err, validate.ErrInvalid) {
		t.Errorf("replacing a directory = %v", err)
	}
}
