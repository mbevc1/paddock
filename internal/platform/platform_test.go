package platform

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const alma95 = `NAME="AlmaLinux"
VERSION="9.5 (Teal Serval)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.5"
`

func TestDetect(t *testing.T) {
	tests := []struct {
		name      string
		osRelease string
		wantMajor int
		wantErr   bool
	}{
		{name: "AlmaLinux 9.5", osRelease: alma95, wantMajor: 9},
		{name: "AlmaLinux 9.4 unquoted", osRelease: "ID=almalinux\nVERSION_ID=9.4\n", wantMajor: 9},
		{name: "AlmaLinux 9.3 too old", osRelease: "ID=almalinux\nVERSION_ID=9.3\n", wantErr: true},
		{name: "AlmaLinux 10 not yet", osRelease: "ID=almalinux\nVERSION_ID=10.0\n", wantErr: true},
		{name: "AlmaLinux 8", osRelease: "ID=almalinux\nVERSION_ID=8.10\n", wantErr: true},
		{name: "other distribution", osRelease: "ID=rocky\nVERSION_ID=9.5\n", wantErr: true},
		{name: "missing version", osRelease: "ID=almalinux\n", wantErr: true},
		{name: "garbage version", osRelease: "ID=almalinux\nVERSION_ID=nine\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Detect(strings.NewReader(tt.osRelease))
			if tt.wantErr {
				if !errors.Is(err, ErrUnsupported) {
					t.Fatalf("err = %v, want ErrUnsupported", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if p.Major != tt.wantMajor {
				t.Errorf("Major = %d, want %d", p.Major, tt.wantMajor)
			}
		})
	}
}

func TestEL9(t *testing.T) {
	p, err := ForMajor(9)
	if err != nil {
		t.Fatal(err)
	}
	if p.RepoPath != "el9" {
		t.Errorf("RepoPath = %q", p.RepoPath)
	}
	if !strings.HasSuffix(p.RemiReleaseURL, "/remi-release-9.rpm") {
		t.Errorf("RemiReleaseURL = %q", p.RemiReleaseURL)
	}
	if !slices.Equal(p.MariaDBModule, []string{"dnf", "-y", "module", "enable", "mariadb:10.11"}) {
		t.Errorf("MariaDBModule = %q", p.MariaDBModule)
	}
	pkgs, err := p.PHPPackages("8.3")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pkgs, "php83-php-fpm") {
		t.Errorf("PHPPackages(8.3) = %q, want php83-php-fpm", pkgs)
	}
	if _, err := p.PHPPackages("7.4"); err == nil {
		t.Error("PHPPackages(7.4) succeeded")
	}
}

var platformStrings = regexp.MustCompile(`\bel(9|10)\b|dnf module|"module"`)

// TestNoPlatformStringsOutside enforces that OS-specific choices stay in this package.
func TestNoPlatformStringsOutside(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == self || strings.HasPrefix(d.Name(), ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if loc := platformStrings.FindIndex(data); loc != nil {
			t.Errorf("%s contains platform-specific string %q; move it to internal/platform", path, data[loc[0]:loc[1]])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
