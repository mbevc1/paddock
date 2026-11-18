package render

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mbevc1/paddock/internal/validate"
)

var update = flag.Bool("update", false, "rewrite golden files")

// reference returns the §7 reference vhost: v00012, owner 3, PHP 8.3, shop.example.com.
func reference(t *testing.T) (Vhost, Limits) {
	t.Helper()
	v, err := NewVhost(12, 3, "8.3", "shop.example.com", []string{"www.shop.example.com"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewLimits(3, 2048, 200, 512)
	if err != nil {
		t.Fatal(err)
	}
	return v, l
}

func goldenFiles(t *testing.T) map[string]File {
	t.Helper()
	v, l := reference(t)
	php83, err := NewPHP("8.3")
	if err != nil {
		t.Fatal(err)
	}
	dropIns, err := SandboxDropIns(v)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := JailMounts(v, true)
	if err != nil {
		t.Fatal(err)
	}
	etc, err := JailEtc(v)
	if err != nil {
		t.Fatal(err)
	}
	must := func(f File, err error) File {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	files := map[string]File{
		"httpd-unit":      must(BackendUnit()),
		"fpm-unit-83":     must(FPMUnit(php83)),
		"sandbox-httpd":   dropIns[0],
		"sandbox-fpm":     dropIns[1],
		"owner-slice":     must(OwnerSlice(l)),
		"user-slice":      must(UserSliceDropIn(v, l)),
		"backend-httpd":   must(BackendHTTPD(v)),
		"fpm":             must(FPM(v)),
		"front-acme":      must(Front(v, FrontOptions{TLS: TLSACME})),
		"front-upload":    must(Front(v, FrontOptions{TLS: TLSUpload})),
		"front-suspended": must(Front(v, FrontOptions{TLS: TLSACME, Suspended: true})),
		"mount-site":      mounts[0],
		"mount-usr":       mounts[1],
		"mount-remi":      mounts[2],
		"mount-proc":      mounts[3],
		"jail-passwd":     etc[0],
		"jail-group":      etc[1],
		"tmpfiles":        must(Tmpfiles(v)),
		"jail-profile":    etc[2],
	}
	return files
}

func TestGolden(t *testing.T) {
	for name, f := range goldenFiles(t) {
		t.Run(name, func(t *testing.T) {
			golden := filepath.Join("testdata", "golden", name)
			content := "# path: " + f.Path + "\n" + string(f.Data)
			if *update {
				if err := os.WriteFile(golden, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run go test -update to create it)", err)
			}
			if content != string(want) {
				t.Errorf("rendered %s differs from %s:\n%s", name, golden, content)
			}
			if f.Mode != 0o644 {
				t.Errorf("mode = %v, want 0644", f.Mode)
			}
		})
	}
}

var fence = regexp.MustCompile("(?s)```[a-z]*\n(.*?)```")

// TestMatchesSpecification compares the reference renders and the host configs in deploy/ with
// the code blocks in docs/plan.md §7, so the specification and the files cannot drift apart.
func TestMatchesSpecification(t *testing.T) {
	plan, err := os.ReadFile(filepath.Join("..", "..", "docs", "plan.md"))
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(plan), "## 7. Rendered files")
	end := strings.Index(string(plan), "### 7.7")
	if start < 0 || end < start {
		t.Fatal("section 7 not found in docs/plan.md")
	}
	var blocks []string
	for _, m := range fence.FindAllStringSubmatch(string(plan)[start:end], -1) {
		blocks = append(blocks, m[1])
	}

	files := goldenFiles(t)
	backend := string(files["backend-httpd"].Data)
	// §7.2 lists the modules in prose instead of LoadModule lines.
	backend = regexp.MustCompile(`(?m)^LoadModule .*\n`).ReplaceAllString(backend, "")
	backend = strings.TrimPrefix(backend, "\n")

	specs := map[string]string{
		"httpd-unit":    string(files["httpd-unit"].Data),
		"fpm-unit-83":   string(files["fpm-unit-83"].Data),
		"sandbox":       string(files["sandbox-fpm"].Data),
		"owner-slice":   string(files["owner-slice"].Data),
		"backend-httpd": backend,
		"fpm":           string(files["fpm"].Data),
		"front-acme":    string(files["front-acme"].Data),
		"mount-site":    string(files["mount-site"].Data),
	}
	for name, path := range map[string]string{
		"panel-http": "etc/httpd/conf.d/paddock-01-panel.conf",
		"sshd":       "etc/ssh/sshd_config.d/50-paddock.conf",
		"nftables":   "etc/paddock/nftables.conf",
		"sysctl":     "etc/sysctl.d/90-paddock.conf",
	} {
		b, err := os.ReadFile(filepath.Join("..", "..", "deploy", path))
		if err != nil {
			t.Fatal(err)
		}
		specs[name] = strings.ReplaceAll(string(b), "@HOSTNAME@", "panel.example.com")
	}
	for name, got := range specs {
		found := false
		for _, b := range blocks {
			if b == got {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s matches no code block in docs/plan.md section 7:\n%s", name, got)
		}
	}
}

func TestRejectsUnvalidatedInput(t *testing.T) {
	var zero Vhost
	if _, err := BackendHTTPD(zero); !errors.Is(err, ErrUnvalidated) {
		t.Errorf("BackendHTTPD(zero) = %v", err)
	}
	if _, err := FPM(zero); !errors.Is(err, ErrUnvalidated) {
		t.Errorf("FPM(zero) = %v", err)
	}
	if _, err := Front(zero, FrontOptions{TLS: TLSACME}); !errors.Is(err, ErrUnvalidated) {
		t.Errorf("Front(zero) = %v", err)
	}
	if _, err := SandboxDropIns(zero); !errors.Is(err, ErrUnvalidated) {
		t.Errorf("SandboxDropIns(zero) = %v", err)
	}
	if _, err := Tmpfiles(zero); !errors.Is(err, ErrUnvalidated) {
		t.Errorf("Tmpfiles(zero) = %v", err)
	}
	if _, err := JailMounts(zero, true); !errors.Is(err, ErrUnvalidated) {
		t.Errorf("JailMounts(zero) = %v", err)
	}
	if _, err := OwnerSlice(Limits{}); !errors.Is(err, ErrUnvalidated) {
		t.Errorf("OwnerSlice(zero) = %v", err)
	}
	if _, err := FPMUnit(PHP{}); !errors.Is(err, ErrUnvalidated) {
		t.Errorf("FPMUnit(zero) = %v", err)
	}
	v, _ := reference(t)
	if _, err := Front(v, FrontOptions{TLS: "self"}); !errors.Is(err, validate.ErrInvalid) {
		t.Errorf("Front with unknown TLS = %v", err)
	}

	for _, tc := range []struct {
		name    string
		n       int
		owner   int64
		php     string
		primary string
		aliases []string
		max     int
	}{
		{"vhost number 0", 0, 3, "8.3", "a.example.com", nil, 10},
		{"owner 0", 1, 0, "8.3", "a.example.com", nil, 10},
		{"PHP 7.4", 1, 3, "7.4", "a.example.com", nil, 10},
		{"newline in domain", 1, 3, "8.3", "a.example.com\nInclude /etc/shadow", nil, 10},
		{"directive in alias", 1, 3, "8.3", "a.example.com", []string{"b.example.com ProxyPass"}, 10},
		{"duplicate alias", 1, 3, "8.3", "a.example.com", []string{"A.example.com"}, 10},
		{"wildcard", 1, 3, "8.3", "*.example.com", nil, 10},
		{"zero children", 1, 3, "8.3", "a.example.com", nil, 0},
	} {
		if _, err := NewVhost(tc.n, tc.owner, tc.php, tc.primary, tc.aliases, tc.max); !errors.Is(err, validate.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", tc.name, err)
		}
	}
	if _, err := NewLimits(3, 0, 200, 512); !errors.Is(err, validate.ErrInvalid) {
		t.Errorf("NewLimits(0 MB) = %v", err)
	}
}

func TestMountUnitName(t *testing.T) {
	for in, want := range map[string]string{
		"/srv/jail/v00012/site":     "srv-jail-v00012-site.mount",
		"/srv/jail/v00012/opt/remi": "srv-jail-v00012-opt-remi.mount",
		"/srv/a-b":                  `srv-a\x2db.mount`,
		"/":                         "-.mount",
	} {
		if got := MountUnitName(in); got != want {
			t.Errorf("MountUnitName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSliceMemoryUnits(t *testing.T) {
	l, err := NewLimits(3, 1536, 100, 64)
	if err != nil {
		t.Fatal(err)
	}
	f, err := OwnerSlice(l)
	if err != nil || !strings.Contains(string(f.Data), "MemoryMax=1536M\n") {
		t.Errorf("OwnerSlice = %q, %v", f.Data, err)
	}
}

// TestDeployedBackendUnitMatches keeps the unit the RPM ships in step with the renderer.
func TestDeployedBackendUnitMatches(t *testing.T) {
	want, err := BackendUnit()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "paddock-httpd@.service"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want.Data) {
		t.Errorf("deploy/systemd/paddock-httpd@.service differs from render.BackendUnit:\n%s", got)
	}
}
