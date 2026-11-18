// Package render produces the host files from docs/plan.md §7. Inputs are types that only
// the constructors in this package can build, after validation, so no raw string reaches a
// template.
package render

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"text/template"

	"github.com/mbevc1/paddock/internal/validate"
)

//go:embed templates/*.tmpl
var templateFiles embed.FS

var templates = template.Must(template.New("").
	Option("missingkey=error").
	Funcs(template.FuncMap{"join": strings.Join}).
	ParseFS(templateFiles, "templates/*.tmpl"))

// ErrUnvalidated reports a zero value passed where a constructed one is required.
var ErrUnvalidated = errors.New("render input was not built by its constructor")

// File is one rendered host file. Path is absolute on the target host.
type File struct {
	Path string
	Data []byte
	Mode fs.FileMode
}

const fileMode fs.FileMode = 0o644

func execute(name string, data any) ([]byte, error) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, data); err != nil {
		return nil, fmt.Errorf("render %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

func file(path, tmpl string, data any) (File, error) {
	b, err := execute(tmpl, data)
	if err != nil {
		return File{}, err
	}
	return File{Path: path, Data: b, Mode: fileMode}, nil
}

// PHP is a validated PHP version.
type PHP struct{ version string }

// NewPHP validates a PHP version such as "8.3".
func NewPHP(version string) (PHP, error) {
	if err := validate.PHPVersion(version); err != nil {
		return PHP{}, err
	}
	return PHP{version: version}, nil
}

// Version returns the version, for example "8.3".
func (p PHP) Version() string { return p.version }

// Tag returns the version without the dot, for example "83".
func (p PHP) Tag() string { return strings.ReplaceAll(p.version, ".", "") }

// FPMUnitName returns the FPM template unit for this version, for example
// "paddock-php83-fpm@.service".
func (p PHP) FPMUnitName() string { return "paddock-php" + p.Tag() + "-fpm@.service" }

// Vhost is the validated description of one vhost.
type Vhost struct {
	n             int
	id            string
	ownerID       int64
	php           PHP
	domains       []string
	pmMaxChildren int
}

// NewVhost validates everything a vhost's files are rendered from. Aliases must not repeat
// the primary domain or each other.
func NewVhost(n int, ownerID int64, php, primary string, aliases []string, pmMaxChildren int) (Vhost, error) {
	id, err := validate.VhostNumber(n)
	if err != nil {
		return Vhost{}, err
	}
	if err := validate.OwnerID(ownerID); err != nil {
		return Vhost{}, err
	}
	p, err := NewPHP(php)
	if err != nil {
		return Vhost{}, err
	}
	if pmMaxChildren < 1 {
		return Vhost{}, fmt.Errorf("%w: pm.max_children %d", validate.ErrInvalid, pmMaxChildren)
	}
	domains := make([]string, 0, 1+len(aliases))
	seen := map[string]bool{}
	for _, d := range append([]string{primary}, aliases...) {
		canon, err := validate.Domain(d)
		if err != nil {
			return Vhost{}, err
		}
		if seen[canon] {
			return Vhost{}, fmt.Errorf("%w: domain %s listed twice", validate.ErrInvalid, canon)
		}
		seen[canon] = true
		domains = append(domains, canon)
	}
	return Vhost{n: n, id: id, ownerID: ownerID, php: p, domains: domains, pmMaxChildren: pmMaxChildren}, nil
}

func (v Vhost) valid() error {
	if v.id == "" {
		return ErrUnvalidated
	}
	return nil
}

// ID returns the vhost ID, for example "v00012".
func (v Vhost) ID() string { return v.id }

// UID returns the vhost user's UID and GID.
func (v Vhost) UID() int { return validate.VhostUIDBase + v.n }

// Address returns the backend loopback address without port.
func (v Vhost) Address() string { return fmt.Sprintf("127.64.%d.%d", v.n>>8, v.n&255) }

// PHP returns the vhost's PHP version.
func (v Vhost) PHP() PHP { return v.php }

// Primary returns the primary domain.
func (v Vhost) Primary() string { return v.domains[0] }

// Aliases returns the alias domains.
func (v Vhost) Aliases() []string { return v.domains[1:] }

// HTTPDUnit returns the backend unit instance, for example "paddock-httpd@v00012.service".
func (v Vhost) HTTPDUnit() string { return "paddock-httpd@" + v.id + ".service" }

// FPMUnit returns the FPM unit instance for the vhost's PHP version.
func (v Vhost) FPMUnit() string { return "paddock-php" + v.php.Tag() + "-fpm@" + v.id + ".service" }

// Limits are the resource limits rendered into slices.
type Limits struct {
	ownerID     int64
	memoryMaxMB int
	cpuQuotaPct int
	tasksMax    int
}

// NewLimits validates an owner's slice limits.
func NewLimits(ownerID int64, memoryMaxMB, cpuQuotaPct, tasksMax int) (Limits, error) {
	if err := validate.OwnerID(ownerID); err != nil {
		return Limits{}, err
	}
	if memoryMaxMB < 1 || cpuQuotaPct < 1 || tasksMax < 1 {
		return Limits{}, fmt.Errorf("%w: slice limits must be positive", validate.ErrInvalid)
	}
	return Limits{ownerID: ownerID, memoryMaxMB: memoryMaxMB, cpuQuotaPct: cpuQuotaPct, tasksMax: tasksMax}, nil
}

// SliceName returns the owner slice, for example "paddock-owner-3.slice".
func (l Limits) SliceName() string { return fmt.Sprintf("paddock-owner-%d.slice", l.ownerID) }

func (l Limits) valid() error {
	if l.ownerID == 0 {
		return ErrUnvalidated
	}
	return nil
}

func (l Limits) data() map[string]any {
	mem := fmt.Sprintf("%dM", l.memoryMaxMB)
	if l.memoryMaxMB%1024 == 0 {
		mem = fmt.Sprintf("%dG", l.memoryMaxMB/1024)
	}
	return map[string]any{"MemoryMax": mem, "CPUQuotaPct": l.cpuQuotaPct, "TasksMax": l.tasksMax}
}
