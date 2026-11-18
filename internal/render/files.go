package render

import (
	"fmt"
	"strings"

	"github.com/mbevc1/paddock/internal/validate"
)

// backendModules is the explicit module set of each backend Apache (§7.2).
var backendModules = []string{
	"mpm_event", "unixd", "systemd", "authz_core", "authz_host", "authn_core", "authn_file",
	"auth_basic", "authz_user", "access_compat", "alias", "dir", "mime", "log_config", "setenvif",
	"env", "headers", "expires", "deflate", "filter", "rewrite", "remoteip", "proxy", "proxy_fcgi",
}

// BackendUnit renders the backend Apache unit template, shipped in the RPM.
func BackendUnit() (File, error) {
	return file("/usr/lib/systemd/system/paddock-httpd@.service", "httpd-unit.tmpl", nil)
}

// FPMUnit renders the FPM unit template for one installed PHP version.
func FPMUnit(p PHP) (File, error) {
	if p.version == "" {
		return File{}, ErrUnvalidated
	}
	return file("/etc/systemd/system/"+p.FPMUnitName(), "fpm-unit.tmpl",
		map[string]string{"Version": p.Version(), "Tag": p.Tag()})
}

// SandboxDropIns renders the sandbox drop-in for the vhost's backend and FPM units.
func SandboxDropIns(v Vhost) ([]File, error) {
	if err := v.valid(); err != nil {
		return nil, err
	}
	data := map[string]any{"OwnerID": v.ownerID, "ID": v.id}
	var out []File
	for _, unit := range []string{v.HTTPDUnit(), v.FPMUnit()} {
		f, err := file("/etc/systemd/system/"+unit+".d/10-sandbox.conf", "sandbox.tmpl", data)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// OwnerSlice renders an owner's slice unit.
func OwnerSlice(l Limits) (File, error) {
	if err := l.valid(); err != nil {
		return File{}, err
	}
	return file("/etc/systemd/system/"+l.SliceName(), "slice.tmpl", l.data())
}

// UserSliceDropIn renders the limits drop-in for the vhost user's login slice.
func UserSliceDropIn(v Vhost, l Limits) (File, error) {
	if err := v.valid(); err != nil {
		return File{}, err
	}
	if err := l.valid(); err != nil {
		return File{}, err
	}
	return file(fmt.Sprintf("/etc/systemd/system/user-%d.slice.d/limits.conf", v.UID()), "slice.tmpl", l.data())
}

func (v Vhost) data() map[string]any {
	return map[string]any{
		"ID": v.id, "Address": v.Address(), "Primary": v.Primary(), "Aliases": v.Aliases(),
		"Domains": v.domains, "PMMaxChildren": v.pmMaxChildren, "UID": v.UID(),
	}
}

// BackendHTTPD renders the vhost's backend Apache config.
func BackendHTTPD(v Vhost) (File, error) {
	if err := v.valid(); err != nil {
		return File{}, err
	}
	data := v.data()
	data["Modules"] = backendModules
	return file("/etc/paddock/httpd/"+v.id+".conf", "backend-httpd.tmpl", data)
}

// FPM renders the vhost's PHP-FPM config.
func FPM(v Vhost) (File, error) {
	if err := v.valid(); err != nil {
		return File{}, err
	}
	return file("/etc/paddock/fpm/"+v.id+".conf", "fpm.tmpl", v.data())
}

// TLS selects how the front vhost gets its certificate.
type TLS string

// TLS sources.
const (
	TLSACME   TLS = "acme"
	TLSUpload TLS = "upload"
)

// FrontOptions select the front vhost variant.
type FrontOptions struct {
	TLS TLS
	// Suspended makes the vhost answer 503 instead of proxying.
	Suspended bool
}

// CertPaths returns where an uploaded certificate chain and key for the vhost are stored.
func CertPaths(v Vhost) (chain, key string) {
	return "/etc/pki/paddock/" + v.id + ".crt", "/etc/pki/paddock/" + v.id + ".key"
}

// Front renders the vhost's front Apache config.
func Front(v Vhost, opts FrontOptions) (File, error) {
	if err := v.valid(); err != nil {
		return File{}, err
	}
	if opts.TLS != TLSACME && opts.TLS != TLSUpload {
		return File{}, fmt.Errorf("%w: TLS source %q", validate.ErrInvalid, opts.TLS)
	}
	data := v.data()
	data["TLS"] = string(opts.TLS)
	data["Suspended"] = opts.Suspended
	data["CertFile"], data["KeyFile"] = CertPaths(v)
	return file("/etc/httpd/conf.d/paddock-"+v.id+".conf", "front.tmpl", data)
}

// FrontGlobal renders the front Apache settings shared by all vhosts.
func FrontGlobal(contactEmail string) (File, error) {
	email, err := validate.Email(contactEmail)
	if err != nil {
		return File{}, err
	}
	return file("/etc/httpd/conf.d/paddock-00-global.conf", "front-global.tmpl", map[string]string{"ContactEmail": email})
}

// PanelHTTP renders the port 80 vhost that serves ACME challenges for the panel hostname.
func PanelHTTP(hostname string) (File, error) {
	h, err := validate.Domain(hostname)
	if err != nil {
		return File{}, err
	}
	return file("/etc/httpd/conf.d/paddock-01-panel.conf", "panel-http.tmpl", map[string]string{"Hostname": h})
}

// MountUnitName returns the systemd mount unit name for an absolute path, as
// systemd-escape --path --suffix=mount does.
func MountUnitName(path string) string {
	trimmed := strings.Trim(path, "/")
	var b strings.Builder
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		switch {
		case c == '/':
			b.WriteByte('-')
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == ':',
			c == '.' && i > 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	if b.Len() == 0 {
		return "-.mount"
	}
	return b.String() + ".mount"
}

func mountUnit(what, where, typ, options string) (File, error) {
	return file("/etc/systemd/system/"+MountUnitName(where), "mount.tmpl",
		map[string]string{"What": what, "Where": where, "Type": typ, "Options": options})
}

// JailMounts renders the vhost jail's mount units: the site bind for every jail, plus /usr,
// /opt/remi, and a private procfs for shell jails.
func JailMounts(v Vhost, shell bool) ([]File, error) {
	if err := v.valid(); err != nil {
		return nil, err
	}
	jail := "/srv/jail/" + v.id
	specs := [][4]string{{"/srv/www/" + v.id, jail + "/site", "none", "bind"}}
	if shell {
		specs = append(specs,
			[4]string{"/usr", jail + "/usr", "none", "bind,ro,nosuid,nodev"},
			[4]string{"/opt/remi", jail + "/opt/remi", "none", "bind,ro,nosuid,nodev"},
			[4]string{"proc", jail + "/proc", "proc", "hidepid=invisible,subset=pid"},
		)
	}
	out := make([]File, 0, len(specs))
	for _, s := range specs {
		f, err := mountUnit(s[0], s[1], s[2], s[3])
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// JailEtc renders the shell jail's passwd and group, which list only the vhost user, and a
// profile that puts the vhost's php and wp first on PATH.
func JailEtc(v Vhost) ([]File, error) {
	if err := v.valid(); err != nil {
		return nil, err
	}
	data := v.data()
	data["Shell"] = "/bin/bash"
	var out []File
	for _, f := range []struct{ name, tmpl string }{
		{"passwd", "jail-passwd.tmpl"}, {"group", "jail-group.tmpl"}, {"profile", "jail-profile.tmpl"},
	} {
		rendered, err := file("/srv/jail/"+v.id+"/etc/"+f.name, f.tmpl, data)
		if err != nil {
			return nil, err
		}
		out = append(out, rendered)
	}
	return out, nil
}

// AuthorizedKeys renders the vhost's authorized_keys file for sshd; each key is validated
// again here.
func AuthorizedKeys(v Vhost, keys []string) (File, error) {
	if err := v.valid(); err != nil {
		return File{}, err
	}
	var b strings.Builder
	for _, k := range keys {
		canon, err := validate.SSHPublicKey(k)
		if err != nil {
			return File{}, err
		}
		b.WriteString(canon)
		b.WriteByte('\n')
	}
	return File{Path: "/etc/ssh/authorized_keys/" + v.id, Data: []byte(b.String()), Mode: fileMode}, nil
}

// Tmpfiles renders the tmpfiles.d entry that recreates the vhost's FPM socket directory at
// boot, since /run is empty after a restart.
func Tmpfiles(v Vhost) (File, error) {
	if err := v.valid(); err != nil {
		return File{}, err
	}
	return file("/etc/tmpfiles.d/paddock-"+v.id+".conf", "tmpfiles.tmpl", v.data())
}

// SSHDDropIn renders the sshd settings for jailed accounts.
func SSHDDropIn() (File, error) {
	return file("/etc/ssh/sshd_config.d/50-paddock.conf", "sshd.tmpl", nil)
}

// NFTables renders the loopback rule that reserves backends for the apache user.
func NFTables() (File, error) {
	return file("/etc/paddock/nftables.conf", "nftables.tmpl", nil)
}

// Sysctl renders the kernel settings.
func Sysctl() (File, error) {
	return file("/etc/sysctl.d/90-paddock.conf", "sysctl.tmpl", nil)
}
