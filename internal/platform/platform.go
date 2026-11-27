// Package platform holds every choice that depends on the Enterprise Linux major version:
// package names, module commands, repository URLs, and the Remi release package. No other
// package may hard-code them.
package platform

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrUnsupported reports an operating system Paddock does not run on.
var ErrUnsupported = errors.New("unsupported operating system")

// minMinorEL9 is the oldest supported EL 9 minor release (9.4).
const minMinorEL9 = 4

// Platform describes the OS-specific choices for one EL major version.
type Platform struct {
	// Major is the EL major version, for example 9.
	Major int
	// RepoPath is the path segment of the Paddock dnf repository, for example "el9".
	RepoPath string
	// RemiReleaseURL is the URL of the remi-release package for this major version.
	RemiReleaseURL string
	// MariaDBModule is the dnf argv that enables MariaDB 10.11; empty when no module is needed.
	MariaDBModule []string
	// BasePackages are the host packages Paddock depends on.
	BasePackages []string
}

var phpExtensions = []string{"fpm", "cli", "mysqlnd", "opcache", "gd", "mbstring", "xml", "intl", "pecl-zip", "bcmath", "pecl-apcu"}

var supportedPHP = map[string]bool{"8.2": true, "8.3": true, "8.4": true}

// PHPPackages returns the Remi packages for a PHP version such as "8.3".
func (p Platform) PHPPackages(version string) ([]string, error) {
	if !supportedPHP[version] {
		return nil, fmt.Errorf("unsupported PHP version %q", version)
	}
	prefix := "php" + strings.ReplaceAll(version, ".", "") + "-php-"
	pkgs := make([]string, len(phpExtensions))
	for i, ext := range phpExtensions {
		pkgs[i] = prefix + ext
	}
	return pkgs, nil
}

// dnf is the package manager on every supported release.
const dnf = "/usr/bin/dnf"

// InstallArgv returns the argv that installs packages.
func (p Platform) InstallArgv(pkgs []string) []string {
	return append([]string{dnf, "-y", "install"}, pkgs...)
}

// RemoveArgv returns the argv that removes packages.
func (p Platform) RemoveArgv(pkgs []string) []string {
	return append([]string{dnf, "-y", "remove"}, pkgs...)
}

// InstalledArgv returns the argv that exits zero only when every package is installed.
func (p Platform) InstalledArgv(pkgs []string) []string {
	return append([]string{"/usr/bin/rpm", "-q", "--quiet"}, pkgs...)
}

// PHPFPMBinary returns the Remi php-fpm binary for a version such as "8.3".
func (p Platform) PHPFPMBinary(version string) (string, error) {
	if !supportedPHP[version] {
		return "", fmt.Errorf("unsupported PHP version %q", version)
	}
	return "/opt/remi/php" + strings.ReplaceAll(version, ".", "") + "/root/usr/sbin/php-fpm", nil
}

// ForMajor returns the platform for an EL major version.
func ForMajor(major int) (Platform, error) {
	switch major {
	case 9:
		return Platform{
			Major:          9,
			RepoPath:       "el9",
			RemiReleaseURL: "https://rpms.remirepo.net/enterprise/remi-release-9.rpm",
			MariaDBModule:  []string{"dnf", "-y", "module", "enable", "mariadb:10.11"},
			BasePackages: []string{
				"httpd", "mod_ssl", "mod_md", "mariadb-server", "fail2ban", "nftables",
				"xfsprogs", "policycoreutils-python-utils", "openssh-server",
			},
		}, nil
	case 10:
		return Platform{}, fmt.Errorf("%w: EL 10 support is planned for phase 3", ErrUnsupported)
	default:
		return Platform{}, fmt.Errorf("%w: EL %d", ErrUnsupported, major)
	}
}

// Detect reads /etc/os-release content and returns the matching platform.
func Detect(osRelease io.Reader) (Platform, error) {
	fields, err := parseOSRelease(osRelease)
	if err != nil {
		return Platform{}, err
	}
	if fields["ID"] != "almalinux" {
		return Platform{}, fmt.Errorf("%w: ID %q, want almalinux", ErrUnsupported, fields["ID"])
	}
	major, minor, err := parseVersion(fields["VERSION_ID"])
	if err != nil {
		return Platform{}, err
	}
	if major == 9 && minor < minMinorEL9 {
		return Platform{}, fmt.Errorf("%w: AlmaLinux %d.%d, want 9.%d or later", ErrUnsupported, major, minor, minMinorEL9)
	}
	return ForMajor(major)
}

func parseOSRelease(r io.Reader) (map[string]string, error) {
	fields := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		} else {
			value = strings.Trim(value, `'`)
		}
		fields[key] = value
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read os-release: %w", err)
	}
	return fields, nil
}

func parseVersion(v string) (major, minor int, err error) {
	majorStr, minorStr, _ := strings.Cut(v, ".")
	major, err = strconv.Atoi(majorStr)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: VERSION_ID %q", ErrUnsupported, v)
	}
	if minorStr != "" {
		minor, err = strconv.Atoi(minorStr)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: VERSION_ID %q", ErrUnsupported, v)
		}
	}
	return major, minor, nil
}
