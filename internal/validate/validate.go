// Package validate checks every name, path, domain, and version before it reaches a
// template, a command, or SQL. Validators return canonical values; callers use those, not
// the raw input.
package validate

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid argument")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

const (
	// MaxVhostNumber is the largest vhost number; the backend address has 16 bits for it.
	MaxVhostNumber = 65535
	// VhostUIDBase plus the vhost number is the vhost user's UID and GID. It lies above
	// SUB_UID_MAX and SUB_GID_MAX (600100000 by default), so useradd never hands out a
	// subordinate ID range that could map vhost IDs in a user namespace.
	VhostUIDBase = 1_000_000_000
	// MaxDatabaseName is the longest database name Paddock creates.
	MaxDatabaseName = 32
)

var (
	vhostIDPattern      = regexp.MustCompile(`^v[0-9]{5}$`)
	dbSuffixPattern     = regexp.MustCompile(`^[a-z0-9]{1,20}$`)
	dbUserSuffixPattern = regexp.MustCompile(`^[a-z0-9]{1,8}$`)
)

// VhostID checks an ID such as "v00012" and returns its vhost number.
func VhostID(id string) (int, error) {
	if !vhostIDPattern.MatchString(id) {
		return 0, invalid("vhost ID %q must match v plus five digits", id)
	}
	n, _ := strconv.Atoi(id[1:])
	if n < 1 || n > MaxVhostNumber {
		return 0, invalid("vhost ID %q out of range", id)
	}
	return n, nil
}

// VhostNumber checks a vhost number and returns its ID.
func VhostNumber(n int) (string, error) {
	if n < 1 || n > MaxVhostNumber {
		return "", invalid("vhost number %d out of range 1 to %d", n, MaxVhostNumber)
	}
	return fmt.Sprintf("v%05d", n), nil
}

// OwnerID checks an owner ID. Owner IDs appear in slice names, so they must be positive.
func OwnerID(id int64) error {
	if id < 1 {
		return invalid("owner ID %d must be positive", id)
	}
	return nil
}

// DatabaseName checks a database suffix and returns "<vhost id>_<suffix>".
func DatabaseName(vhostID, suffix string) (string, error) {
	if _, err := VhostID(vhostID); err != nil {
		return "", err
	}
	if !dbSuffixPattern.MatchString(suffix) {
		return "", invalid("database suffix %q must be 1 to 20 lowercase letters or digits", suffix)
	}
	name := vhostID + "_" + suffix
	if len(name) > MaxDatabaseName {
		return "", invalid("database name %q longer than %d characters", name, MaxDatabaseName)
	}
	return name, nil
}

// DBUserName checks an extra DB user suffix and returns "<vhost id>_<suffix>".
func DBUserName(vhostID, suffix string) (string, error) {
	if _, err := VhostID(vhostID); err != nil {
		return "", err
	}
	if !dbUserSuffixPattern.MatchString(suffix) {
		return "", invalid("DB user suffix %q must be 1 to 8 lowercase letters or digits", suffix)
	}
	return vhostID + "_" + suffix, nil
}

var phpVersions = map[string]bool{"8.2": true, "8.3": true, "8.4": true}

// PHPVersion checks a PHP version such as "8.3".
func PHPVersion(v string) error {
	if !phpVersions[v] {
		return invalid("PHP version %q must be one of 8.2, 8.3, 8.4", v)
	}
	return nil
}

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,31}$`)

// Username checks a panel username: 3 to 32 characters, lowercase, starting with a letter.
func Username(name string) error {
	if !usernamePattern.MatchString(name) {
		return invalid("username %q must be 3 to 32 lowercase letters, digits, or ._- and start with a letter", name)
	}
	return nil
}

const maxDisplayName = 64

// DisplayName checks a human-readable name such as an owner's: 1 to 64 characters of valid
// UTF-8 without control characters or surrounding spaces.
func DisplayName(name string) error {
	if name == "" || utf8.RuneCountInString(name) > maxDisplayName || !utf8.ValidString(name) {
		return invalid("name must be 1 to %d characters of UTF-8", maxDisplayName)
	}
	if strings.TrimSpace(name) != name {
		return invalid("name must not start or end with spaces")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return invalid("name must not contain control characters")
		}
	}
	return nil
}

const (
	minAccessPassword = 12
	maxAccessPassword = 128
)

// AccessPassword checks an SFTP or shell password: 12 to 128 printable ASCII characters
// without ":", which chpasswd uses as its separator. Errors never quote the password.
func AccessPassword(pw string) error {
	if len(pw) < minAccessPassword || len(pw) > maxAccessPassword {
		return invalid("password must be %d to %d characters", minAccessPassword, maxAccessPassword)
	}
	for i := 0; i < len(pw); i++ {
		if pw[i] < 0x20 || pw[i] > 0x7e || pw[i] == ':' {
			return invalid("password must be printable ASCII without ':'")
		}
	}
	return nil
}
