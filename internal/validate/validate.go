// Package validate checks every name, path, domain, and version before it reaches a
// template, a command, or SQL. Validators return canonical values; callers use those, not
// the raw input.
package validate

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid argument")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

const (
	// MaxVhostNumber is the largest vhost number; the backend address has 16 bits for it.
	MaxVhostNumber = 65535
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
