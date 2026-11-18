// Package mariadb administers MariaDB as root over its unix_socket login. SQL goes to the
// mariadb client on stdin, never in argv, and every identifier passes through the quoting and
// grant-escaping helpers here.
package mariadb

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/mbevc1/paddock/internal/system"
)

// ErrInvalidName reports an identifier these helpers refuse to quote.
var ErrInvalidName = errors.New("invalid MariaDB name")

// MaxIdentifier is MariaDB's limit for database names, including escapes in grants.
const MaxIdentifier = 64

// Paddock creates only names of lowercase letters, digits, and underscores (§5).
var namePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// Ident quotes a database or user name as a backtick identifier.
func Ident(name string) (string, error) {
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return "`" + name + "`", nil
}

// GrantDB quotes a database name for GRANT and REVOKE, where _ and % are wildcards and must
// be escaped. It refuses names whose escaped form exceeds 64 characters (§9).
func GrantDB(name string) (string, error) {
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	escaped := strings.ReplaceAll(name, "_", `\_`)
	if len(escaped) > MaxIdentifier {
		return "", fmt.Errorf("%w: %q is longer than %d characters once escaped", ErrInvalidName, name, MaxIdentifier)
	}
	return "`" + escaped + "`", nil
}

// GrantVhostDatabases returns the grant pattern matching every database of a vhost, such as
// `v00012\_%`: the underscore is escaped and the trailing % stays a wildcard.
func GrantVhostDatabases(vhostID string) (string, error) {
	if !namePattern.MatchString(vhostID) || strings.Contains(vhostID, "_") {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, vhostID)
	}
	return "`" + vhostID + `\_%` + "`", nil
}

// Account quotes a local account as 'name'@'localhost'.
func Account(name string) (string, error) {
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return "'" + name + "'@'localhost'", nil
}

// String quotes a value as an SQL string literal.
func String(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\'':
			b.WriteString(`\'`)
		case '\\':
			b.WriteString(`\\`)
		case 0:
			b.WriteString(`\0`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case 0x1a:
			b.WriteString(`\Z`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

const (
	passwordLength   = 24
	passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
)

// NewPassword returns a random password of letters and digits.
func NewPassword() (string, error) {
	var b strings.Builder
	alphabetSize := big.NewInt(int64(len(passwordAlphabet)))
	for range passwordLength {
		i, err := rand.Int(rand.Reader, alphabetSize)
		if err != nil {
			return "", err
		}
		b.WriteByte(passwordAlphabet[i.Int64()])
	}
	return b.String(), nil
}

// Client runs SQL as MariaDB's root over the unix socket.
type Client struct {
	Run system.Runner
}

const clientBinary = "/usr/bin/mariadb"

var clientArgv = []string{clientBinary, "--protocol=socket", "--batch", "--skip-column-names"}

// Exec runs statements and returns the raw output.
func (c Client) Exec(ctx context.Context, sql string) ([]byte, error) {
	res, err := c.Run.Run(ctx, clientArgv, system.Opts{Stdin: strings.NewReader(sql)})
	if err != nil {
		return nil, err
	}
	return res.Stdout, nil
}

// Server error codes that ExecEach can treat as already done.
const (
	NoSuchGrant      = 1141
	NoSuchTableGrant = 1147
)

// ExecEach runs statements one at a time. A statement failing with one of the allowed server
// error codes counts as done; any other failure stops the run.
func (c Client) ExecEach(ctx context.Context, statements []string, allowed ...int) error {
	for _, st := range statements {
		_, err := c.Exec(ctx, st+";\n")
		if err == nil {
			continue
		}
		var exitErr *system.ExitError
		if !errors.As(err, &exitErr) || !hasErrorCode(exitErr.Stderr, allowed) {
			return err
		}
	}
	return nil
}

// hasErrorCode matches the client's "ERROR 1141 (42000) at line 1: ..." message.
func hasErrorCode(stderr string, codes []int) bool {
	for _, code := range codes {
		if strings.Contains(stderr, fmt.Sprintf("ERROR %d ", code)) {
			return true
		}
	}
	return false
}

// Query runs a statement and splits its batch output into rows of tab-separated fields.
func (c Client) Query(ctx context.Context, sql string) ([][]string, error) {
	out, err := c.Exec(ctx, sql)
	if err != nil {
		return nil, err
	}
	var rows [][]string
	for _, line := range bytes.Split(bytes.TrimRight(out, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		rows = append(rows, strings.Split(string(line), "\t"))
	}
	return rows, nil
}
