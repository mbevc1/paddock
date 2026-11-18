package mariadb

import (
	"fmt"
	"strings"
)

// Privileges are the grant levels of an extra DB user.
type Privileges string

// Grant levels.
const (
	PrivilegesAll  Privileges = "all"
	PrivilegesRead Privileges = "read"
)

func (p Privileges) sql() (string, error) {
	switch p {
	case PrivilegesAll:
		return "ALL PRIVILEGES", nil
	case PrivilegesRead:
		return "SELECT, SHOW VIEW", nil
	}
	return "", fmt.Errorf("%w: privileges %q", ErrInvalidName, p)
}

// writePrivileges are revoked when an owner reaches their disk limit (§9).
const writePrivileges = "INSERT, UPDATE, CREATE"

func stmts(lines ...string) string { return strings.Join(lines, ";\n") + ";\n" }

// CreatePrimaryUser creates a vhost's primary user: unix_socket for the vhost's processes, or
// a password for tunneled clients (§9).
func CreatePrimaryUser(vhostID, password string, maxConnections int) (string, error) {
	acct, err := Account(vhostID)
	if err != nil {
		return "", err
	}
	return stmts(fmt.Sprintf("CREATE USER %s IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD(%s) WITH MAX_USER_CONNECTIONS %d",
		acct, String(password), maxConnections)), nil
}

// SetPrimaryPassword replaces the primary user's password and keeps unix_socket.
func SetPrimaryPassword(vhostID, password string) (string, error) {
	acct, err := Account(vhostID)
	if err != nil {
		return "", err
	}
	return stmts(fmt.Sprintf("ALTER USER %s IDENTIFIED VIA unix_socket OR mysql_native_password USING PASSWORD(%s)",
		acct, String(password))), nil
}

// CreateDatabase creates a database in utf8mb4 and grants it to the vhost's primary user.
func CreateDatabase(name, primary string) (string, error) {
	db, err := Ident(name)
	if err != nil {
		return "", err
	}
	grantDB, err := GrantDB(name)
	if err != nil {
		return "", err
	}
	acct, err := Account(primary)
	if err != nil {
		return "", err
	}
	return stmts(
		fmt.Sprintf("CREATE DATABASE %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", db),
		fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO %s", grantDB, acct),
	), nil
}

// DropDatabase drops a database, ignoring one already gone.
func DropDatabase(name string) (string, error) {
	db, err := Ident(name)
	if err != nil {
		return "", err
	}
	return stmts("DROP DATABASE IF EXISTS " + db), nil
}

// RevokeDatabase takes the primary user's grant on a database, which outlives a dropped
// database otherwise. Run it with ExecEach, allowing NoSuchGrant.
func RevokeDatabase(name, primary string) ([]string, error) {
	grantDB, err := GrantDB(name)
	if err != nil {
		return nil, err
	}
	acct, err := Account(primary)
	if err != nil {
		return nil, err
	}
	return []string{fmt.Sprintf("REVOKE ALL PRIVILEGES ON %s.* FROM %s", grantDB, acct)}, nil
}

// CreateUser creates an extra DB user with privileges on all of a vhost's databases.
func CreateUser(name, vhostID, password string, p Privileges, maxConnections int) (string, error) {
	acct, err := Account(name)
	if err != nil {
		return "", err
	}
	pattern, err := GrantVhostDatabases(vhostID)
	if err != nil {
		return "", err
	}
	privs, err := p.sql()
	if err != nil {
		return "", err
	}
	return stmts(
		fmt.Sprintf("CREATE USER %s IDENTIFIED BY %s WITH MAX_USER_CONNECTIONS %d", acct, String(password), maxConnections),
		fmt.Sprintf("GRANT %s ON %s.* TO %s", privs, pattern, acct),
	), nil
}

// SetPassword replaces an extra user's password.
func SetPassword(name, password string) (string, error) {
	acct, err := Account(name)
	if err != nil {
		return "", err
	}
	return stmts(fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s", acct, String(password))), nil
}

// DropUsers drops accounts, ignoring ones already gone.
func DropUsers(names ...string) (string, error) {
	lines := make([]string, 0, len(names))
	for _, n := range names {
		acct, err := Account(n)
		if err != nil {
			return "", err
		}
		lines = append(lines, "DROP USER IF EXISTS "+acct)
	}
	return stmts(lines...), nil
}

// DropDatabases drops databases, ignoring ones already gone.
func DropDatabases(names ...string) (string, error) {
	lines := make([]string, 0, len(names))
	for _, n := range names {
		db, err := Ident(n)
		if err != nil {
			return "", err
		}
		lines = append(lines, "DROP DATABASE IF EXISTS "+db)
	}
	return stmts(lines...), nil
}

// DatabaseSizes returns the query for the bytes used by each database of a vhost; rows are
// name and size.
func DatabaseSizes(vhostID string) (string, error) {
	if !namePattern.MatchString(vhostID) || strings.Contains(vhostID, "_") {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, vhostID)
	}
	return stmts("SELECT table_schema, COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables" +
		" WHERE table_schema LIKE " + String(vhostID+`\_%`) + " GROUP BY table_schema"), nil
}

// RevokeWrites takes INSERT, UPDATE, and CREATE on a vhost's databases from its primary user
// and from writeUsers, its extra users with full privileges, while the owner is over their disk
// limit; SELECT and DELETE stay so they can clean up (§9). Run the statements with ExecEach,
// allowing NoSuchGrant and NoSuchTableGrant, so a repeat is harmless.
func RevokeWrites(vhostID string, databases, writeUsers []string) ([]string, error) {
	return writeGrants("REVOKE", "FROM", vhostID, databases, writeUsers)
}

// RestoreWrites gives back what RevokeWrites took.
func RestoreWrites(vhostID string, databases, writeUsers []string) ([]string, error) {
	return writeGrants("GRANT", "TO", vhostID, databases, writeUsers)
}

func writeGrants(verb, prep, vhostID string, databases, writeUsers []string) ([]string, error) {
	primary, err := Account(vhostID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, db := range databases {
		grantDB, err := GrantDB(db)
		if err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s %s ON %s.* %s %s", verb, writePrivileges, grantDB, prep, primary))
	}
	if len(writeUsers) > 0 {
		pattern, err := GrantVhostDatabases(vhostID)
		if err != nil {
			return nil, err
		}
		for _, u := range writeUsers {
			acct, err := Account(u)
			if err != nil {
				return nil, err
			}
			out = append(out, fmt.Sprintf("%s %s ON %s.* %s %s", verb, writePrivileges, pattern, prep, acct))
		}
	}
	return out, nil
}
