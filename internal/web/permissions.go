// Package web is the panel: an HTTPS server where every route declares a permission, with
// sessions, CSRF protection, server-rendered pages, and notifications. It changes the host
// only through the agent.
package web

import "github.com/mbevc1/paddock/internal/api"

// Permission names what a route lets a user do (§11.1).
type Permission string

// Permissions. PermPublic needs no session; PermPending is the second login step; PermSelf is
// any signed-in user acting on their own account.
const (
	PermPublic      Permission = "public"
	PermPending     Permission = "login.pending"
	PermSelf        Permission = "self"
	PermVhosts      Permission = "vhost.manage"
	PermDatabases   Permission = "db.manage"
	PermAccess      Permission = "access.manage"
	PermCerts       Permission = "cert.manage"
	PermOwners      Permission = "owner.manage"
	PermPHP         Permission = "php.manage"
	PermServer      Permission = "server.view"
	PermAudit       Permission = "audit.view"
	PermImpersonate Permission = "impersonate"
)

var ownerPermissions = []Permission{PermSelf, PermVhosts, PermDatabases, PermAccess, PermCerts}

var grants = map[api.Role]map[Permission]bool{
	api.RoleOwner: set(ownerPermissions...),
	// Admins manage owners' resources by impersonating them, so the agent sees the owner.
	api.RoleAdmin: set(append(ownerPermissions, PermOwners, PermPHP, PermServer, PermAudit, PermImpersonate)...),
}

func set(ps ...Permission) map[Permission]bool {
	m := map[Permission]bool{}
	for _, p := range ps {
		m[p] = true
	}
	return m
}

// knownPermission reports whether p is one the router accepts.
func knownPermission(p Permission) bool {
	return p == PermPublic || p == PermPending || grants[api.RoleAdmin][p]
}
