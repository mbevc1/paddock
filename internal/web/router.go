package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Route is one registered handler. Every route names its permission; the router refuses to
// build otherwise.
type Route struct {
	Method  string
	Pattern string
	Perm    Permission
	// StepUp requires a password or TOTP check within the last 5 minutes (§11.3).
	StepUp  bool
	Handler http.HandlerFunc
}

// Router collects routes and wraps each in its permission check.
type Router struct {
	routes []Route
	// guard wraps a route with identification, permission, CSRF, and step-up checks.
	guard func(Route) http.Handler
}

// Handle registers a route.
func (rt *Router) Handle(r Route) { rt.routes = append(rt.routes, r) }

// ErrRouteWithoutPermission reports a route registered without a known permission.
var ErrRouteWithoutPermission = errors.New("route without permission")

// Build returns the handler for all routes. It fails when any route lacks a permission or
// handler, or when two routes share a method and pattern.
func (rt *Router) Build() (http.Handler, error) {
	mux := http.NewServeMux()
	seen := map[string]bool{}
	var errs []error
	for _, r := range rt.routes {
		key := r.Method + " " + r.Pattern
		switch {
		case !knownPermission(r.Perm):
			errs = append(errs, fmt.Errorf("%w: %s (%q)", ErrRouteWithoutPermission, key, r.Perm))
			continue
		case r.Handler == nil:
			errs = append(errs, fmt.Errorf("route %s has no handler", key))
			continue
		case r.Method == "" || !strings.HasPrefix(r.Pattern, "/"):
			errs = append(errs, fmt.Errorf("route %q needs a method and an absolute pattern", key))
			continue
		case seen[key]:
			errs = append(errs, fmt.Errorf("route %s registered twice", key))
			continue
		}
		seen[key] = true
		h := http.Handler(r.Handler)
		if rt.guard != nil {
			h = rt.guard(r)
		}
		mux.Handle(key, h)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return mux, nil
}
