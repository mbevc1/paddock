package web

import "net/http"

const hstsValue = "max-age=31536000"

// securityHeaders sets the §11.3 headers on every response, and HSTS once the panel serves a
// trusted certificate.
func securityHeaders(next http.Handler, trusted func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Content-Type-Options", "nosniff")
		if trusted != nil && trusted() {
			h.Set("Strict-Transport-Security", hstsValue)
		}
		next.ServeHTTP(w, r)
	})
}

// redirectHandler sends plain-HTTP visitors to the panel. The target host is the configured
// panel hostname, never the request's Host header, so it cannot become an open redirect.
func redirectHandler(origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := origin + r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently) // #nosec G710 -- the host is the configured origin; only the path comes from the request.
	})
}
