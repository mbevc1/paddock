package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

func TestRouterRefusesRoutesWithoutPermission(t *testing.T) {
	for name, r := range map[string]Route{
		"no permission":      {Method: "GET", Pattern: "/x", Handler: ok},
		"unknown permission": {Method: "GET", Pattern: "/x", Perm: "anything", Handler: ok},
		"no handler":         {Method: "GET", Pattern: "/x", Perm: PermSelf},
		"relative pattern":   {Method: "GET", Pattern: "x", Perm: PermSelf, Handler: ok},
	} {
		t.Run(name, func(t *testing.T) {
			var rt Router
			rt.Handle(Route{Method: "GET", Pattern: "/fine", Perm: PermPublic, Handler: ok})
			rt.Handle(r)
			if _, err := rt.Build(); err == nil {
				t.Fatal("Build accepted the route")
			} else if name != "no handler" && name != "relative pattern" && !errors.Is(err, ErrRouteWithoutPermission) {
				t.Errorf("err = %v", err)
			}
		})
	}
	var rt Router
	rt.Handle(Route{Method: "GET", Pattern: "/x", Perm: PermPublic, Handler: ok})
	rt.Handle(Route{Method: "GET", Pattern: "/x", Perm: PermSelf, Handler: ok})
	if _, err := rt.Build(); err == nil {
		t.Error("duplicate route accepted")
	}
}

func TestSecurityHeaders(t *testing.T) {
	trusted := false
	h := securityHeaders(http.HandlerFunc(ok), func() bool { return trusted })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/", nil))
	want := map[string]string{
		"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "same-origin",
		"X-Content-Type-Options":  "nosniff",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent before the certificate is trusted")
	}
	trusted = true
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/", nil))
	if rec.Header().Get("Strict-Transport-Security") != hstsValue {
		t.Error("HSTS missing once trusted")
	}
}

func TestRedirectHandler(t *testing.T) {
	h := redirectHandler("https://panel.example.com:8443")
	req := httptest.NewRequestWithContext(context.Background(), "GET", "http://evil.example.net:8080/vhosts?x=1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "https://panel.example.com:8443/vhosts?x=1" {
		t.Errorf("redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
