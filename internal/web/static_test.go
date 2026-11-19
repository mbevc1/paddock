package web

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The panel embeds a copy of the project icon, since go:embed cannot reach docs/.
func TestLogoIsServedAndMatchesTheProjectIcon(t *testing.T) {
	h := newHarness(t)
	rec := h.browser().do("GET", "/static/logo.svg", nil)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "image/svg+xml") {
		t.Fatalf("GET /static/logo.svg = %d, %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	want, err := os.ReadFile("../../docs/assets/logo/paddock-icon-small.svg")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Error("internal/web/static/logo.svg differs from docs/assets/logo/paddock-icon-small.svg")
	}
}
