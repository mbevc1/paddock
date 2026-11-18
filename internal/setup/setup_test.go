package setup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mbevc1/paddock/internal/state"
	"github.com/mbevc1/paddock/internal/web/store"
)

func newDeps(t *testing.T) (*Deps, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	return &Deps{
		Root:    t.TempDir(),
		Out:     out,
		WebUser: func() (int, int, error) { return os.Getuid(), os.Getgid(), nil },
		Chown:   func(string, int, int) error { return nil },
	}, out
}

func TestFirstRunAndRerun(t *testing.T) {
	ctx := context.Background()
	d, out := newDeps(t)
	if err := Run(ctx, Options{}, d); err != nil {
		t.Fatalf("first run: %v", err)
	}
	for _, want := range []string{"username:  admin", "password:  ", "TOTP URI:  otpauth://totp/Paddock:admin?"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("first run output lacks %q:\n%s", want, out)
		}
	}
	if entries, _ := os.ReadDir(d.path(WebDir)); len(entries) == 0 {
		t.Fatal("web.db missing")
	}
	for _, name := range []string{"panel.crt", "panel.key"} {
		if _, err := os.Stat(filepath.Join(d.path(WebDir), name)); err == nil {
			t.Errorf("setup created %s; paddock web owns the panel certificate", name)
		}
	}

	ws, err := store.Open(ctx, filepath.Join(d.path(WebDir), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := ws.GetUserByName(ctx, "admin")
	_ = ws.Close()
	if err != nil || admin.Role != store.RoleAdmin {
		t.Fatalf("web admin = %+v, %v", admin, err)
	}
	st, err := state.Open(ctx, filepath.Join(d.path(StateDir), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.GetAdmin(ctx, admin.ID)
	_ = st.Close()
	if err != nil || a.Username != "admin" || len(a.TOTPSecret) != 20 {
		t.Errorf("state admin = %+v, %v", a, err)
	}

	out.Reset()
	if err := Run(ctx, Options{AdminUser: "other"}, d); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if s := out.String(); strings.Contains(s, "password:") || strings.Contains(s, "otpauth://") || !strings.Contains(s, "no secrets printed") {
		t.Errorf("rerun output:\n%s", s)
	}
}

func TestRejectsBadAdminName(t *testing.T) {
	d, _ := newDeps(t)
	if err := Run(context.Background(), Options{AdminUser: "Bad Name"}, d); err == nil || !strings.Contains(err.Error(), "--admin") {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(d.path(StateDir)); err == nil {
		t.Error("created state before validating the admin name")
	}
}

func TestWebFilesOwnedByWebUser(t *testing.T) {
	d, _ := newDeps(t)
	var owned []string
	d.Chown = func(p string, _, _ int) error {
		owned = append(owned, filepath.Base(p))
		return nil
	}
	if err := Run(context.Background(), Options{}, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"web", "web.db"} {
		found := false
		for _, o := range owned {
			found = found || o == want
		}
		if !found {
			t.Errorf("%s not given to the web user; chowned %v", want, owned)
		}
	}
}
