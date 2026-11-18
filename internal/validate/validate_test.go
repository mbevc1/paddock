package validate

import (
	"errors"
	"strings"
	"testing"
)

// hostile inputs shared by the name validators.
var hostile = []string{
	"", "../v00001", "v00001/..", "v0000\x001", "v00001\n", "v00001\r\nx", "V00001",
	"v00001; rm -rf /", "$(id)", "`id`", "v00001|x", "v00001&", "v 00001", "v00001 ",
	strings.Repeat("a", 300),
}

func assertInvalid(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestVhostID(t *testing.T) {
	for id, want := range map[string]int{"v00001": 1, "v00012": 12, "v65535": 65535} {
		n, err := VhostID(id)
		if err != nil || n != want {
			t.Errorf("VhostID(%q) = %d, %v; want %d", id, n, err, want)
		}
	}
	for _, id := range append([]string{"v00000", "v65536", "v99999", "v0001", "v000001", "x00001"}, hostile...) {
		_, err := VhostID(id)
		assertInvalid(t, err)
	}
}

func TestVhostNumber(t *testing.T) {
	if id, err := VhostNumber(12); err != nil || id != "v00012" {
		t.Errorf("VhostNumber(12) = %q, %v", id, err)
	}
	for _, n := range []int{-1, 0, 65536} {
		_, err := VhostNumber(n)
		assertInvalid(t, err)
	}
}

func TestOwnerID(t *testing.T) {
	if err := OwnerID(3); err != nil {
		t.Error(err)
	}
	assertInvalid(t, OwnerID(0))
	assertInvalid(t, OwnerID(-3))
}

func TestDatabaseName(t *testing.T) {
	if name, err := DatabaseName("v00012", "wp"); err != nil || name != "v00012_wp" {
		t.Errorf("DatabaseName = %q, %v", name, err)
	}
	if name, err := DatabaseName("v00012", strings.Repeat("a", 20)); err != nil || len(name) != 27 {
		t.Errorf("20-character suffix: %q, %v", name, err)
	}
	for _, suffix := range append([]string{strings.Repeat("a", 21), "WP", "w_p", "w%p", "w-p"}, hostile...) {
		_, err := DatabaseName("v00012", suffix)
		assertInvalid(t, err)
	}
	_, err := DatabaseName("v0012", "wp")
	assertInvalid(t, err)
}

func TestDBUserName(t *testing.T) {
	if name, err := DBUserName("v00012", "ro"); err != nil || name != "v00012_ro" {
		t.Errorf("DBUserName = %q, %v", name, err)
	}
	for _, suffix := range append([]string{"abcdefghi", "RO", "r_o"}, hostile...) {
		_, err := DBUserName("v00012", suffix)
		assertInvalid(t, err)
	}
}

func TestPHPVersion(t *testing.T) {
	for _, v := range []string{"8.2", "8.3", "8.4"} {
		if err := PHPVersion(v); err != nil {
			t.Errorf("PHPVersion(%q): %v", v, err)
		}
	}
	for _, v := range append([]string{"7.4", "8", "8.3.0", "8.5", "83", " 8.3"}, hostile...) {
		assertInvalid(t, PHPVersion(v))
	}
}

func TestDomain(t *testing.T) {
	valid := map[string]string{
		"shop.example.com":               "shop.example.com",
		"Shop.Example.COM":               "shop.example.com",
		"a-b.example.co.uk":              "a-b.example.co.uk",
		"xn--bcher-kva.example":          "xn--bcher-kva.example",
		"123.example.com":                "123.example.com",
		strings.Repeat("a", 63) + ".com": strings.Repeat("a", 63) + ".com",
	}
	for in, want := range valid {
		got, err := Domain(in)
		if err != nil || got != want {
			t.Errorf("Domain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	invalidDomains := []string{
		"", "localhost", "*.example.com", "example.com.", ".example.com", "a..example.com",
		"-a.example.com", "a-.example.com", "ab--c.example.com", "under_score.example.com",
		"bücher.example", "192.168.1.1", "example.com/../etc", "example.com\n", "exa\x00mple.com",
		"example.com;id", "$(id).example.com", "exa mple.com",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat(strings.Repeat("a", 60)+".", 5) + "com",
	}
	for _, in := range invalidDomains {
		_, err := Domain(in)
		assertInvalid(t, err)
	}
}

func TestEmail(t *testing.T) {
	if got, err := Email("Ops+acme@Example.COM"); err != nil || got != "Ops+acme@example.com" {
		t.Errorf("Email = %q, %v", got, err)
	}
	for _, in := range []string{"", "a", "@example.com", "a@", "a@b@example.com", "a b@example.com",
		"a\n@example.com", "a\"@example.com", "a@localhost", strings.Repeat("a", 65) + "@example.com", "ä@example.com"} {
		_, err := Email(in)
		assertInvalid(t, err)
	}
}

func TestUsername(t *testing.T) {
	for _, ok := range []string{"admin", "ops.team", "a_b-c", "abc"} {
		if err := Username(ok); err != nil {
			t.Errorf("Username(%q): %v", ok, err)
		}
	}
	for _, bad := range append([]string{"ab", "1admin", "Admin", "ad min", strings.Repeat("a", 33), "admin\n"}, hostile...) {
		assertInvalid(t, Username(bad))
	}
}

func TestDisplayName(t *testing.T) {
	for _, ok := range []string{"Acme Ltd", "Müller & Söhne", "a"} {
		if err := DisplayName(ok); err != nil {
			t.Errorf("DisplayName(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", " Acme", "Acme ", "Ac\nme", "Ac\x00me", "\xff", strings.Repeat("a", 65)} {
		assertInvalid(t, DisplayName(bad))
	}
}
