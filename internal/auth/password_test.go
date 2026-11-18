package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Errorf("hash = %q", h)
	}
	if ok, rehash, err := VerifyPassword("correct horse battery staple", h); !ok || rehash || err != nil {
		t.Errorf("verify = %v %v %v", ok, rehash, err)
	}
	if ok, _, _ := VerifyPassword("Correct horse battery staple", h); ok {
		t.Error("wrong password accepted")
	}
	old := encodeHash(argonParams{memory: 19 * 1024, time: 2, threads: 1}, []byte("0123456789abcdef"),
		derive("pw-with-old-params", []byte("0123456789abcdef"), argonParams{memory: 19 * 1024, time: 2, threads: 1}, 32))
	if ok, rehash, err := VerifyPassword("pw-with-old-params", old); !ok || !rehash || err != nil {
		t.Errorf("old parameters: ok %v rehash %v err %v", ok, rehash, err)
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$v=19$m=0,t=1,p=1$AAAA$AAAA", "$argon2id$v=18$m=1,t=1,p=1$AAAA$AAAA"} {
		if _, _, err := VerifyPassword("x", bad); !errors.Is(err, ErrMalformedHash) {
			t.Errorf("VerifyPassword(%q) err = %v", bad, err)
		}
	}
	VerifyDummy("anything")
}

func TestPasswordPolicy(t *testing.T) {
	if err := CheckPasswordPolicy("violet sparrow ledger", "alice"); err != nil {
		t.Error(err)
	}
	for _, tc := range []struct{ pw, user string }{
		{"short", "alice"},
		{"alicealice12", "AliceAlice12"},
		{"contortionist", "alice"},
		{"BusinessBabe", "alice"},
		{"\xff\xfe" + strings.Repeat("a", 12), "alice"},
		{strings.Repeat("a", 1025), "alice"},
	} {
		if err := CheckPasswordPolicy(tc.pw, tc.user); !errors.Is(err, ErrWeakPassword) {
			t.Errorf("CheckPasswordPolicy(%.20q) = %v", tc.pw, err)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes()
	if err != nil || len(codes) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount {
		t.Fatalf("NewRecoveryCodes = %d codes, %v", len(codes), err)
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Errorf("code %q", c)
		}
		seen[c] = true
		if HashRecoveryCode(strings.ToUpper(strings.ReplaceAll(c, "-", " "))) != hashes[i] {
			t.Errorf("code %q does not match its hash when typed differently", c)
		}
	}
}
