package auth

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B test vectors for SHA-1, truncated to six digits.
func TestTOTPCodeRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	} {
		if got := TOTPCode(secret, TOTPStep(time.Unix(unix, 0))); got != want {
			t.Errorf("code at %d = %s, want %s", unix, got, want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_015, 0)
	step := TOTPStep(now)
	for _, offset := range []int64{-1, 0, 1} {
		got, ok := VerifyTOTP(secret, TOTPCode(secret, step+offset), now)
		if !ok || got != step+offset {
			t.Errorf("offset %d: step %d, ok %v", offset, got, ok)
		}
	}
	for _, code := range []string{TOTPCode(secret, step-2), TOTPCode(secret, step+2), "", "12345", "1234567", "abcdef"} {
		if _, ok := VerifyTOTP(secret, code, now); ok {
			t.Errorf("code %q accepted", code)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("Paddock", "admin", []byte("12345678901234567890"))
	for _, want := range []string{"otpauth://totp/Paddock:admin?", "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer=Paddock", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI %q lacks %q", uri, want)
		}
	}
}
