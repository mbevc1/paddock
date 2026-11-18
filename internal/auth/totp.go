// Package auth implements the panel's credentials: TOTP (RFC 6238) here, password hashing
// and external identity providers alongside.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP with SHA-1 is what authenticator apps expect.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	// TOTPPeriod is the length of one time step.
	TOTPPeriod = 30 * time.Second
	// TOTPDigits is the code length.
	TOTPDigits = 6
	// totpSkew is how many steps either side of now a code may come from.
	totpSkew = 1
	// totpSecretBytes is the secret length recommended by RFC 4226 for HMAC-SHA-1.
	totpSecretBytes = 20
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random secret.
func NewTOTPSecret() ([]byte, error) {
	s := make([]byte, totpSecretBytes)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// TOTPStep returns the time step that contains t.
func TOTPStep(t time.Time) int64 { return t.Unix() / int64(TOTPPeriod/time.Second) }

// TOTPCode returns the code for a time step.
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- steps are positive.
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", TOTPDigits, value%1_000_000)
}

// VerifyTOTP checks code against the steps around now and returns the matching step. The
// caller must record the step and reject codes from that step or earlier, so each code
// works once.
func VerifyTOTP(secret []byte, code string, now time.Time) (step int64, ok bool) {
	if len(code) != TOTPDigits {
		return 0, false
	}
	current := TOTPStep(now)
	for s := current - totpSkew; s <= current+totpSkew; s++ {
		if subtle.ConstantTimeCompare([]byte(TOTPCode(secret, s)), []byte(code)) == 1 {
			step, ok = s, true
		}
	}
	return step, ok
}

// TOTPURI returns the otpauth:// URI that authenticator apps import.
func TOTPURI(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", base32NoPad.EncodeToString(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(TOTPDigits))
	q.Set("period", fmt.Sprint(int(TOTPPeriod/time.Second)))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + q.Encode()
}
