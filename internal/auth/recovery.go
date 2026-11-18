package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	// RecoveryCodeCount is how many recovery codes an owner gets (§11.2).
	RecoveryCodeCount = 10
	recoveryAlphabet  = "abcdefghjkmnpqrstuvwxyz23456789"
	recoveryHalf      = 5
)

// NewRecoveryCodes returns fresh single-use codes such as "k7m2q-x9tbd" and their hashes for
// storage.
func NewRecoveryCodes() (codes, hashes []string, err error) {
	for range RecoveryCodeCount {
		buf := make([]byte, 2*recoveryHalf)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		var b strings.Builder
		for i, c := range buf {
			if i == recoveryHalf {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryAlphabet[int(c)%len(recoveryAlphabet)])
		}
		code := b.String()
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// HashRecoveryCode normalizes a code as typed (case, spaces, dashes) and hashes it. Codes carry
// about 49 bits of randomness and are single-use, so a fast hash suffices.
func HashRecoveryCode(code string) string {
	norm := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(code))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}
