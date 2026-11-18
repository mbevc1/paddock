package auth

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (§11.2). They are stored with each hash, so a change here takes effect
// as users log in.
const (
	argonMemoryKiB  = 64 * 1024
	argonIterations = 3
	argonThreads    = 1
	argonSaltLen    = 16
	argonKeyLen     = 32
	// MinPasswordLength is the shortest password accepted.
	MinPasswordLength = 12
	maxPasswordBytes  = 1024
)

var b64 = base64.RawStdEncoding

// ErrMalformedHash reports a stored hash that is not an Argon2id PHC string.
var ErrMalformedHash = errors.New("malformed password hash")

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

var currentParams = argonParams{memory: argonMemoryKiB, time: argonIterations, threads: argonThreads}

// HashPassword returns an Argon2id hash in PHC format.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return encodeHash(currentParams, salt, derive(password, salt, currentParams, argonKeyLen)), nil
}

func derive(password string, salt []byte, p argonParams, keyLen uint32) []byte {
	return argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, keyLen)
}

func encodeHash(p argonParams, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.time, p.threads,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

func decodeHash(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argonParams{}, nil, nil, ErrMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return argonParams{}, nil, nil, ErrMalformedHash
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil ||
		p.memory == 0 || p.time == 0 || p.threads == 0 {
		return argonParams{}, nil, nil, ErrMalformedHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return argonParams{}, nil, nil, ErrMalformedHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return argonParams{}, nil, nil, ErrMalformedHash
	}
	return p, salt, key, nil
}

// VerifyPassword checks a password against a stored hash in constant time. rehash reports a
// hash made with other parameters, which the caller should replace after a successful login.
func VerifyPassword(password, encoded string) (ok, rehash bool, err error) {
	p, salt, key, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	got := derive(password, salt, p, uint32(len(key))) // #nosec G115 -- key length comes from our own hashes.
	ok = subtle.ConstantTimeCompare(got, key) == 1
	return ok, ok && (p != currentParams || len(key) != argonKeyLen || len(salt) != argonSaltLen), nil
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// VerifyDummy spends the time of one password check against a throwaway hash, so a login for
// an unknown username takes as long as one for a known user.
func VerifyDummy(password string) {
	dummyOnce.Do(func() {
		h, err := HashPassword("paddock dummy password")
		if err == nil {
			dummyHash = h
		}
	})
	_, _, _ = VerifyPassword(password, dummyHash)
}

//go:embed data/common-passwords.txt
var commonPasswordData []byte

var (
	commonOnce      sync.Once
	commonPasswords map[string]struct{}
)

func isCommon(password string) bool {
	commonOnce.Do(func() {
		commonPasswords = map[string]struct{}{}
		sc := bufio.NewScanner(bytes.NewReader(commonPasswordData))
		for sc.Scan() {
			commonPasswords[sc.Text()] = struct{}{}
		}
	})
	_, found := commonPasswords[strings.ToLower(password)]
	return found
}

// ErrWeakPassword reports a password the policy refuses; the message says why.
var ErrWeakPassword = errors.New("weak password")

// CheckPasswordPolicy enforces §11.2: at least 12 characters, not a common password, and not
// the username.
func CheckPasswordPolicy(password, username string) error {
	switch {
	case !utf8.ValidString(password):
		return fmt.Errorf("%w: password must be valid UTF-8", ErrWeakPassword)
	case utf8.RuneCountInString(password) < MinPasswordLength:
		return fmt.Errorf("%w: password must have at least %d characters", ErrWeakPassword, MinPasswordLength)
	case len(password) > maxPasswordBytes:
		return fmt.Errorf("%w: password must be at most %d bytes", ErrWeakPassword, maxPasswordBytes)
	case strings.EqualFold(password, username):
		return fmt.Errorf("%w: password must differ from the username", ErrWeakPassword)
	case isCommon(password):
		return fmt.Errorf("%w: password is too common", ErrWeakPassword)
	}
	return nil
}

const randomPasswordLength = 20

// RandomPassword returns a 20-character password of letters and digits without look-alikes,
// for accounts whose first password is shown once.
func RandomPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, randomPasswordLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}
