package validate

import (
	"crypto/rsa"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	minRSABits       = 3072
	maxKeyLineLength = 16 * 1024
	maxCommentLength = 100
)

var allowedKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:  true,
	ssh.KeyAlgoECDSA256: true,
	ssh.KeyAlgoECDSA384: true,
	ssh.KeyAlgoECDSA521: true,
	ssh.KeyAlgoRSA:      true,
}

// SSHPublicKey checks one authorized_keys line and returns it re-encoded as
// "<type> <base64>[ <comment>]". Options, certificates, and RSA keys under 3072 bits are
// rejected.
func SSHPublicKey(line string) (string, error) {
	if len(line) > maxKeyLineLength {
		return "", invalid("SSH key longer than %d bytes", maxKeyLineLength)
	}
	if strings.ContainsAny(line, "\x00\r\n") {
		return "", invalid("SSH key must be a single line")
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", invalid("SSH key does not parse")
	}
	if len(options) > 0 {
		return "", invalid("SSH key must not carry options")
	}
	if len(rest) > 0 {
		return "", invalid("SSH key must be a single line")
	}
	if !allowedKeyTypes[key.Type()] {
		return "", invalid("SSH key type %q not allowed", key.Type())
	}
	if key.Type() == ssh.KeyAlgoRSA {
		ck, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return "", invalid("SSH RSA key unreadable")
		}
		pub, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < minRSABits {
			return "", invalid("SSH RSA key must have at least %d bits", minRSABits)
		}
	}
	if err := keyComment(comment); err != nil {
		return "", err
	}
	out := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n")
	if comment != "" {
		out += " " + comment
	}
	return out, nil
}

func keyComment(c string) error {
	if len(c) > maxCommentLength {
		return invalid("SSH key comment longer than %d characters", maxCommentLength)
	}
	for i := 0; i < len(c); i++ {
		if c[i] < 0x20 || c[i] > 0x7e {
			return invalid("SSH key comment must be printable ASCII")
		}
	}
	return nil
}
