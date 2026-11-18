package validate

import (
	"strings"
)

const (
	maxDomainLength = 253
	maxLabelLength  = 63
)

// Domain checks a host name and returns it in lowercase ASCII. Wildcards, trailing dots,
// IP addresses, and single-label names are rejected. Internationalized names must arrive
// as A-labels ("xn--..."): Unicode input is rejected until IDNA conversion is available.
func Domain(name string) (string, error) {
	if name == "" {
		return "", invalid("domain name is empty")
	}
	if len(name) > maxDomainLength {
		return "", invalid("domain name longer than %d characters", maxDomainLength)
	}
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return "", invalid("domain name %q must be ASCII; give internationalized names as xn-- labels", name)
		}
	}
	lower := strings.ToLower(name)
	labels := strings.Split(lower, ".")
	if len(labels) < 2 {
		return "", invalid("domain name %q needs at least two labels", name)
	}
	for _, label := range labels {
		if err := domainLabel(label); err != nil {
			return "", err
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", invalid("domain name %q ends in a numeric label", name)
	}
	return lower, nil
}

func domainLabel(label string) error {
	if label == "" {
		return invalid("domain name has an empty label")
	}
	if len(label) > maxLabelLength {
		return invalid("domain label %q longer than %d characters", label, maxLabelLength)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return invalid("domain label %q contains %q", label, c)
		}
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return invalid("domain label %q starts or ends with a hyphen", label)
	}
	// RFC 5891 reserves "??--" for encodings; only punycode's "xn--" is valid.
	if len(label) >= 4 && label[2:4] == "--" && label[:2] != "xn" {
		return invalid("domain label %q uses a reserved prefix", label)
	}
	return nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

const maxEmailLocal = 64

// Email checks an address such as an ACME contact and returns it with the domain lowercased.
// The local part is limited to letters, digits, and ._%+- so it is safe in config files.
func Email(addr string) (string, error) {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || len(local) > maxEmailLocal {
		return "", invalid("email address %q is malformed", addr)
	}
	for i := 0; i < len(local); i++ {
		c := local[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._%+-", c) >= 0
		if !ok {
			return "", invalid("email address %q has an unsupported character", addr)
		}
	}
	d, err := Domain(domain)
	if err != nil {
		return "", err
	}
	return local + "@" + d, nil
}
