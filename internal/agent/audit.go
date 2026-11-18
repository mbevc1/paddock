package agent

import (
	"encoding/json"
	"strings"
)

const redacted = "[redacted]"

// sensitiveNames are redacted in every operation's audit arguments, at any depth.
var sensitiveNames = []string{"password", "secret", "token", "totp", "code", "private_key", "key_pem", "pem"}

func isSensitive(name string, extra []string) bool {
	lower := strings.ToLower(name)
	for _, s := range extra {
		if lower == strings.ToLower(s) {
			return true
		}
	}
	for _, s := range sensitiveNames {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// redactArgs returns the arguments as JSON with secret values replaced. Arguments that are
// not valid JSON are dropped entirely.
func redactArgs(raw json.RawMessage, extra []string) string {
	if len(raw) == 0 {
		return "{}"
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return `"[unparsable]"`
	}
	out, err := json.Marshal(redactValue(v, extra))
	if err != nil {
		return `"[unparsable]"`
	}
	return string(out)
}

func redactValue(v any, extra []string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if isSensitive(k, extra) {
				t[k] = redacted
			} else {
				t[k] = redactValue(val, extra)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactValue(t[i], extra)
		}
		return t
	default:
		return v
	}
}

type auditActor struct {
	CallerUID      uint32 `json:"caller_uid"`
	UserID         int64  `json:"user_id,omitempty"`
	Role           string `json:"role,omitempty"`
	OwnerID        int64  `json:"owner_id,omitempty"`
	ImpersonatedBy int64  `json:"impersonated_by,omitempty"`
}

func actorJSON(c *Call) string {
	a := auditActor{CallerUID: c.CallerUID}
	if c.Actor != nil {
		a.UserID, a.Role, a.OwnerID, a.ImpersonatedBy = c.Actor.UserID, string(c.Actor.Role), c.Actor.OwnerID, c.Actor.ImpersonatedBy
	}
	b, err := json.Marshal(a)
	if err != nil {
		return "{}"
	}
	return string(b)
}
