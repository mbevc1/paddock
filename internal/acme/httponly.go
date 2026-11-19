package acme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"sync"
)

// maxACMEJSON bounds the ACME replies read into memory; authorizations are a few kilobytes.
const maxACMEJSON = 1 << 20

// httpOnly removes every challenge but HTTP-01 from the CA's authorization replies. autocert
// tries TLS-ALPN-01 first, which fails behind the front Apache and costs one of Let's Encrypt's
// failed validations per attempt. It also keeps the CA's reason for a failed HTTP-01 challenge,
// which autocert discards.
type httpOnly struct {
	base   http.RoundTripper
	report *caReport
}

// caReport holds the latest reason the CA gave for failing an HTTP-01 challenge.
type caReport struct {
	mu     sync.Mutex
	reason string
}

func (r *caReport) set(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reason = reason
}

// take returns the reason and clears it.
func (r *caReport) take() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	reason := r.reason
	r.reason = ""
	return reason
}

func (t httpOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return resp, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxACMEJSON+1))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > maxACMEJSON {
		return nil, fmt.Errorf("ACME reply from %s exceeds %d bytes", r.URL.Redacted(), maxACMEJSON)
	}
	if reason := http01Failure(body); reason != "" && t.report != nil {
		t.report.set(reason)
	}
	body = keepHTTP01(body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return resp, nil
}

// http01Failure returns "type: detail" from the error of a failed HTTP-01 challenge in an
// authorization or challenge reply, or "" when there is none.
func http01Failure(body []byte) string {
	type problem struct{ Type, Detail string }
	type challenge struct {
		Type  string
		Error *problem
	}
	var reply struct {
		challenge
		Challenges []challenge
	}
	if json.Unmarshal(body, &reply) != nil {
		return ""
	}
	for _, c := range append([]challenge{reply.challenge}, reply.Challenges...) {
		if c.Type == "http-01" && c.Error != nil {
			return c.Error.Type + ": " + c.Error.Detail
		}
	}
	return ""
}

// keepHTTP01 returns body with its "challenges" list cut to HTTP-01, or body unchanged when it
// has no such list.
func keepHTTP01(body []byte) []byte {
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return body
	}
	var challenges []json.RawMessage
	if raw, ok := obj["challenges"]; !ok || json.Unmarshal(raw, &challenges) != nil {
		return body
	}
	kept := make([]json.RawMessage, 0, len(challenges))
	for _, c := range challenges {
		var head struct{ Type string }
		if json.Unmarshal(c, &head) == nil && head.Type == "http-01" {
			kept = append(kept, c)
		}
	}
	if len(kept) == len(challenges) {
		return body
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		return body
	}
	obj["challenges"] = raw
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}
