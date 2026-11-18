package acme

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
)

// maxACMEJSON bounds the ACME replies read into memory; authorizations are a few kilobytes.
const maxACMEJSON = 1 << 20

// httpOnly removes every challenge but HTTP-01 from the CA's authorization replies. autocert
// tries TLS-ALPN-01 first, which fails behind the front Apache and costs one of Let's Encrypt's
// failed validations per attempt.
type httpOnly struct{ base http.RoundTripper }

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
	body = keepHTTP01(body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return resp, nil
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
