package acme

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKeepHTTP01(t *testing.T) {
	authz := `{"status":"pending","identifier":{"type":"dns","value":"panel.example.com"},"challenges":[` +
		`{"type":"tls-alpn-01","url":"https://ca/c/1","token":"a"},{"type":"http-01","url":"https://ca/c/2","token":"b"},` +
		`{"type":"dns-01","url":"https://ca/c/3","token":"c"}]}`
	var got struct {
		Status     string
		Identifier struct{ Value string }
		Challenges []struct{ Type, URL, Token string }
	}
	if err := json.Unmarshal(keepHTTP01([]byte(authz)), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || got.Identifier.Value != "panel.example.com" {
		t.Errorf("other fields changed: %+v", got)
	}
	if len(got.Challenges) != 1 || got.Challenges[0].Type != "http-01" || got.Challenges[0].Token != "b" {
		t.Errorf("challenges = %+v, want the http-01 one alone", got.Challenges)
	}

	for _, body := range []string{
		`{"status":"valid","challenges":[{"type":"http-01","token":"b"}]}`,
		`{"type":"http-01","status":"processing"}`,
		`{"challenges":"not a list"}`,
		`not json`,
	} {
		if out := string(keepHTTP01([]byte(body))); out != body {
			t.Errorf("keepHTTP01(%s) = %s, want it unchanged", body, out)
		}
	}
}

func TestHTTPOnlyTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cert" {
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		_, _ = io.WriteString(w, `{"challenges":[{"type":"tls-alpn-01"},{"type":"http-01"}]}`)
	}))
	defer srv.Close()
	client := &http.Client{Transport: httpOnly{base: http.DefaultTransport}}
	for path, want := range map[string]string{
		"/authz": `{"challenges":[{"type":"http-01"}]}`,
		"/cert":  `{"challenges":[{"type":"tls-alpn-01"},{"type":"http-01"}]}`,
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != want || resp.ContentLength != int64(len(want)) {
			t.Errorf("%s: body %s (length %d), want %s", path, body, resp.ContentLength, want)
		}
	}
}

func TestHTTP01Failure(t *testing.T) {
	for body, want := range map[string]string{
		`{"type":"http-01","status":"invalid","error":{"type":"urn:x:unauthorized","detail":"503"}}`:                    "urn:x:unauthorized: 503",
		`{"status":"invalid","challenges":[{"type":"http-01","error":{"type":"urn:x:connection","detail":"timeout"}}]}`: "urn:x:connection: timeout",
		`{"status":"invalid","challenges":[{"type":"tls-alpn-01","error":{"type":"urn:x:tls","detail":"no ALPN"}}]}`:    "",
		`{"status":"pending","challenges":[{"type":"http-01","status":"pending"}]}`:                                     "",
		`not json`: "",
	} {
		if got := http01Failure([]byte(body)); got != want {
			t.Errorf("http01Failure(%s) = %q, want %q", body, got, want)
		}
	}
}
