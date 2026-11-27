package httpsafe

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestErrorBodyScrubTransport_ReplacesNonOKBodies: every status other than 200 OK (a 2xx
// other than 200 included, since azsecrets treats it as an error and azcore prints its body)
// reaches the SDK with a fixed body. Only a plain error.code survives; status and headers are
// kept. A 200 body passes through untouched.
func TestErrorBodyScrubTransport_ReplacesNonOKBodies(t *testing.T) {
	const secret = "kx-httpsafe-secret-canary"
	cases := []struct {
		status   int
		body     string
		wantBody string
	}{
		{200, `{"value":"` + secret + `"}`, `{"value":"` + secret + `"}`},
		{403, `{"error":{"code":"Forbidden","message":"` + secret + `"}}`,
			`{"error":{"code":"Forbidden","message":"upstream error response body suppressed"}}`},
		{203, `{"value":"` + secret + `"}`,
			`{"error":{"code":"UpstreamError","message":"upstream error response body suppressed"}}`},
		{500, `{"error":{"code":"` + secret + `\"}","message":"x"}}`,
			`{"error":{"code":"UpstreamError","message":"upstream error response body suppressed"}}`},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		}))
		resp, err := NewAzureClient(http.DefaultTransport).Get(srv.URL)
		if err != nil {
			srv.Close()
			t.Fatalf("status %d: GET: %v", tc.status, err)
		}
		got, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		srv.Close()
		if err != nil {
			t.Fatalf("status %d: ReadAll: %v", tc.status, err)
		}
		if string(got) != tc.wantBody {
			t.Errorf("status %d: body = %q, want %q", tc.status, got, tc.wantBody)
		}
		if tc.status != 200 && strings.Contains(string(got), secret) {
			t.Errorf("status %d: scrubbed body still carries the secret", tc.status)
		}
		if resp.StatusCode != tc.status || resp.Header.Get("Retry-After") != "7" {
			t.Errorf("status %d: got status %d, Retry-After %q; want both kept", tc.status, resp.StatusCode, resp.Header.Get("Retry-After"))
		}
	}
}
