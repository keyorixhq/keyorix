package notifychan

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func redirectPolicyURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// TestrefuseRedirectDowngrade_HopCap: a redirect chain that keeps pointing back at the same
// URL (a 307 keeps method and body) must be cut off after a few requests, not
// followed until the client timeout.
func TestRedirectPolicy_HopCap(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	c := &http.Client{Timeout: 3 * time.Second, CheckRedirect: refuseRedirectDowngrade}
	resp, err := c.Post(srv.URL+"/loop", "application/json", strings.NewReader("{}"))
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected the redirect loop to be refused")
	}
	if n := hits.Load(); n > 3 {
		t.Fatalf("redirect loop was followed for %d requests, want <= 3", n)
	}
}

// TestrefuseRedirectDowngrade_Policy covers the per-hop decisions directly.
func TestRedirectPolicy_Policy(t *testing.T) {
	prev := func(raw string) []*http.Request {
		return []*http.Request{{URL: redirectPolicyURL(t, raw)}}
	}
	cases := []struct {
		name    string
		via     []*http.Request
		to      string
		wantErr bool
	}{
		{"same origin first hop", prev("https://idp.example.com/a"), "https://idp.example.com/b", false},
		{"different port is a different origin", prev("https://idp.example.com/a"), "https://idp.example.com:8443/b", true},
		{"different port, http", prev("http://127.0.0.1:1111/a"), "http://127.0.0.1:2222/b", true},
		{"different host", prev("https://idp.example.com/a"), "https://other.example.com/b", true},
		{"https to http downgrade", prev("https://idp.example.com/a"), "http://idp.example.com/b", true},
		{"third hop refused", append(prev("https://idp.example.com/a"),
			&http.Request{URL: redirectPolicyURL(t, "https://idp.example.com/b")},
			&http.Request{URL: redirectPolicyURL(t, "https://idp.example.com/c")}), "https://idp.example.com/d", true},
		{"second hop allowed", append(prev("https://idp.example.com/a"),
			&http.Request{URL: redirectPolicyURL(t, "https://idp.example.com/b")}), "https://idp.example.com/c", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{URL: redirectPolicyURL(t, tc.to)}
			err := refuseRedirectDowngrade(req, tc.via)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
