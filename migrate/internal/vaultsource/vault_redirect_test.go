// Fast unit tests for vaultsource's fail-closed handling of a non-success READ/LIST status.
// These complement TestClient_RefusesRedirect (which proves a redirect is not *followed*): here
// the client does not follow the 3xx, but it must also not parse the un-followed redirect's body
// as the secret. See INV-VAULTSOURCE-non-2xx-read-is-an-error.
package vaultsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mountAndListRoutes serves a one-leaf KV v2 tree ("secret" mount, LIST root -> ["db"]) and
// hands the READ of secret/data/db to readHandler, so each test controls only the READ response.
func mountAndListServer(t *testing.T, readHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"path":"secret/","options":{"version":"2"}}}`))
		case strings.HasPrefix(r.URL.Path, "/v1/secret/metadata"):
			w.Header().Set("Content-Type", "application/json")
			sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata"), "/")
			if sub == "" {
				_, _ = w.Write([]byte(`{"data":{"keys":["db"]}}`))
			} else {
				_, _ = w.Write([]byte(`{"data":{"keys":[]}}`))
			}
		case strings.HasPrefix(r.URL.Path, "/v1/secret/data"):
			readHandler(w, r)
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestWalk_RedirectReadBodyIsNotImported is the F3 regression: a READ answered with a 3xx
// (redirect) must be an error, not an import. The client does not follow the redirect, but it
// must also not treat the un-followed redirect's body as authoritative secret data.
func TestWalk_RedirectReadBodyIsNotImported(t *testing.T) {
	srv := mountAndListServer(t, func(w http.ResponseWriter, _ *http.Request) {
		// A 302 whose body is shaped like a real KV v2 read response. Pre-fix, vaultsource
		// read this body and imported db=attacker-value; post-fix it must be an error.
		w.Header().Set("Location", "http://169.254.169.254/latest/")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"attacker-redirect-body"},"metadata":{"version":1}}}`))
	})

	c, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", Token: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, _, err := c.Walk(context.Background(), "", false)
	if err == nil {
		t.Fatalf("Walk imported %d entr(ies) from a 302 redirect read; want an error (a 3xx body must never be parsed as the secret)", len(entries))
	}
	for _, e := range entries {
		if strings.Contains(e.Value, "attacker-redirect-body") {
			t.Fatalf("Walk imported the redirect body as a secret value: %q", e.Value)
		}
	}
}

// TestWalk_Non200ReadIsAnError checks the general rule the redirect case is one instance of:
// any READ status other than 200 (and the deliberately-handled 404) is an error, not a parsed
// body. 206 Partial Content is the probe here — a non-404 2xx that is still not a complete,
// authoritative read.
func TestWalk_Non200ReadIsAnError(t *testing.T) {
	srv := mountAndListServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPartialContent) // 206
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"partial"},"metadata":{"version":1}}}`))
	})

	c, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", Token: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := c.Walk(context.Background(), "", false); err == nil {
		t.Fatal("Walk treated a 206 read as success; want an error (only 200 and 404 are accepted)")
	}
}

// TestAppRoleLogin_Non200IsAnError covers the third response handler in the client: an AppRole
// login answered with anything other than 200 must fail New(), and its body must never be decoded.
// Pre-fix only status >= 400 was an error, so an un-followed 302 (or a 206/204) whose body carried
// a client_token had that token adopted as the session token for the whole import.
func TestAppRoleLogin_Non200IsAnError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"302 with a token body", http.StatusFound, `{"auth":{"client_token":"from-a-redirect-body"}}`},
		{"206 with a token body", http.StatusPartialContent, `{"auth":{"client_token":"from-a-partial-body"}}`},
		{"204 no content", http.StatusNoContent, ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/auth/approle/login" {
					http.Error(w, "unexpected path "+r.URL.Path, http.StatusTeapot)
					return
				}
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "http://169.254.169.254/latest/")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)

			c, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", RoleID: "r", SecretID: "s"})
			if err == nil {
				t.Fatalf("New succeeded on an AppRole login answered with HTTP %d (token %q); want an error", tc.status, c.token)
			}
			if strings.Contains(err.Error(), "decode") {
				t.Fatalf("New error %q shows the HTTP %d body was decoded; it must be rejected on status alone", err, tc.status)
			}
		})
	}
}
