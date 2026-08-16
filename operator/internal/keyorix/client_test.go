package keyorix

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_FetchValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/value", r.URL.Path)
		assert.Equal(t, "app/production/db", r.URL.Query().Get("ref"))
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"data":{"secret":{"Name":"db"},"value":"p4ss"}}`))
	}))
	defer srv.Close()

	v, err := New(srv.URL, "tok").FetchValue(context.Background(), "app/production/db")
	require.NoError(t, err)
	assert.Equal(t, []byte("p4ss"), v)
}

// TestClient_FetchValueMissingDataValueErrors pins the fix for finding
// operator-keyorix.json#0: a 200 response whose body omits data.value entirely (a
// malformed/unexpected response shape, a partial response, or an upstream API contract
// change) must return an explicit error, never a silent ("", nil) success that would
// materialize an empty Kubernetes Secret value in place of a real one.
func TestClient_FetchValueMissingDataValueErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No "value" key in data at all -- distinct from an explicit "value":"".
		_, _ = w.Write([]byte(`{"data":{"secret":{"Name":"db"}}}`))
	}))
	defer srv.Close()

	v, err := New(srv.URL, "tok").FetchValue(context.Background(), "app/production/db")
	require.Error(t, err, "a 200 response missing data.value must not silently succeed")
	assert.Nil(t, v)
	assert.Contains(t, err.Error(), "missing data.value")
}

// TestClient_FetchValueExplicitEmptyValueSucceeds pins the other half of the same fix:
// a response that explicitly sets data.value to "" is a deliberate, well-formed answer
// (the wire contract doesn't forbid it, even though today's server-side validation never
// produces one in practice) and must be returned as a real empty value, not treated as
// the same failure as an outright missing field.
func TestClient_FetchValueExplicitEmptyValueSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secret":{"Name":"db"},"value":""}}`))
	}))
	defer srv.Close()

	v, err := New(srv.URL, "tok").FetchValue(context.Background(), "app/production/db")
	require.NoError(t, err)
	assert.Equal(t, []byte(""), v)
}

func TestClient_FetchValueErrors(t *testing.T) {
	cases := map[int]string{
		http.StatusUnauthorized:        "not authorized",
		http.StatusForbidden:           "forbidden",
		http.StatusNotFound:            "not found",
		http.StatusBadRequest:          "invalid reference",
		http.StatusInternalServerError: "HTTP 500",
	}
	for status, want := range cases {
		t.Run(want, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
		})
	}
}

// TestClient_FetchValueErrorGoneClassification pins the 404/403-vs-everything-else
// distinction the operator controller relies on (#428): a 404 or 403 must wrap
// ErrSecretGone so the controller can treat it as "the secret is confirmed gone" and
// wipe the stale target Secret, while every other failure (401, 400, 5xx, network)
// must NOT wrap it — those are ambiguous or transient and must never trigger a
// destructive action against a previously synced Secret.
func TestClient_FetchValueErrorGoneClassification(t *testing.T) {
	cases := []struct {
		status   int
		wantGone bool
	}{
		{http.StatusNotFound, true},
		{http.StatusForbidden, true},
		{http.StatusUnauthorized, false},
		{http.StatusBadRequest, false},
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusServiceUnavailable, false},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
			require.Error(t, err)
			assert.Equal(t, tc.wantGone, errors.Is(err, ErrSecretGone),
				"HTTP %d: errors.Is(err, ErrSecretGone) = %v, want %v", tc.status, errors.Is(err, ErrSecretGone), tc.wantGone)
		})
	}
}

// A genuine network failure (no HTTP response at all — connection refused here) must
// never be classified as ErrSecretGone: it says nothing about whether the secret
// still exists, only that this attempt to reach the server failed transiently.
func TestClient_FetchValueNetworkErrorIsNotGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	unreachable := srv.URL
	srv.Close() // closed before use: connections to this URL are refused

	_, err := New(unreachable, "tok").FetchValue(context.Background(), "a/b/c")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrSecretGone), "a connection-refused error must not be classified as ErrSecretGone")
}

// TestClient_FetchValueUnauthorizedWrapsErrUnauthorized pins the 401 classification the
// operator controller relies on: a 401 must wrap ErrUnauthorized (distinct from
// ErrSecretGone, which stays reserved for a confirmed 404/403) so the controller can
// treat a revoked/rotated bearer token as an access-cut signal worth wiping the target
// Secret for, while still recording a status reason distinct from a confirmed-gone
// secret.
func TestClient_FetchValueUnauthorizedWrapsErrUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "tok").FetchValue(context.Background(), "a/b/c")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnauthorized), "a 401 must wrap ErrUnauthorized")
	assert.False(t, errors.Is(err, ErrSecretGone), "a 401 must NOT wrap ErrSecretGone — it says nothing about the referenced secret's own fate")
}

// TestClient_RefusesRedirect pins the fix for a bearer-token-leak-on-downgrade bug: Go's
// default http.Client only strips the Authorization header when a redirect's Host
// differs from the original — never when only the scheme changes, so a same-host
// https->http redirect would otherwise carry the bearer token (and the plaintext secret
// value in the response) over cleartext. This client has no legitimate reason to follow
// any redirect, so CheckRedirect must refuse every one outright.
func TestClient_RefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If a redirect were followed, the Authorization header would land here.
		assert.Fail(t, "the client must never actually reach the redirect target", "Authorization=%q", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/secrets/value", http.StatusFound)
	}))
	defer redirector.Close()

	_, err := New(redirector.URL, "tok").FetchValue(context.Background(), "a/b/c")
	require.Error(t, err, "a redirect must be refused, not silently followed")
	assert.Contains(t, err.Error(), "redirect")
}
