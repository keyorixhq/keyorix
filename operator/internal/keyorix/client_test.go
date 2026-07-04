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
