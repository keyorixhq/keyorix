package keyorix

import (
	"context"
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
		http.StatusForbidden:           "not authorized",
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
