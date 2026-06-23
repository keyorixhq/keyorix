package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyorixClient_GetSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/value", r.URL.Path)
		assert.Equal(t, "app/prod/db", r.URL.Query().Get("ref"))
		assert.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"data":{"secret":{"Name":"db"},"value":"p4ss"}}`))
	}))
	defer srv.Close()

	v, err := NewKeyorixClient(srv.URL, "tok").GetSecret(context.Background(), "app/prod/db")
	require.NoError(t, err)
	assert.Equal(t, "p4ss", v)
}

func TestKeyorixClient_GetSecretErrors(t *testing.T) {
	cases := map[int]string{
		http.StatusUnauthorized: "not authorized",
		http.StatusForbidden:    "not authorized",
		http.StatusNotFound:     "not found",
		http.StatusBadRequest:   "invalid request",
		http.StatusBadGateway:   "HTTP 502",
	}
	for status, want := range cases {
		t.Run(want, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			_, err := NewKeyorixClient(srv.URL, "tok").GetSecret(context.Background(), "a/b/c")
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
		})
	}
}

func TestKeyorixClient_ListSecretsBuildsRefsAndFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets", r.URL.Path)
		assert.Equal(t, "100", r.URL.Query().Get("page_size"))
		_, _ = w.Write([]byte(`{"data":{"secrets":[
			{"Name":"db","Type":"password","project_name":"app","environment_name":"production"},
			{"Name":"api","Type":"api_key","project_name":"app","environment_name":"staging"},
			{"Name":"orphan","project_name":"app"}
		]}}`))
	}))
	defer srv.Close()

	// No filter: the two complete entries map to refs; the entry missing an environment
	// is dropped (can't form an unambiguous ref).
	all, err := NewKeyorixClient(srv.URL, "tok").ListSecrets(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, "app/production/db", all[0].Ref)
	assert.Equal(t, "password", all[0].Type)
	assert.Equal(t, "app/staging/api", all[1].Ref)

	// Environment filter (case-insensitive) narrows to one.
	prod, err := NewKeyorixClient(srv.URL, "tok").ListSecrets(context.Background(), "Production")
	require.NoError(t, err)
	require.Len(t, prod, 1)
	assert.Equal(t, "app/production/db", prod[0].Ref)
}
