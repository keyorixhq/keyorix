package k8ssync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRef(t *testing.T) {
	cases := []struct {
		ref, env, name string
		ok             bool
	}{
		{"production/db-password", "production", "db-password", true},
		{"prod/app/config/url", "prod", "app/config/url", true}, // name may contain slashes
		{"noslash", "", "", false},
		{"/leading", "", "", false},
		{"trailing/", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		env, name, err := parseRef(c.ref)
		if !c.ok {
			assert.Error(t, err, "ref %q should be rejected", c.ref)
			continue
		}
		require.NoError(t, err, "ref %q", c.ref)
		assert.Equal(t, c.env, env)
		assert.Equal(t, c.name, name)
	}
}

// keyorixStub serves the two endpoints the fetcher uses: the filtered list and the
// value read.
func keyorixStub(t *testing.T, wantToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/secrets" && r.URL.Query().Get("environment") == "production":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":7,"Name":"db-password"},{"ID":9,"Name":"api-key"}]}}`))
		case r.URL.Path == "/api/v1/secrets/7" && r.URL.Query().Get("include_value") == "true":
			_, _ = w.Write([]byte(`{"data":{"secret":{"ID":7,"Name":"db-password"},"value":"s3cr3t"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestKeyorixFetcher_Fetch(t *testing.T) {
	srv := keyorixStub(t, "tok")
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok")

	val, err := f.Fetch(context.Background(), "production/db-password")
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t"), val)
}

func TestKeyorixFetcher_NotFound(t *testing.T) {
	srv := keyorixStub(t, "tok")
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "tok")

	_, err := f.Fetch(context.Background(), "production/missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestKeyorixFetcher_Unauthorized(t *testing.T) {
	srv := keyorixStub(t, "tok")
	defer srv.Close()
	f := NewKeyorixFetcher(srv.URL, "wrong-token")

	_, err := f.Fetch(context.Background(), "production/db-password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized")
}

func TestKeyorixFetcher_BadRef(t *testing.T) {
	f := NewKeyorixFetcher("http://example.invalid", "tok")
	_, err := f.Fetch(context.Background(), "noslash")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ref")
}
