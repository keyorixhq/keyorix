package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVault stands up an in-process Vault HTTP endpoint that requires the token and
// serves canned responses keyed by request path.
func fakeVault(t *testing.T, token string, responses map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, ok := responses[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVault_TypeAndName(t *testing.T) {
	c := NewVaultConnector("prod-vault", "https://v:8200", "t", nil)
	assert.Equal(t, "prod-vault", c.Name())
	assert.Equal(t, "vault", c.Type())
}

func TestVault_GetSecret_KVv2(t *testing.T) {
	// KV v2 nests the secret under data.data, with a sibling data.metadata.
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/secret/data/myapp": `{"data":{"data":{"password":"p@ss","user":"svc"},"metadata":{"version":3}}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", nil)
	val, err := c.GetSecret(context.Background(), "secret/data/myapp")
	require.NoError(t, err)
	assert.JSONEq(t, `{"password":"p@ss","user":"svc"}`, val, "KV v2 inner data map is returned")
}

func TestVault_GetSecret_KVv1(t *testing.T) {
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/secret/legacy": `{"data":{"apikey":"abc123"}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", nil)
	val, err := c.GetSecret(context.Background(), "secret/legacy")
	require.NoError(t, err)
	assert.JSONEq(t, `{"apikey":"abc123"}`, val, "KV v1 data map is returned as-is")
}

func TestVault_GetSecret_Errors(t *testing.T) {
	srv := fakeVault(t, "tok", map[string]string{"/v1/ok": `{"data":{"x":"y"}}`})

	t.Run("empty ref", func(t *testing.T) {
		_, err := NewVaultConnector("v", srv.URL, "tok", nil).GetSecret(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("missing token", func(t *testing.T) {
		_, err := NewVaultConnector("v", srv.URL, "", nil).GetSecret(context.Background(), "ok")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no token")
	})
	t.Run("wrong token → 403", func(t *testing.T) {
		_, err := NewVaultConnector("v", srv.URL, "bad", nil).GetSecret(context.Background(), "ok")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 403")
	})
	t.Run("not found → 404", func(t *testing.T) {
		_, err := NewVaultConnector("v", srv.URL, "tok", nil).GetSecret(context.Background(), "nope")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 404")
	})
	t.Run("allowed_refs guardrail", func(t *testing.T) {
		c := NewVaultConnector("v", srv.URL, "tok", []string{"secret/keyorix/"})
		_, err := c.GetSecret(context.Background(), "secret/other")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
	})
}
