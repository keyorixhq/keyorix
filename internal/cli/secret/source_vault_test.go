package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVault serves a small KV v2 tree:
//
//	secret/data/prod/db        → {username, password}
//	secret/data/prod/api-key   → {value}
//	secret/metadata/prod       → LIST [db, api-key]
//	secret/metadata (root)     → LIST [prod/]
func fakeVaultKVv2() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/metadata", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"keys":["prod/"]}}`))
	})
	mux.HandleFunc("/v1/secret/metadata/prod", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"keys":["db","api-key"]}}`))
	})
	mux.HandleFunc("/v1/secret/data/prod/db", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"data":{"username":"app_user","password":"pg-xK9"}}}`))
	})
	mux.HandleFunc("/v1/secret/data/prod/api-key", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"sk_live_abc"}}}`))
	})
	return httptest.NewServer(mux)
}

func TestFetchFromVault_KVv2(t *testing.T) {
	srv := fakeVaultKVv2()
	defer srv.Close()

	// Drive the package-level flag vars the fetcher reads.
	vaultAddr, vaultToken, vaultMount, vaultPath, vaultKVVersion = srv.URL, "root", "secret", "", 2
	importNoExplode = false

	entries, err := fetchFromVault(context.Background())
	require.NoError(t, err)

	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Value
	}
	assert.Equal(t, "app_user", got["prod-db-username"])
	assert.Equal(t, "pg-xK9", got["prod-db-password"])
	// Single "value" field → secret named after the path, no "-value" suffix.
	assert.Equal(t, "sk_live_abc", got["prod-api-key"])
	assert.Len(t, entries, 3)
}

func TestFetchFromVault_PathScoped(t *testing.T) {
	srv := fakeVaultKVv2()
	defer srv.Close()

	vaultAddr, vaultToken, vaultMount, vaultPath, vaultKVVersion = srv.URL, "root", "secret", "prod", 2
	importNoExplode = false

	entries, err := fetchFromVault(context.Background())
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	assert.Equal(t, []string{"prod-api-key", "prod-db-password", "prod-db-username"}, names)
}

// A KV key name containing URL-significant characters (space, '#') must be
// path-escaped so the read reaches the right path instead of being mangled into
// a malformed URL or a fragment — otherwise the secret is silently dropped.
func TestFetchFromVault_SpecialCharKey(t *testing.T) {
	// Match on the DECODED r.URL.Path: the client must escape the space and '#'
	// (→ %20, %23) for the server to decode them back to this exact path. Without
	// path-escaping in join, '#' would be sent as a fragment (dropped) and the
	// read would 404, silently losing the secret.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/secret/metadata" && r.URL.Query().Get("list") == "true":
			_, _ = w.Write([]byte(`{"data":{"keys":["api key#1"]}}`))
		case r.URL.Path == "/v1/secret/data/api key#1":
			_, _ = w.Write([]byte(`{"data":{"data":{"value":"sk_special"}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	vaultAddr, vaultToken, vaultMount, vaultPath, vaultKVVersion = srv.URL, "root", "secret", "", 2
	importNoExplode = false

	entries, err := fetchFromVault(context.Background())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "sk_special", entries[0].Value)
}

func TestFetchFromVault_MissingCreds(t *testing.T) {
	vaultAddr, vaultToken = "", ""
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
	_, err := fetchFromVault(context.Background())
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "address") || strings.Contains(err.Error(), "token"))
}
