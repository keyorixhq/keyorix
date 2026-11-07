package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vaultStub serves a fixed mount-info body and a fixed secret body, counting
// mount-info lookups so a test can assert that a refused reply is not cached.
func vaultStub(t *testing.T, mountInfo, secret string, mountHits *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") {
			if mountHits != nil {
				*mountHits++
			}
			_, _ = w.Write([]byte(mountInfo))
			return
		}
		_, _ = w.Write([]byte(secret))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// vaultTokenLookupStub answers /v1/auth/token/lookup-self with body (200) for the
// expected token.
func vaultTokenLookupStub(t *testing.T, expectedToken, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" || r.Header.Get("X-Vault-Token") != expectedToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVault_MountInfoMustCarryKnownKVVersion(t *testing.T) {
	const v2Secret = `{"data":{"data":{"password":"p"},"metadata":{"version":2}}}`
	bad := map[string]string{
		"empty object":          `{}`,
		"no data":               `{"request_id":"x"}`,
		"data null":             `{"data":null}`,
		"data empty":            `{"data":{}}`,
		"no path":               `{"data":{"options":{"version":"2"}}}`,
		"options empty":         `{"data":{"path":"secret/","options":{}}}`,
		"version unknown":       `{"data":{"path":"secret/","options":{"version":"3"}}}`,
		"version empty":         `{"data":{"path":"secret/","options":{"version":""}}}`,
		"version null":          `{"data":{"path":"secret/","options":{"version":null}}}`,
		"version wrong type":    `{"data":{"path":"secret/","options":{"version":2}}}`,
		"options wrong type":    `{"data":{"path":"secret/","options":"2"}}`,
		"options array":         `{"data":{"path":"secret/","options":[]}}`,
		"data wrong type":       `{"data":"secret/"}`,
		"version uppercase etc": `{"data":{"path":"secret/","options":{"version":" 2"}}}`,
	}
	for name, mountInfo := range bad {
		t.Run(name, func(t *testing.T) {
			hits := 0
			srv := vaultStub(t, mountInfo, v2Secret, &hits)
			c := NewVaultConnector("v", srv.URL, "tok", nil)
			val, err := c.GetSecret(context.Background(), "secret/data/myapp")
			require.Error(t, err, "got value %q", val)
			assert.Empty(t, val)
			// Not cached: a second read asks Vault again.
			_, _ = c.GetSecret(context.Background(), "secret/data/myapp")
			assert.Equal(t, 2, hits, "a refused mount-info reply must not be cached")
		})
	}
}

func TestVault_MountInfoOptionsNullIsKVv1(t *testing.T) {
	// A KV v1 mount enabled without a version option reports "options": null.
	for name, mountInfo := range map[string]string{
		"null":   `{"data":{"path":"secret/","type":"kv","options":null}}`,
		"absent": `{"data":{"path":"secret/","type":"kv"}}`,
		"v1":     `{"data":{"path":"secret/","type":"kv","options":{"version":"1"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := vaultStub(t, mountInfo, `{"data":{"password":"p"}}`, nil)
			c := NewVaultConnector("v", srv.URL, "tok", nil)
			val, err := c.GetSecret(context.Background(), "secret/legacy")
			require.NoError(t, err)
			assert.JSONEq(t, `{"password":"p"}`, val)
		})
	}
}

func TestVault_EmptyKVPayloadIsNotASecret(t *testing.T) {
	cases := map[string]struct{ mount, secret string }{
		"v1 empty map": {vaultMountInfoV1(), `{"data":{}}`},
		"v1 null":      {vaultMountInfoV1(), `{"data":null}`},
		"v2 empty map": {vaultMountInfoV2(), `{"data":{"data":{},"metadata":{"version":1}}}`},
		"v1 string":    {vaultMountInfoV1(), `{"data":"AAAA"}`},
		"v1 array":     {vaultMountInfoV1(), `{"data":[1]}`},
		"v1 number":    {vaultMountInfoV1(), `{"data":5}`},
		"v2 string":    {vaultMountInfoV2(), `{"data":{"data":"AAAA","metadata":{"version":1}}}`},
		"v2 array":     {vaultMountInfoV2(), `{"data":{"data":[],"metadata":{"version":1}}}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := vaultStub(t, tc.mount, tc.secret, nil)
			c := NewVaultConnector("v", srv.URL, "tok", nil)
			val, err := c.GetSecret(context.Background(), "secret/data/myapp")
			require.Error(t, err, "got value %q", val)
			assert.Empty(t, val)
		})
	}
}

func TestVault_CheckTokenTTL_RequiresNumericTTL(t *testing.T) {
	for name, body := range map[string]string{
		"data empty":   `{"data":{}}`,
		"no data":      `{}`,
		"ttl null":     `{"data":{"ttl":null}}`,
		"ttl string":   `{"data":{"ttl":"0"}}`,
		"ttl float":    `{"data":{"ttl":1.5}}`,
		"ttl bool":     `{"data":{"ttl":false}}`,
		"ttl negative": `{"data":{"ttl":-5}}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := vaultTokenLookupStub(t, "tok", body, http.StatusOK)
			c := NewVaultConnector("v", srv.URL, "tok", nil)
			_, _, err := c.CheckTokenTTL(context.Background())
			require.Error(t, err)
		})
	}
}

func TestVault_CheckTokenTTL_ExplicitZeroIsRootToken(t *testing.T) {
	// What a real root token's lookup-self reports.
	srv := vaultTokenLookupStub(t, "root", `{"data":{"ttl":0,"renewable":false,"policies":["root"]}}`, http.StatusOK)
	c := NewVaultConnector("v", srv.URL, "root", nil)
	ttl, renewable, err := c.CheckTokenTTL(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, ttl)
	assert.False(t, renewable)
}
