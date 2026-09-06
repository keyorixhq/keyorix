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

// vaultMountInfoV2/vaultMountInfoV1 are canned sys/internal/ui/mounts/<path>
// responses for the two KV versions, used to stub resolveKVMountVersion's
// lookup in fakeVault-backed tests below.
func vaultMountInfoV2() string {
	return `{"data":{"path":"secret/","type":"kv","options":{"version":"2"}}}`
}
func vaultMountInfoV1() string {
	return `{"data":{"path":"secret/","type":"kv","options":{"version":"1"}}}`
}

func TestVault_GetSecret_KVv2(t *testing.T) {
	// KV v2 nests the secret under data.data, with a sibling data.metadata. The
	// version comes from the mount-info lookup, not from sniffing this shape.
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/sys/internal/ui/mounts/secret/data/myapp": vaultMountInfoV2(),
		"/v1/secret/data/myapp":                        `{"data":{"data":{"password":"p@ss","user":"svc"},"metadata":{"version":3}}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", nil)
	val, err := c.GetSecret(context.Background(), "secret/data/myapp")
	require.NoError(t, err)
	assert.JSONEq(t, `{"password":"p@ss","user":"svc"}`, val, "KV v2 inner data map is returned")
}

func TestVault_GetSecret_KVv1(t *testing.T) {
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/sys/internal/ui/mounts/secret/legacy": vaultMountInfoV1(),
		"/v1/secret/legacy":                        `{"data":{"apikey":"abc123"}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", nil)
	val, err := c.GetSecret(context.Background(), "secret/legacy")
	require.NoError(t, err)
	assert.JSONEq(t, `{"apikey":"abc123"}`, val, "KV v1 data map is returned as-is")
}

// TestVault_GetSecret_KVv1_LiteralDataAndMetadataFieldsBothPresent pins the
// fix for concrete bug (1) of the KV-version misdetection finding: a genuine
// KV v1 secret can legitimately have its OWN fields literally named "data" and
// "metadata" (plausible field names an operator might pick). The old
// response-shape-sniffing code misdetected this exact shape as KV v2 —
// confirmed empirically against the old code's exact branch logic before this
// fix (a standalone harness reproducing vault.go's old GetSecret tail
// byte-for-byte returned val="api-key-value", silently discarding the
// "metadata"/"other_field" values) — because json.RawMessage captures the raw
// bytes of ANY present JSON value, including a plain string, so
// `len(kv2.Data) > 0 && len(kv2.Metadata) > 0` was satisfied by ordinary field
// values, not just KV v2's nested-object envelope. With version now resolved
// explicitly from the mount (v1 here), the full outer object — every field —
// is returned as-is regardless of what its field names happen to be.
func TestVault_GetSecret_KVv1_LiteralDataAndMetadataFieldsBothPresent(t *testing.T) {
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/sys/internal/ui/mounts/secret/legacy": vaultMountInfoV1(),
		"/v1/secret/legacy":                        `{"data":{"data":"api-key-value","metadata":"some-metadata-value","other_field":"other-value"}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", nil)
	val, err := c.GetSecret(context.Background(), "secret/legacy")
	require.NoError(t, err)
	assert.JSONEq(t, `{"data":"api-key-value","metadata":"some-metadata-value","other_field":"other-value"}`, val,
		"every field of the genuine v1 secret must survive, not just the literal \"data\" field's value")
}

// TestVault_GetSecret_KVv2_SoftDeletedReturnsNotFoundError pins the fix for
// concrete bug (2): Vault's real soft-deleted KV v2 response shape
// (`{"data": null, "metadata": {...}}`, taken verbatim from Vault's own docs)
// must surface as a clear "not found/deleted" error, never as a successful
// read. Confirmed empirically against the old code's exact branch logic
// before this fix: json.RawMessage captures the literal 4 bytes "null" for a
// JSON null value (len=4, NOT 0), so the old `len(kv2.Data) > 0 &&
// len(kv2.Metadata) > 0` check was satisfied and returned the bare string
// "null" as if it were the plaintext secret — with a nil error, i.e. silent
// success on a deleted secret.
func TestVault_GetSecret_KVv2_SoftDeletedReturnsNotFoundError(t *testing.T) {
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/sys/internal/ui/mounts/secret/data/deleted-secret": vaultMountInfoV2(),
		"/v1/secret/data/deleted-secret":                        `{"data":{"data":null,"metadata":{"created_time":"2018-03-22T02:24:06.945319214Z","deletion_time":"2018-03-23T02:24:06.945319214Z","destroyed":false,"version":1}}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", nil)
	val, err := c.GetSecret(context.Background(), "secret/data/deleted-secret")
	require.Error(t, err, "a soft-deleted KV v2 version must be reported as an error, never as a successful read")
	assert.Empty(t, val)
	assert.Contains(t, err.Error(), "not found")
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

// TestVault_GetSecret_RejectsTraversalAndInjection proves a caller cannot use a ref
// that satisfies the allowed_refs HasPrefix check to climb to another Vault path via
// `..` or to inject a query string — the ref is sanitized before the URL is built.
func TestVault_GetSecret_RejectsTraversalAndInjection(t *testing.T) {
	// The fake server records the raw request target and parsed query of every
	// request, so we can prove the dangerous ref is never transmitted as sent.
	type hit struct {
		rawURI   string
		rawQuery string
	}
	var hits []hit
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, hit{rawURI: r.RequestURI, rawQuery: r.URL.RawQuery})
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	// allowed_refs confines the connector to secret/data/team-a/.
	c := NewVaultConnector("v", srv.URL, "tok", []string{"secret/data/team-a/"})

	t.Run("path traversal is rejected before any request", func(t *testing.T) {
		_, err := c.GetSecret(context.Background(), "secret/data/team-a/../../../sys/policies/acl")
		require.Error(t, err)
		// prefixAllowed (the allowed_refs layer) now rejects the traversal-shaped
		// ref outright, before sanitizeVaultRef's own defense-in-depth check even
		// runs — so the error surfaces as "not permitted" rather than "traversal".
		assert.Contains(t, err.Error(), "not permitted")
		assert.Empty(t, hits, "no request should reach Vault for a traversal ref")
	})

	t.Run("query injection is neutralized, not split into a query string", func(t *testing.T) {
		hits = nil
		// HasPrefix passes; without sanitization url.Parse would split the `?` into a
		// query string sent to Vault. After escaping, the `?` is a literal path char.
		_, _ = c.GetSecret(context.Background(), "secret/data/team-a/x?list=true")
		require.Len(t, hits, 1)
		assert.Empty(t, hits[0].rawQuery, "the injected ?list=true must not become a Vault query parameter")
		assert.Contains(t, hits[0].rawURI, "%3F", "the ? is percent-escaped into the path")
	})
}

// TestVault_GetSecret_CrossTenantTraversalIsRejected proves the exact exploit trace
// from finding #326: a caller scoped by allowed_refs to "secret/data/myapp/" cannot
// read "secret/data/otherapp/secret" by requesting the ref
// "secret/data/myapp/../otherapp/secret". strings.HasPrefix on that ref against the
// granted prefix "secret/data/myapp/" is true (the literal string starts with the
// allowed prefix), so without a traversal guard the request would reach Vault, whose
// HTTP layer resolves the ".." per RFC 3986 to a path outside the granted prefix —
// a cross-tenant read through one shared connector.
func TestVault_GetSecret_CrossTenantTraversalIsRejected(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		// Simulate the victim secret actually existing at the path the traversal
		// resolves to, so a failure to reject would silently succeed.
		if r.URL.Path == "/v1/secret/data/otherapp/secret" {
			_, _ = w.Write([]byte(`{"data":{"data":{"password":"victim-secret"},"metadata":{}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c := NewVaultConnector("v", srv.URL, "tok", []string{"secret/data/myapp/"})

	_, err := c.GetSecret(context.Background(), "secret/data/myapp/../otherapp/secret")
	require.Error(t, err, "the cross-tenant traversal ref must be rejected")
	// Rejected at the allowed_refs layer (prefixAllowed) before sanitizeVaultRef's
	// defense-in-depth check even runs.
	assert.Contains(t, err.Error(), "not permitted")
	assert.Zero(t, hits, "no request should ever reach Vault for a traversal ref")
}

// TestVault_GetSecret_LegitimateScopedRefStillWorks proves the traversal guard does
// not collaterally break an ordinary, non-traversal ref within the granted prefix —
// the same GetSecret code path (prefixAllowed then sanitizeVaultRef) must still let
// a legitimately scoped caller read their own secret.
func TestVault_GetSecret_LegitimateScopedRefStillWorks(t *testing.T) {
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/sys/internal/ui/mounts/secret/data/myapp/config": vaultMountInfoV2(),
		"/v1/secret/data/myapp/config":                        `{"data":{"data":{"password":"p@ss"},"metadata":{}}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", []string{"secret/data/myapp/"})

	val, err := c.GetSecret(context.Background(), "secret/data/myapp/config")
	require.NoError(t, err)
	assert.JSONEq(t, `{"password":"p@ss"}`, val)
}

// TestVault_GetSecret_RefusesCrossHostRedirect proves #98: a compromised/MITM'd Vault
// endpoint that answers a GET with a 3xx to a different host must NOT cause the live
// X-Vault-Token to be forwarded there. Go's default redirect policy strips
// Authorization/Cookie/WWW-Authenticate on a cross-host hop, but NOT the custom
// X-Vault-Token header — so without an explicit CheckRedirect override, the token
// would leak to the attacker-controlled host. The connector refuses to follow the
// redirect at all, so the attacker host must never even receive a request.
func TestVault_GetSecret_RefusesCrossHostRedirect(t *testing.T) {
	var attackerHits int
	var attackerSawToken bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits++
		if r.Header.Get("X-Vault-Token") != "" {
			attackerSawToken = true
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(attacker.Close)

	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A "compromised" Vault endpoint redirecting the client to an
		// attacker-controlled host, on a different origin than vault's own.
		http.Redirect(w, r, attacker.URL+"/steal", http.StatusFound)
	}))
	t.Cleanup(vault.Close)

	c := NewVaultConnector("v", vault.URL, "supersecret-token", nil)
	_, err := c.GetSecret(context.Background(), "secret/data/myapp")

	require.Error(t, err, "a redirect response must not be treated as a successful read")
	assert.Contains(t, err.Error(), "HTTP 302", "the redirect status itself surfaces as the (non-200) response")
	assert.Zero(t, attackerHits, "the connector must never follow the redirect to the attacker-controlled host")
	assert.False(t, attackerSawToken, "the live Vault token must never reach the attacker-controlled host")
}

// TestVault_GetSecret_RefusesSameHostRedirect proves the refusal is unconditional
// (not merely cross-host-aware): even a same-host redirect (e.g. to a path an
// operator didn't intend to be reachable) is refused rather than followed, since
// Vault's real KV-read API has no legitimate reason to redirect a GET at all.
func TestVault_GetSecret_RefusesSameHostRedirect(t *testing.T) {
	var redirectTargetHits int
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/v1/sys/internal/ui/mounts/secret/data/myapp", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(vaultMountInfoV2()))
	})
	mux.HandleFunc("/v1/secret/data/myapp", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/v1/secret/data/other", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/v1/secret/data/other", func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHits++
		_, _ = w.Write([]byte(`{"data":{"data":{"x":"y"},"metadata":{}}}`))
	})

	c := NewVaultConnector("v", srv.URL, "tok", nil)
	_, err := c.GetSecret(context.Background(), "secret/data/myapp")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 301")
	assert.Zero(t, redirectTargetHits, "even a same-host redirect target must never be requested")
}
