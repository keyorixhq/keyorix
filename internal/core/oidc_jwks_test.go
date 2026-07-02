package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPJWKSResolver_FetchAndCache(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &key.PublicKey

	// Serve a JWKS with the public key under kid "k1".
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	}))
	defer srv.Close()

	// srv.URL is http://127.0.0.1:… (loopback) — allowed for tests.
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	got, err := r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
	rsaKey, ok := got.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, 0, pub.N.Cmp(rsaKey.N), "modulus round-trips")
	assert.Equal(t, pub.E, rsaKey.E)

	// Second lookup of the same kid is served from cache (no new fetch).
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
	assert.Equal(t, 1, hits, "fresh cache is not refetched")

	// Unknown issuer fails.
	_, err = r.Key(context.Background(), "https://other", "k1")
	require.ErrorContains(t, err, "no jwks_uri")
}

// On a transient JWKS fetch failure, a cached key is served only within a bounded
// grace window past the TTL — so a key the issuer rotated out (e.g. compromised)
// cannot be honoured indefinitely while the issuer is unreachable.
func TestHTTPJWKSResolver_StaleFallbackBounded(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// A JWKS endpoint that always fails, forcing reliance on the cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	seedCache := func(age time.Duration) {
		r.mu.Lock()
		r.cache["https://iss"] = &jwksEntry{
			keys:      map[string]interface{}{"k1": &key.PublicKey},
			fetchedAt: time.Now().Add(-age),
		}
		r.mu.Unlock()
	}

	// Stale but within the grace window: the cached key is served despite the fetch failure.
	seedCache(jwksCacheTTL + jwksStaleGrace - time.Minute)
	got, err := r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
	assert.Equal(t, &key.PublicKey, got)

	// Beyond the grace window: a failed refetch fails closed (rotated-out key not honoured).
	seedCache(jwksCacheTTL + jwksStaleGrace + time.Minute)
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.Error(t, err)
}

// An unknown kid on a fresh cache triggers at most one refetch per
// jwksMinRefetchInterval per issuer, so a flood of tokens bearing a trusted issuer
// and random kids can't amplify into a JWKS-fetch storm against the IdP.
func TestHTTPJWKSResolver_UnknownKidRefetchRateLimited(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &key.PublicKey
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	// Prime the cache (1 fetch).
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
	require.Equal(t, 1, hits)

	// A flood of distinct unknown kids on the now-fresh cache: the first one is
	// allowed to refetch (rotation), the rest within the interval are rejected
	// without any outbound fetch.
	for i := 0; i < 50; i++ {
		_, _ = r.Key(context.Background(), "https://iss", "bogus-kid")
	}
	assert.LessOrEqual(t, hits, 2, "bogus-kid flood must not amplify into a fetch storm")

	// The legitimate kid is still served from cache throughout.
	_, err = r.Key(context.Background(), "https://iss", "k1")
	require.NoError(t, err)
}

// A JWKS with more keys than maxJWKSKeys is capped so a pathological key set can't
// bloat the cache.
func TestHTTPJWKSResolver_CapsKeyCount(t *testing.T) {
	// Generate all RSA-2048 keys UP FRONT, not inside the HTTP handler: generating
	// 70 of them (maxJWKSKeys+20) takes long enough under load (heavy parallel test
	// suite contention) that doing it per-request could exceed the resolver's 10s
	// HTTP client timeout, making r.Key() below return an error the test didn't
	// check — a nil-pointer panic on the next line (the cache entry was never
	// populated), observed as an intermittent flake. Precomputing removes the
	// timing dependency: the handler now does pure, fast JSON encoding.
	keys := make([]map[string]string, 0, maxJWKSKeys+20)
	for i := 0; i < maxJWKSKeys+20; i++ {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pub := &k.PublicKey
		keys = append(keys, map[string]string{
			"kty": "RSA", "kid": "k" + strconv.Itoa(i), "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
	}))
	defer srv.Close()
	r, err := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})
	require.NoError(t, err)

	_, err = r.Key(context.Background(), "https://iss", "k0")
	require.NoError(t, err)
	r.mu.Lock()
	n := len(r.cache["https://iss"].keys)
	r.mu.Unlock()
	assert.LessOrEqual(t, n, maxJWKSKeys, "retained key count is capped")
}

func TestNewHTTPJWKSResolver_RejectsInsecureScheme(t *testing.T) {
	// Plaintext http to a non-loopback host is refused (signing-key MITM).
	_, err := NewHTTPJWKSResolver(map[string]string{"https://iss": "http://idp.example.com/jwks"})
	require.ErrorContains(t, err, "must use https")

	// https is accepted.
	_, err = NewHTTPJWKSResolver(map[string]string{"https://iss": "https://idp.example.com/jwks"})
	require.NoError(t, err)

	// http to loopback is allowed (dev/test).
	for _, uri := range []string{"http://localhost:8200/jwks", "http://127.0.0.1:8200/jwks", "http://[::1]:8200/jwks"} {
		_, err = NewHTTPJWKSResolver(map[string]string{"https://iss": uri})
		require.NoErrorf(t, err, "loopback %s should be allowed", uri)
	}
}
