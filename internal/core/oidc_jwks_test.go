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
	"testing"

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

	r := NewHTTPJWKSResolver(map[string]string{"https://iss": srv.URL})

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
