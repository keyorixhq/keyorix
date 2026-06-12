// oidc_jwks.go — JWKS fetcher/cache for OIDC federation (ADR-031).
//
// Fetches an issuer's JSON Web Key Set from its jwks_uri, parses the RSA/EC
// signing keys, and caches them by (issuer, kid). On an unknown kid (key
// rotation) or an expired cache entry it refetches once. The actual signature
// check is done by golang-jwt with the key this returns.
package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// jwksCacheTTL bounds how long a fetched key set is trusted before a refetch.
const jwksCacheTTL = 1 * time.Hour

// jwksStaleGrace bounds how far PAST the TTL a cached key set may still be served
// as a fallback when a JWKS refetch fails transiently. Without a bound, a key the
// issuer rotated out — e.g. because its private key was compromised — would keep
// verifying federation tokens for as long as the issuer's JWKS endpoint is
// unreachable from Keyorix, defeating rotation-as-revocation. After the grace
// window, a failed refetch fails closed.
const jwksStaleGrace = 10 * time.Minute

// HTTPJWKSResolver implements JWKSResolver by fetching each issuer's jwks_uri.
type HTTPJWKSResolver struct {
	jwksURIs map[string]string // issuer -> jwks_uri (operator-configured)
	client   *http.Client

	mu    sync.Mutex
	cache map[string]*jwksEntry // issuer -> cached keys
}

type jwksEntry struct {
	keys      map[string]interface{} // kid -> public key
	fetchedAt time.Time
}

// NewHTTPJWKSResolver builds a resolver over the issuer->jwks_uri map. Each
// jwks_uri must use https so the issuer's signing keys are never fetched over
// plaintext — a MITM on an http jwks_uri could swap the keys and forge federation
// tokens. http is permitted only for loopback hosts (local development/testing).
func NewHTTPJWKSResolver(jwksURIs map[string]string) (*HTTPJWKSResolver, error) {
	for issuer, uri := range jwksURIs {
		if err := validateJWKSScheme(uri); err != nil {
			return nil, fmt.Errorf("issuer %q: %w", issuer, err)
		}
	}
	return &HTTPJWKSResolver{
		jwksURIs: jwksURIs,
		client:   &http.Client{Timeout: 10 * time.Second},
		cache:    map[string]*jwksEntry{},
	}, nil
}

// validateJWKSScheme requires https for a jwks_uri (http only for loopback).
func validateJWKSScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid jwks_uri %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("jwks_uri %q must use https (http is allowed only for localhost)", raw)
	default:
		return fmt.Errorf("jwks_uri %q must use https", raw)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// Key returns the public key for (issuer, kid), fetching/refreshing the issuer's
// JWKS as needed. An unknown kid forces one refetch (handles key rotation).
func (r *HTTPJWKSResolver) Key(ctx context.Context, issuer, kid string) (interface{}, error) {
	jwksURI, ok := r.jwksURIs[issuer]
	if !ok {
		return nil, fmt.Errorf("no jwks_uri configured for issuer %q", issuer)
	}

	r.mu.Lock()
	entry := r.cache[issuer]
	fresh := entry != nil && time.Since(entry.fetchedAt) < jwksCacheTTL
	r.mu.Unlock()

	if fresh {
		if k, ok := entry.keys[kid]; ok {
			return k, nil
		}
		// Unknown kid on a fresh cache: the key may have just rotated — refetch once.
	}

	keys, err := r.fetch(ctx, jwksURI)
	if err != nil {
		// Fall back to a recently-cached key set on a transient fetch error — but
		// ONLY within a bounded grace window past the TTL, so a rotated-out (possibly
		// compromised) key cannot be honoured indefinitely while the issuer is
		// unreachable. Beyond the window, fail closed.
		if entry != nil && time.Since(entry.fetchedAt) < jwksCacheTTL+jwksStaleGrace {
			if k, ok := entry.keys[kid]; ok {
				return k, nil
			}
		}
		return nil, err
	}

	r.mu.Lock()
	r.cache[issuer] = &jwksEntry{keys: keys, fetchedAt: time.Now()}
	r.mu.Unlock()

	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no signing key with kid %q at issuer %q", kid, issuer)
}

// jwk is one JSON Web Key (the subset of fields we verify with).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (r *HTTPJWKSResolver) fetch(ctx context.Context, jwksURI string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwks decode: %w", err)
	}

	out := make(map[string]interface{}, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue // not a signing key
		}
		key, err := parseJWK(k)
		if err != nil {
			continue // skip keys we can't parse rather than failing the whole set
		}
		if k.Kid != "" {
			out[k.Kid] = key
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("jwks contained no usable signing keys")
	}
	return out, nil
}

// parseJWK converts a JWK into an *rsa.PublicKey or *ecdsa.PublicKey.
func parseJWK(k jwk) (interface{}, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uBigInt(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("rsa e: %w", err)
		}
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Int64() <= 0 {
			return nil, fmt.Errorf("rsa e out of range")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		x, err := b64uBigInt(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uBigInt(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

func b64uBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64url: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}
