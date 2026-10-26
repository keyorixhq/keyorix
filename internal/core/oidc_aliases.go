package core

import "github.com/keyorixhq/keyorix/internal/oidcverify"

// The federated-JWT verifier (oidc.go's former OIDCVerifier, OIDCTrustedIssuer,
// JWKSResolver and oidc_jwks.go) lives in internal/oidcverify, a pure leaf: no
// *KeyorixCore, no import of this package. These aliases keep every core.X name
// valid, so no caller changes.
type OIDCVerifier = oidcverify.OIDCVerifier

type OIDCTrustedIssuer = oidcverify.OIDCTrustedIssuer

type JWKSResolver = oidcverify.JWKSResolver

type HTTPJWKSResolver = oidcverify.HTTPJWKSResolver

// The constructors are thin wrappers, not var aliases (same as
// rules_compat.go): an exported var could be reassigned at run time.

// NewOIDCVerifier is oidcverify.NewOIDCVerifier.
func NewOIDCVerifier(issuers []OIDCTrustedIssuer, jwks JWKSResolver) (*OIDCVerifier, error) {
	return oidcverify.NewOIDCVerifier(issuers, jwks)
}

// NewHTTPJWKSResolver is oidcverify.NewHTTPJWKSResolver.
func NewHTTPJWKSResolver(jwksURIs map[string]string) (*HTTPJWKSResolver, error) {
	return oidcverify.NewHTTPJWKSResolver(jwksURIs)
}

// Read by core's JWT tests.
const (
	oidcClockSkew          = oidcverify.OIDCClockSkew
	defaultOIDCMaxTokenAge = oidcverify.DefaultOIDCMaxTokenAge
)
