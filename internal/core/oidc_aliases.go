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

var NewOIDCVerifier = oidcverify.NewOIDCVerifier

var NewHTTPJWKSResolver = oidcverify.NewHTTPJWKSResolver

// Read by core's JWT tests.
const (
	oidcClockSkew          = oidcverify.OIDCClockSkew
	defaultOIDCMaxTokenAge = oidcverify.DefaultOIDCMaxTokenAge
)
