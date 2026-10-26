package oidcverify

import "github.com/keyorixhq/keyorix/internal/core/rules"

// Seam for internal/core (CORE-PURE-AUTH-LEAVES-1). Core's tests read these
// two bounds through unexported aliases (internal/core/oidc_aliases.go).

// OIDCClockSkew is the exp/nbf/iat leeway Verify allows.
const OIDCClockSkew = oidcClockSkew

// DefaultOIDCMaxTokenAge is the (now - iat) bound for an issuer without its own.
const DefaultOIDCMaxTokenAge = defaultOIDCMaxTokenAge

// --- JWK parsing (internal/core/rules/jwk.go), same lines as core/rules_compat.go ---

type jwk = rules.JWK

const (
	maxRSABits           = rules.MaxRSABits
	minRSABits           = rules.MinRSABits
	maxRSAPublicExponent = rules.MaxRSAPublicExponent
)

func parseJWK(k jwk) (any, error) { return rules.ParseJWK(k) }
