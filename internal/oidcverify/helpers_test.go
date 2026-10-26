package oidcverify

// Copies of internal/core/oidc_test.go's helpers, which tests staying in
// core still use (CORE-PURE-AUTH-LEAVES-1).

import (
	"context"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// staticResolver returns one fixed RSA public key for a known kid.
type staticResolver struct {
	kid string
	key any
}

func (s staticResolver) Key(_ context.Context, _, kid string) (any, error) {
	if kid == s.kid {
		return s.key, nil
	}
	return nil, errTestNoKey
}

var errTestNoKey = &noKeyErr{}

type noKeyErr struct{}

func (*noKeyErr) Error() string { return "no key" }

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}
