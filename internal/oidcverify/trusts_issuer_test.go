package oidcverify

// Moved verbatim from internal/core/core_s25_test.go (CORE-PURE-AUTH-LEAVES-1):
// it reads the verifier's unexported issuer map.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrustsIssuer_TrueAndFalse(t *testing.T) {
	t.Parallel()
	v := &OIDCVerifier{issuers: map[string]oidcIssuerTrust{
		"https://accounts.google.com": {},
	}}
	assert.True(t, v.TrustsIssuer("https://accounts.google.com"))
	assert.False(t, v.TrustsIssuer("https://evil.com"))
}
