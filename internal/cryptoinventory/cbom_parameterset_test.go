package cryptoinventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The recovery key is a 260-bit secret verified by a SHA-256 digest. CycloneDX
// parameterSetIdentifier is the digest length for a hash ("256" for SHA256), so
// the SHA-256 component must not claim "260".
func TestCBOM_RecoveryHashParameterSetIsTheDigestLength(t *testing.T) {
	in, _ := fullInputs(t)
	doc := renderCBOM(t, Build(in, DefaultPolicy(), riskNow))
	var found bool
	for _, c := range doc.Components {
		if a := c.CryptoProperties.Algorithm; a != nil && a.Primitive == "hash" {
			found = true
			assert.Equal(t, "256", a.ParameterSet, "%s: SHA-256 digest length", c.Name)
		}
	}
	require.True(t, found, "fixture must contain the recovery hash algorithm component")
}
