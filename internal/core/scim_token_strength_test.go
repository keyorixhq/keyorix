package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ValidateSCIMTokenStrength rejects a configured-but-too-short SCIM bearer token,
// accepts one at or above MinSCIMTokenLength, and treats an empty token as "not
// configured" (not a strength failure) — SCIMToken's own empty-token fail-closed
// gate handles that case per-request.
func TestValidateSCIMTokenStrength(t *testing.T) {
	t.Run("empty token is not a strength error", func(t *testing.T) {
		assert.NoError(t, ValidateSCIMTokenStrength(""))
	})

	t.Run("too-short non-empty token is rejected", func(t *testing.T) {
		short := strings.Repeat("a", MinSCIMTokenLength-1)
		err := ValidateSCIMTokenStrength(short)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too short")
	})

	t.Run("token at the minimum length is accepted", func(t *testing.T) {
		exact := strings.Repeat("a", MinSCIMTokenLength)
		assert.NoError(t, ValidateSCIMTokenStrength(exact))
	})

	t.Run("a realistic high-entropy token is accepted", func(t *testing.T) {
		assert.NoError(t, ValidateSCIMTokenStrength("kx_scim_9f8a3b2c1d0e7f6a5b4c3d2e1f0a9b8c"))
	})
}
