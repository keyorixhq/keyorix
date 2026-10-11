package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExplicitlySetPathsIn_FlattensSequencesLikeSourcePaths(t *testing.T) {
	got, err := explicitlySetPathsIn([]byte(`
security:
  require_transport_tls: false
sso:
  providers:
    - name: a
    - name: b
      trust_asserted_email: true
`))
	require.NoError(t, err)
	for _, p := range []string{"security", "security.require_transport_tls", "sso.providers", "sso.providers.trust_asserted_email"} {
		assert.True(t, got[p], "%s is written by the file", p)
	}
	assert.False(t, got["security.require_mfa"], "an absent key is not explicit")
	assert.False(t, got["sso.providers.0.trust_asserted_email"], "sequence indices are flattened away")
}

func TestExplicitlySetPathsIn_EmptyFileWritesNothing(t *testing.T) {
	got, err := explicitlySetPathsIn([]byte("# comments only\n"))
	require.NoError(t, err)
	assert.Empty(t, got)
}
